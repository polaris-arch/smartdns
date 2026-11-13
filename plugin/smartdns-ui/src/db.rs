/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use crate::dns_log;
use crate::smartdns;
use crate::smartdns::*;
use crate::utils;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::vec;

use chrono::Local;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, Result};

/// Serves domain-filtered log reads in query-time order: `domain = ?` and the
/// dictionary-driven `domain IN (...)` both read it backwards without sorting.
const QUERY_INDEX_NAME: &str = "idx_domain_domain_timestamp";
const QUERY_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS idx_domain_domain_timestamp ON domain (domain, timestamp)";
/// One row per distinct logged domain, so substring filters scan tens of
/// thousands of names instead of millions of log rows.
const DOMAIN_NAME_TABLE_SQL: &str =
    "CREATE TABLE IF NOT EXISTS domain_name (domain TEXT PRIMARY KEY) WITHOUT ROWID";
const TOP_DOMAIN_SQL: &str = "SELECT domain, COUNT(*) FROM domain WHERE timestamp >= ? GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 20";

pub struct DB {
    conn: Mutex<Option<Connection>>,
    /// Cached at open so read-only connections never wait on the writer lock,
    /// which a first-time index build holds for tens of seconds.
    path: Mutex<Option<String>>,
    /// Set only after the index exists and the name dictionary was backfilled
    /// in this process; until then every read takes the original SQL.
    query_index_ready: AtomicBool,
    version: i32,
    query_plan: bool,
}

#[derive(Debug, Clone)]
pub struct ClientData {
    pub id: u32,
    pub hostname: String,
    pub client_ip: String,
    pub mac: String,
    pub last_query_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ClientQueryCount {
    pub client_ip: String,
    pub count: u32,
    pub timestamp_start: u64,
    pub timestamp_end: u64,
}

#[derive(Debug, Clone)]
pub struct DomainQueryCount {
    pub domain: String,
    pub count: u32,
    pub timestamp_start: u64,
    pub timestamp_end: u64,
}

#[derive(Debug, Clone)]
pub struct HourlyQueryCountItem {
    pub hour: String,
    pub query_count: u32,
}

#[derive(Debug, Clone)]
pub struct HourlyQueryCount {
    pub query_timestamp: u64,
    pub hourly_query_count: Vec<HourlyQueryCountItem>,
}

#[derive(Debug, Clone)]
pub struct DailyQueryCountItem {
    pub day: String,
    pub query_count: u32,
}

#[derive(Debug, Clone)]
pub struct DailyQueryCount {
    pub query_timestamp: u64,
    pub daily_query_count: Vec<DailyQueryCountItem>,
}

#[derive(Debug, Clone)]
pub struct DomainData {
    pub id: u64,
    pub timestamp: u64,
    pub domain: String,
    pub domain_type: u32,
    pub client: String,
    pub domain_group: String,
    pub reply_code: u16,
    pub query_time: i32,
    pub ping_time: f64,
    pub is_blocked: bool,
    pub is_cached: bool,
}

#[derive(Debug, Clone)]
pub struct QueryDomainListResult {
    pub domain_list: Vec<DomainData>,
    pub total_count: u64,
    pub step_by_cursor: bool,
}

struct TimeOrderedQuery {
    sql_where: String,
    sql_order: String,
    sql_param: Vec<String>,
    paged_by_cursor: bool,
}

#[derive(Debug, Clone)]
pub struct DomainListGetParamCursor {
    pub id: Option<u64>,
    pub total_count: u64,
    pub direction: String,
}

#[derive(Debug, Clone)]
pub struct QueryClientListResult {
    pub client_list: Vec<ClientData>,
    pub total_count: u64,
    pub step_by_cursor: bool,
}

#[derive(Debug, Clone)]
pub struct ClientListGetParamCursor {
    pub id: Option<u64>,
    pub total_count: u64,
    pub direction: String,
}

#[derive(Debug, Clone)]
pub struct ClientListGetParam {
    pub id: Option<u64>,
    pub order: Option<String>,
    pub page_num: u64,
    pub page_size: u64,
    pub client_ip: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub timestamp_before: Option<u64>,
    pub timestamp_after: Option<u64>,
    pub cursor: Option<ClientListGetParamCursor>,
}

impl ClientListGetParam {
    pub fn new() -> Self {
        ClientListGetParam {
            id: None,
            page_num: 1,
            order: None,
            page_size: 10,
            client_ip: None,
            mac: None,
            hostname: None,
            timestamp_before: None,
            timestamp_after: None,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainListGetParam {
    pub id: Option<u64>,
    pub order: Option<String>,
    pub page_num: u64,
    pub page_size: u64,
    pub domain: Option<String>,
    pub domain_filter_mode: Option<String>,
    pub domain_type: Option<u32>,
    pub client: Option<String>,
    pub domain_group: Option<String>,
    pub reply_code: Option<u16>,
    pub timestamp_before: Option<u64>,
    pub timestamp_after: Option<u64>,
    pub is_blocked: Option<bool>,
    pub is_cached: Option<bool>,
    pub cursor: Option<DomainListGetParamCursor>,
}

impl DomainListGetParam {
    pub fn new() -> Self {
        DomainListGetParam {
            id: None,
            page_num: 1,
            order: None,
            page_size: 10,
            domain: None,
            domain_filter_mode: None,
            domain_type: None,
            client: None,
            domain_group: None,
            reply_code: None,
            timestamp_before: None,
            timestamp_after: None,
            is_blocked: None,
            is_cached: None,
            cursor: None,
        }
    }
}

impl DB {
    pub fn new() -> Self {
        DB {
            conn: Mutex::new(None),
            path: Mutex::new(None),
            query_index_ready: AtomicBool::new(false),
            version: 10000, /* x: major version, xx: minor version, xx: patch version */
            query_plan: std::env::var("SMARTDNS_DEBUG_SQL").is_ok(),
        }
    }

    fn create_table(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp BIGINT NOT NULL,
                domain TEXT NOT NULL,
                domain_type INTEGER NOT NULL,
                client TEXT NOT NULL,
                domain_group TEXT NOT NULL,
                reply_code INTEGER NOT NULL,
                query_time INTEGER NOT NULL,
                ping_time REAL NOT NULL,
                is_blocked INTEGER DEFAULT 0,
                is_cached INTEGER DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_timestamp ON domain (timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_client ON domain (client)",
            [],
        )?;

        conn.execute(QUERY_INDEX_SQL, [])?;
        conn.execute(DOMAIN_NAME_TABLE_SQL, [])?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_hourly_count (
                timestamp BIGINT PRIMARY KEY,
                count INTEGER DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_daily_count (
                timestamp BIGINT PRIMARY KEY,
                count INTEGER DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS top_domain_list (
                domain TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                timestamp_start BIGINT DEFAULT 0,
                timestamp_end BIGINT DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS top_client_list (
                client TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                timestamp_start BIGINT DEFAULT 0,
                timestamp_end BIGINT DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "
        CREATE TABLE IF NOT EXISTS client (
            id INTEGER PRIMARY KEY,
            client_ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            hostname TEXT NOT NULL,
            last_query_timestamp BIGINT NOT NULL,
            UNIQUE(client_ip, mac)
        )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_client_last_query_timestamp ON client (last_query_timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS status_data (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            [self.version],
        )?;

        Ok(())
    }

    fn migrate_db(&self, _conn: &Connection) -> Result<(), Box<dyn Error>> {
        return Err(
            "Currently Not Support Migrate Database, Please Backup DB File, And Restart Server."
                .into(),
        );
    }

    fn init_db(&self, conn: &Connection) -> Result<(), Box<dyn Error>> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )",
            [],
        )?;

        let current_version: i32 = conn
            .query_row(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(self.version);

        if current_version >= self.version {
            self.create_table(conn)?;
        } else {
            self.migrate_db(conn)?;
        }

        Ok(())
    }

    pub fn open(&self, path: &str) -> Result<(), Box<dyn Error>> {
        self.query_index_ready.store(false, Ordering::Release);
        let ruconn: std::result::Result<Connection, rusqlite::Error> =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE);
        let mut conn = self.conn.lock().unwrap();
        if let Err(_) = ruconn {
            let ruconn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            )?;

            let ret = self.init_db(&ruconn);
            if let Err(e) = ret {
                _ = ruconn.close();
                fs::remove_file(path)?;
                return Err(e);
            }

            *conn = Some(ruconn);
        } else {
            *conn = Some(ruconn.unwrap());
        }

        conn.as_ref()
            .unwrap()
            .execute("PRAGMA synchronous = OFF", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA page_size  = 4096", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA cache_size = -8192", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA temp_store = MEMORY", [])?;

        let current_auto_vacuum: i32 =
            conn.as_ref()
                .unwrap()
                .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
        dns_log!(
            LogLevel::DEBUG,
            "Current auto_vacuum: {}",
            current_auto_vacuum
        );
        if current_auto_vacuum != 2 {
            dns_log!(LogLevel::INFO, "Set auto_vacuum to INCREMENTAL");
            conn.as_ref()
                .unwrap()
                .execute("PRAGMA auto_vacuum = INCREMENTAL", [])?;
            conn.as_ref().unwrap().execute("VACUUM", [])?;
        }

        conn.as_ref()
            .unwrap()
            .query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.as_ref()
            .unwrap()
            .query_row("PRAGMA wal_autocheckpoint = 1000", [], |_| Ok(()))?;
        // Cheap and needed before the first insert, which maintains it.
        conn.as_ref().unwrap().execute(DOMAIN_NAME_TABLE_SQL, [])?;
        *self.path.lock().unwrap() = conn.as_ref().unwrap().path().map(|v| v.to_string());
        Ok(())
    }

    pub fn run_vacuum(&self, pages: Option<u32>) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        dns_log!(LogLevel::DEBUG, "Start incremental vacuum");

        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
        let vacuum_sql = if let Some(pages) = pages {
            format!("PRAGMA incremental_vacuum({})", pages)
        } else {
            "PRAGMA incremental_vacuum".to_string()
        };

        let mut stmt = conn.prepare(vacuum_sql.as_str())?;
        let mut _reclaimed_pages = 0;

        let rows = stmt.query_map([], |_row| Ok(()));
        if let Ok(rows) = rows {
            for _row in rows {
                _reclaimed_pages += 1;
            }
        }
        Ok(())
    }

    pub fn query_index_ready(&self) -> bool {
        self.query_index_ready.load(Ordering::Acquire)
    }

    fn query_index_exists(conn: &Connection) -> Result<bool, rusqlite::Error> {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
            [QUERY_INDEX_NAME],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n > 0)
    }

    /// Builds the query index once (in the background, after the DNS server is
    /// up) and backfills the name dictionary on every start. Readers switch to
    /// the indexed SQL only when both are complete in this process, so a
    /// dictionary left stale by an older plugin is never trusted.
    pub fn prepare_query_index(&self) -> Result<(), Box<dyn Error>> {
        let guard = self.conn.lock().unwrap();
        let conn = match guard.as_ref() {
            Some(conn) => conn,
            None => return Err("db is not open".into()),
        };

        if !Self::query_index_exists(conn)? {
            dns_log!(LogLevel::INFO, "building query index {}", QUERY_INDEX_NAME);
            // With temp_store=MEMORY the index sort never spills and peaks at
            // about the index size in RSS; the default spills to temp files.
            conn.execute_batch("PRAGMA temp_store = DEFAULT")?;
            let built = conn.execute_batch(QUERY_INDEX_SQL);
            conn.execute_batch("PRAGMA temp_store = MEMORY")?;
            built?;
            // The build leaves a WAL about the size of the index behind.
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        }

        conn.execute_batch(
            "INSERT OR IGNORE INTO domain_name (domain) SELECT DISTINCT domain FROM domain",
        )?;
        self.query_index_ready.store(true, Ordering::Release);
        dns_log!(LogLevel::INFO, "query index ready");
        Ok(())
    }

    /// Hourly upkeep: drop names no longer in the log. The NOT EXISTS probe
    /// uses the query index, so it only runs once that index is confirmed.
    pub fn maintain_query_index(&self) -> Result<(), Box<dyn Error>> {
        if !self.query_index_ready() {
            return Ok(());
        }
        let guard = self.conn.lock().unwrap();
        let conn = match guard.as_ref() {
            Some(conn) => conn,
            None => return Err("db is not open".into()),
        };
        conn.execute(
            "DELETE FROM domain_name WHERE NOT EXISTS \
            (SELECT 1 FROM domain WHERE domain.domain = domain_name.domain)",
            [],
        )?;
        Ok(())
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)")?;
        let ret = stmt.execute(&[&key, &value]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_config_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut ret = HashMap::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare("SELECT key, value FROM config").unwrap();

        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((key, value))
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.insert(row.0, row.1);
                }
            }
        }

        Ok(ret)
    }

    pub fn set_status_data(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("INSERT OR REPLACE INTO status_data (key, value) VALUES (?1, ?2)")?;
        let ret = stmt.execute(&[&key, &value]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_status_data_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut ret = HashMap::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let stmt = conn.prepare("SELECT key, value FROM status_data");
        if let Err(e) = stmt {
            return Err(Box::new(e));
        }
        let mut stmt = stmt.unwrap();

        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((key, value))
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.insert(row.0, row.1);
                }
            }
        }

        Ok(ret)
    }

    pub fn debug_query_plan(&self, conn: &Connection, sql: String, sql_param: &Vec<String>) {
        if !self.query_plan {
            return;
        }

        let sqlplan = "EXPLAIN QUERY PLAN ".to_string() + &sql;
        let stmt = conn.prepare(sqlplan.as_str());
        if let Err(e) = stmt {
            dns_log!(LogLevel::DEBUG, "query plan sql error: {}", e);
            return;
        }

        let mut stmt = stmt.unwrap();
        let plan_rows = stmt.query_map(rusqlite::params_from_iter(sql_param.clone()), |row| {
            Ok(row.get::<_, String>(3)?)
        });

        if let Err(e) = plan_rows {
            dns_log!(LogLevel::DEBUG, "query plan error: {}", e);
            return;
        }

        let plan_rows = plan_rows.unwrap();
        dns_log!(LogLevel::NOTICE, "sql: {}", sql);
        for plan in plan_rows {
            if let Ok(plan) = plan {
                dns_log!(LogLevel::NOTICE, "plan: {}", plan);
            }
        }
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn
            .prepare("SELECT value FROM config WHERE key = ?")
            .unwrap();
        let rows = stmt.query_map(&[&key], |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return Ok(Some(row));
                }
            }
        }

        Ok(None)
    }

    pub fn update_domain_hourly_count(
        &self,
        tx: &Transaction<'_>,
        hourly_count: &HashMap<u64, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stmt = tx.prepare(
            "INSERT INTO domain_hourly_count (timestamp, count)
                 VALUES (
                    ?1,
                    ?2
                )
                ON CONFLICT(timestamp) DO UPDATE SET count = count + ?2;",
        )?;

        for (k, v) in hourly_count {
            stmt.execute(rusqlite::params![k, v])?;
        }
        stmt.finalize()?;
        Ok(())
    }

    pub fn update_domain_daily_count(
        &self,
        tx: &Transaction<'_>,
        daily_count: &HashMap<u64, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stmt = tx.prepare(
            "INSERT INTO domain_daily_count (timestamp, count)
                 VALUES (
                    ?1,
                    ?2
                )
                ON CONFLICT(timestamp) DO UPDATE SET count = count + ?2;",
        )?;

        for (k, v) in daily_count {
            stmt.execute(rusqlite::params![k, v])?;
        }
        stmt.finalize()?;
        Ok(())
    }

    pub fn insert_domain(&self, data: &Vec<DomainData>) -> Result<(), Box<dyn Error>> {
        let local_offset = Local::now().offset().local_minus_utc();
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let mut hourly_count = HashMap::new();
        let mut daily_count = HashMap::new();
        let conn = conn.as_mut().unwrap();

        let tx = conn.transaction()?;

        let mut stmt = tx.prepare(
            "INSERT INTO domain \
            (timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)")?;
        let mut name_stmt = tx.prepare("INSERT OR IGNORE INTO domain_name (domain) VALUES (?1)")?;

        for d in data {
            let ret = stmt.execute(rusqlite::params![
                &d.timestamp.to_string(),
                &d.domain,
                &d.domain_type.to_string(),
                &d.client,
                &d.domain_group,
                &d.reply_code,
                &d.query_time,
                &d.ping_time,
                &(d.is_blocked as i32),
                &(d.is_cached as i32)
            ]);

            let ret = ret.and_then(|_| name_stmt.execute([&d.domain]));
            if let Err(e) = ret {
                stmt.finalize()?;
                name_stmt.finalize()?;
                tx.rollback()?;
                return Err(Box::new(e));
            }

            let localtimestamp = d.timestamp + local_offset as u64 * 1000;

            let hour_timestamp =
                localtimestamp - localtimestamp % 3600000 - local_offset as u64 * 1000;
            let day_timestamp =
                localtimestamp - localtimestamp % 86400000 - local_offset as u64 * 1000;

            hourly_count
                .entry(hour_timestamp)
                .and_modify(|v| *v += 1)
                .or_insert(1);
            daily_count
                .entry(day_timestamp)
                .and_modify(|v| *v += 1)
                .or_insert(1);
        }

        stmt.finalize()?;
        name_stmt.finalize()?;

        self.update_domain_hourly_count(&tx, &hourly_count)?;
        self.update_domain_daily_count(&tx, &daily_count)?;

        tx.commit()?;

        Ok(())
    }

    pub fn get_db_file_path(&self) -> Option<String> {
        self.path.lock().unwrap().clone()
    }

    pub fn get_readonly_conn(&self) -> Option<Connection> {
        let path = self.get_db_file_path()?;

        let read_conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        );

        if let Err(_) = read_conn {
            return None;
        }

        Some(read_conn.unwrap())
    }

    /// # Returns
    ///
    /// A tuple containing:
    /// - `String`: The SQL WHERE clause.
    /// - `String`: The SQL ORDER BY clause.
    /// - `Vec<String>`: The parameters for the SQL query.
    pub fn get_domain_sql_where(
        param: Option<&DomainListGetParam>,
    ) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
        Self::domain_sql_where(param, false)
    }

    /// `for_count` drops the unary `+` that keeps id-ordered lists off the
    /// query index where a count gains the seek and has no order to protect.
    fn domain_sql_where(
        param: Option<&DomainListGetParam>,
        for_count: bool,
    ) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
        let mut is_desc_order = true;
        let mut is_cursor_prev = false;
        let param = match param {
            Some(v) => v,
            None => return Ok((String::new(), String::new(), Vec::new())),
        };
        // A count may seek the query index, except next to a client filter:
        // without statistics the planner would then prefer the domain index
        // over idx_domain_client even for a hot domain and a small client.
        let exact_domain = if for_count && param.client.is_none() {
            "domain = ?"
        } else {
            "+domain = ?"
        };
        let mut order_timestamp_first = true;

        let mut sql_where = Vec::new();
        let mut sql_param: Vec<String> = Vec::new();
        let mut sql_order = String::new();

        if let Some(v) = &param.id {
            sql_where.push("id = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.order {
            if v.eq_ignore_ascii_case("asc") {
                is_cursor_prev = true;
            } else if v.eq_ignore_ascii_case("desc") {
                is_cursor_prev = false;
            } else {
                return Err("order param error".into());
            }
        }

        if let Some(v) = &param.cursor {
            if v.direction.eq_ignore_ascii_case("prev") {
                is_desc_order = !is_desc_order;
            } else if v.direction.eq_ignore_ascii_case("next") {
                // do nothing
            } else {
                return Err("cursor direction param error".into());
            }
        }

        if let Some(v) = &param.domain {
            if let Some(m) = &param.domain_filter_mode {
                match m.to_lowercase().as_str() {
                    "endswith" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("%{}", v));
                    }
                    "startswith" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("{}%", v));
                    }
                    "contains" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("%{}%", v));
                    }
                    "equals" => {
                        sql_where.push(exact_domain.to_string());
                        sql_param.push(v.to_string());
                    }
                    "notempty" => {
                        sql_where.push("domain IS NOT NULL AND domain <> ''".to_string());
                    }
                    _ => return Err("domain_filter_mode param error".into()),
                }
            } else {
                // Unary + keeps id-ordered combinations on their original plan
                // instead of reading every row of a hot domain and sorting.
                sql_where.push(exact_domain.to_string());
                sql_param.push(v.to_string());
                order_timestamp_first = false;
            }
        }

        if let Some(v) = &param.domain_type {
            sql_where.push("domain_type = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.client {
            sql_where.push("client = ?".to_string());
            sql_param.push(v.clone());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.domain_group {
            sql_where.push("domain_group = ?".to_string());
            sql_param.push(v.clone());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.reply_code {
            sql_where.push("reply_code = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.timestamp_before {
            sql_where.push("timestamp <= ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.timestamp_after {
            sql_where.push("timestamp >= ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.cursor {
            if is_cursor_prev {
                if let Some(id) = &v.id {
                    if is_desc_order {
                        sql_where.push("id > ?".to_string());
                    } else {
                        sql_where.push("id < ?".to_string());
                    }

                    sql_param.push(id.to_string());
                    order_timestamp_first = false;
                }
            } else {
                if let Some(id) = &v.id {
                    if is_desc_order {
                        sql_where.push("id < ?".to_string());
                    } else {
                        sql_where.push("id > ?".to_string());
                    }

                    sql_param.push(id.to_string());
                    order_timestamp_first = false;
                }
            }
        }

        if let Some(v) = &param.is_blocked {
            if *v {
                sql_where.push("is_blocked = 1".to_string());
            } else {
                sql_where.push("is_blocked = 0".to_string());
            }
            order_timestamp_first = false;
        }

        if let Some(v) = &param.is_cached {
            if *v {
                sql_where.push("is_cached = 1".to_string());
            } else {
                sql_where.push("is_cached = 0".to_string());
            }
            order_timestamp_first = false;
        }

        if is_cursor_prev {
            is_desc_order = !is_desc_order;
        }

        if is_desc_order {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY timestamp DESC, id DESC");
            } else {
                sql_order.push_str(" ORDER BY id DESC, timestamp DESC");
            }
        } else {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY timestamp ASC, id ASC");
            } else {
                sql_order.push_str(" ORDER BY id ASC, timestamp ASC");
            }
        }

        let sql_where = if sql_where.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", sql_where.join(" AND "))
        };

        Ok((sql_where, sql_order, sql_param))
    }

    /// Builds the indexed, query-time ordered form of a domain-log read when it
    /// applies: only domain (exact or contains), time range, order and cursor
    /// are set and the query index is ready. Anything else, or a cursor row that
    /// no longer exists, keeps the original id-ordered SQL.
    fn time_ordered_query(
        &self,
        conn: &Connection,
        param: &DomainListGetParam,
    ) -> Option<TimeOrderedQuery> {
        if !self.query_index_ready()
            || param.id.is_some()
            || param.domain_type.is_some()
            || param.client.is_some()
            || param.domain_group.is_some()
            || param.reply_code.is_some()
            || param.is_blocked.is_some()
            || param.is_cached.is_some()
        {
            return None;
        }

        let desc = match param.order.as_deref() {
            None => true,
            Some(v) if v.eq_ignore_ascii_case("desc") => true,
            Some(v) if v.eq_ignore_ascii_case("asc") => false,
            Some(_) => return None,
        };
        let prev = match &param.cursor {
            None => false,
            Some(c) if c.direction.eq_ignore_ascii_case("prev") => true,
            Some(c) if c.direction.eq_ignore_ascii_case("next") => false,
            Some(_) => return None,
        };

        let mut sql_where = Vec::new();
        let mut sql_param: Vec<String> = Vec::new();
        if let Some(v) = &param.domain {
            match param
                .domain_filter_mode
                .as_deref()
                .map(|m| m.to_lowercase())
            {
                None => {
                    sql_where.push("domain = ?".to_string());
                    sql_param.push(v.clone());
                }
                Some(m) if m == "equals" => {
                    sql_where.push("domain = ?".to_string());
                    sql_param.push(v.clone());
                }
                Some(m) if m == "contains" => {
                    // One statement, so the dictionary and the log are read in
                    // the same snapshot.
                    sql_where.push(
                        "domain IN (SELECT domain FROM domain_name WHERE domain LIKE ?)"
                            .to_string(),
                    );
                    sql_param.push(format!("%{}%", v));
                }
                Some(_) => return None,
            }
        }

        // Pages walk forward in the displayed order; prev pages read backwards
        // and are reversed by the caller.
        let read_desc = desc != prev;
        let mut before = param.timestamp_before;
        let mut after = param.timestamp_after;
        let mut paged_by_cursor = false;

        if let Some(cursor_id) = param.cursor.as_ref().and_then(|c| c.id) {
            // A cursor row that is gone (retention or API delete) falls back
            // to the original id paging.
            let anchor: u64 = conn
                .query_row(
                    "SELECT timestamp FROM domain WHERE id = ?",
                    [cursor_id.to_string()],
                    |r| r.get(0),
                )
                .ok()?;
            // Rows past the cursor in read order; that side's time bound is
            // implied by the anchor and replacing it keeps the range seek.
            if read_desc {
                sql_where.push("(timestamp, id) < (?, ?)".to_string());
                before = None;
            } else {
                sql_where.push("(timestamp, id) > (?, ?)".to_string());
                after = None;
            }
            sql_param.push(anchor.to_string());
            sql_param.push(cursor_id.to_string());
            paged_by_cursor = true;
        }

        if let Some(v) = before {
            sql_where.push("timestamp <= ?".to_string());
            sql_param.push(v.to_string());
        }
        if let Some(v) = after {
            sql_where.push("timestamp >= ?".to_string());
            sql_param.push(v.to_string());
        }

        let sql_where = if sql_where.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", sql_where.join(" AND "))
        };
        let sql_order = if read_desc {
            " ORDER BY timestamp DESC, id DESC".to_string()
        } else {
            " ORDER BY timestamp ASC, id ASC".to_string()
        };

        Some(TimeOrderedQuery {
            sql_where,
            sql_order,
            sql_param,
            paged_by_cursor,
        })
    }

    pub fn get_domain_list_count(&self, param: Option<&DomainListGetParam>) -> u64 {
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return 0;
        }

        let conn = conn.as_ref().unwrap();
        let mut sql = String::new();
        let mut sql_param = Vec::new();
        sql.push_str("SELECT COUNT(*) FROM domain");
        let timed = match param {
            Some(p) => self.time_ordered_query(conn, p),
            None => None,
        };
        if let Some(q) = timed {
            sql.push_str(q.sql_where.as_str());
            sql_param = q.sql_param;
        } else if let Ok((sql_where, sql_order, mut ret_sql_param)) =
            Self::domain_sql_where(param, true)
        {
            sql.push_str(sql_where.as_str());
            sql.push_str(sql_order.as_str());
            sql_param.append(&mut ret_sql_param);
        }

        let mut stmt = conn.prepare(sql.as_str()).unwrap();
        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return row;
                }
            }
        }

        0
    }

    pub fn delete_domain_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM domain WHERE id = ?", &[&id]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn delete_domain_before_timestamp(&self, timestamp: u64) -> Result<u64, Box<dyn Error>> {
        let ret = {
            let conn = self.conn.lock().unwrap();
            if conn.as_ref().is_none() {
                return Err("db is not open".into());
            }

            let conn = conn.as_ref().unwrap();

            let ret = conn.execute("DELETE FROM domain WHERE timestamp <= ?", &[&timestamp]);

            if let Err(e) = ret {
                return Err(Box::new(e));
            }

            Ok(ret.unwrap() as u64)
        };

        self.run_vacuum(Some(50000))?;

        ret
    }

    pub fn refresh_client_top_list(&self, timestamp: u64) -> Result<(), Box<dyn Error>> {
        let mut client_count_list = Vec::new();
        let conn = match self.get_readonly_conn() {
            Some(v) => v,
            None => return Err("db is not open".into()),
        };

        let timestamp_now = smartdns::get_utc_time_ms();
        let sql = "SELECT client, COUNT(*) FROM domain WHERE timestamp >= ? GROUP BY client ORDER BY COUNT(*) DESC LIMIT 20";
        self.debug_query_plan(&conn, sql.to_string(), &vec![timestamp.to_string()]);
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([timestamp.to_string()], |row| {
            Ok(ClientQueryCount {
                client_ip: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: timestamp,
                timestamp_end: timestamp_now,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    client_count_list.push(row);
                }
            }
        }

        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();

        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("DELETE FROM top_client_list")?;
        stmt.execute([])?;
        stmt.finalize()?;
        let mut stmt =
            tx.prepare("INSERT INTO top_client_list (client, count, timestamp_start, timestamp_end) VALUES ( ?1, ?2, $3, $4)")?;
        for client in &client_count_list {
            stmt.execute(rusqlite::params![
                client.client_ip,
                client.count,
                client.timestamp_start,
                client.timestamp_end
            ])?;
            dns_log!(
                LogLevel::DEBUG,
                "client: {}, count: {}, timestamp_start: {}, timestamp_end: {}",
                client.client_ip,
                client.count,
                client.timestamp_start,
                client.timestamp_end
            );
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_client_top_list(&self, count: u32) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("SELECT client, count, timestamp_start, timestamp_end FROM top_client_list ORDER BY count DESC LIMIT ?")?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(ClientQueryCount {
                client_ip: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: row.get(2)?,
                timestamp_end: row.get(3)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(ret)
    }

    pub fn delete_daily_query_count_before_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute(
            "DELETE FROM domain_daily_count WHERE timestamp <= ?",
            &[&timestamp],
        );

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_daily_query_count(&self, past_days: u32) -> Result<DailyQueryCount, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let seconds = 86400 * past_days - utils::seconds_until_next_hour() as u32;
        let mut stmt = conn.prepare(
            "SELECT \
                    strftime('%Y-%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) AS date, timestamp, count \
                 FROM \
                    domain_daily_count \
                 WHERE \
                    timestamp >= strftime('%s', 'now') * 1000 - ? * 1000 \
                 ORDER BY \
                    timestamp DESC;\
                 ",
        )?;

        let rows = stmt.query_map([seconds.to_string()], |row| {
            Ok(DailyQueryCountItem {
                day: row.get(0)?,
                query_count: row.get(2)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(DailyQueryCount {
            query_timestamp: smartdns::get_utc_time_ms(),
            daily_query_count: ret,
        })
    }

    pub fn delete_hourly_query_count_before_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute(
            "DELETE FROM domain_hourly_count WHERE timestamp <= ?",
            &[&timestamp],
        );

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_hourly_query_count(
        &self,
        past_hours: u32,
    ) -> Result<HourlyQueryCount, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let query_start = std::time::Instant::now();
        let conn = conn.as_ref().unwrap();
        let seconds = 3600 * past_hours - utils::seconds_until_next_hour() as u32;

        let sql = "SELECT \
                    strftime('%Y-%m-%d %H:00:00', datetime(timestamp / 1000, 'unixepoch', 'localtime')) AS hour, timestamp, count \
                 FROM \
                    domain_hourly_count \
                 WHERE \
                    timestamp >= strftime('%s', 'now') * 1000 - ? * 1000 \
                 ORDER BY \
                    timestamp DESC;\
                 ";
        self.debug_query_plan(conn, sql.to_string(), &vec![seconds.to_string()]);
        let mut stmt = conn.prepare(sql)?;

        let rows = stmt.query_map([seconds.to_string()], |row| {
            Ok(HourlyQueryCountItem {
                hour: row.get(0)?,
                query_count: row.get(2)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "hourly_query_count time: {}ms",
            query_start.elapsed().as_millis()
        );

        Ok(HourlyQueryCount {
            query_timestamp: smartdns::get_utc_time_ms(),
            hourly_query_count: ret,
        })
    }

    pub fn refresh_domain_top_list(&self, timestamp: u64) -> Result<(), Box<dyn Error>> {
        let mut domain_count_list = Vec::new();
        let conn = match self.get_readonly_conn() {
            Some(v) => v,
            None => return Err("db is not open".into()),
        };

        let timestamp_now = smartdns::get_utc_time_ms();
        let sql = TOP_DOMAIN_SQL;
        self.debug_query_plan(&conn, sql.to_string(), &vec![timestamp.to_string()]);
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([timestamp.to_string()], |row| {
            Ok(DomainQueryCount {
                domain: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: timestamp,
                timestamp_end: timestamp_now,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    domain_count_list.push(row);
                }
            }
        }

        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("DELETE FROM top_domain_list")?;
        stmt.execute([])?;
        stmt.finalize()?;
        let mut stmt =
            tx.prepare("INSERT INTO top_domain_list (domain, count, timestamp_start, timestamp_end) VALUES ( ?1, ?2, ?3, ?4)")?;
        for domain in &domain_count_list {
            stmt.execute(rusqlite::params![
                domain.domain,
                domain.count,
                domain.timestamp_start,
                domain.timestamp_end
            ])?;
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_domain_top_list(&self, count: u32) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let mut stmt = conn.prepare("SELECT domain, count, timestamp_start, timestamp_end FROM top_domain_list DESC LIMIT ?")?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(DomainQueryCount {
                domain: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: row.get(2)?,
                timestamp_end: row.get(3)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(ret)
    }

    pub fn get_domain_list(
        &self,
        param: Option<&DomainListGetParam>,
    ) -> Result<QueryDomainListResult, Box<dyn Error>> {
        let query_start = std::time::Instant::now();
        let mut cursor_reverse = false;

        let mut ret = QueryDomainListResult {
            domain_list: vec![],
            total_count: 0,
            step_by_cursor: false,
        };

        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let timed = match param {
            Some(p) => self.time_ordered_query(conn, p),
            None => None,
        };
        let paged_by_cursor = timed.as_ref().map(|q| q.paged_by_cursor);
        let (sql_where, sql_order, mut sql_param) = match timed {
            Some(q) => (q.sql_where, q.sql_order, q.sql_param),
            None => Self::get_domain_sql_where(param)?,
        };

        let mut sql = String::new();
        sql.push_str("SELECT id, timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached FROM domain");

        sql.push_str(sql_where.as_str());
        sql.push_str(sql_order.as_str());

        if let Some(p) = param {
            let mut with_offset = true;
            if let Some(cursor) = &p.cursor {
                if paged_by_cursor.unwrap_or(cursor.id.is_some()) {
                    sql.push_str(" LIMIT ?");
                    sql_param.push(p.page_size.to_string());
                    with_offset = false;
                }

                if cursor.direction.eq_ignore_ascii_case("prev") {
                    cursor_reverse = true;
                }
            }

            if with_offset {
                sql.push_str(" LIMIT ? OFFSET ?");
                sql_param.push(p.page_size.to_string());
                sql_param.push(((p.page_num - 1) * p.page_size).to_string());
            }
        }

        self.debug_query_plan(conn, sql.clone(), &sql_param);
        let stmt = conn.prepare(&sql);

        if let Err(e) = stmt {
            dns_log!(LogLevel::ERROR, "get_domain_list error: {}", e);
            return Err("get_domain_list error".into());
        }

        let mut stmt = stmt?;

        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| {
            Ok(DomainData {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                domain: row.get(2)?,
                domain_type: row.get(3)?,
                client: row.get(4)?,
                domain_group: row.get(5)?,
                reply_code: row.get(6)?,
                query_time: row.get(7)?,
                ping_time: row.get(8)?,
                is_blocked: row.get(9)?,
                is_cached: row.get(10)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.domain_list.push(row);
                }
            }
        }

        if cursor_reverse {
            ret.domain_list.reverse();
        }

        if let Some(p) = param {
            if let Some(v) = &p.cursor {
                ret.total_count = v.total_count;
                ret.step_by_cursor = true;
            } else {
                let total_count = self.get_domain_list_count(param);
                ret.total_count = total_count;
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "domain_list time: {}ms",
            query_start.elapsed().as_millis()
        );
        Ok(ret)
    }

    pub fn insert_client(&self, client_data: &Vec<ClientData>) -> Result<(), Box<dyn Error>> {
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("INSERT INTO client (id, client_ip, mac, hostname, last_query_timestamp) VALUES (
            (SELECT MAX(rowid) FROM client) + 1,
            ?1, ?2, ?3, ?4)
            ON CONFLICT(client_ip, mac) DO UPDATE SET last_query_timestamp = excluded.last_query_timestamp;
            ")?;
        for d in client_data {
            let ret = stmt.execute(rusqlite::params![
                d.client_ip,
                d.mac,
                d.hostname,
                d.last_query_timestamp
            ]);

            if let Err(e) = ret {
                stmt.finalize()?;
                tx.rollback()?;
                return Err(Box::new(e));
            }
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_client_list_count(&self, param: Option<&ClientListGetParam>) -> u64 {
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return 0;
        }

        let conn = conn.as_ref().unwrap();
        let mut sql = String::new();
        let mut sql_param = Vec::new();
        sql.push_str("SELECT COUNT(*) FROM client");
        if let Ok((sql_where, sql_order, mut ret_sql_param)) = Self::get_client_sql_where(param) {
            sql.push_str(sql_where.as_str());
            sql.push_str(sql_order.as_str());
            sql_param.append(&mut ret_sql_param);
        }

        let mut stmt = conn.prepare(sql.as_str()).unwrap();
        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return row;
                }
            }
        }

        0
    }

    fn get_client_sql_where(
        param: Option<&ClientListGetParam>,
    ) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
        let mut is_desc_order = true;
        let mut is_cursor_prev = false;
        let param = match param {
            Some(v) => v,
            None => return Ok((String::new(), String::new(), Vec::new())),
        };
        let mut order_timestamp_first = false;

        let mut sql_where = Vec::new();
        let mut sql_param: Vec<String> = Vec::new();
        let mut sql_order = String::new();

        if let Some(v) = &param.id {
            sql_where.push("id = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.order {
            if v.eq_ignore_ascii_case("asc") {
                is_cursor_prev = true;
            } else if v.eq_ignore_ascii_case("desc") {
                is_cursor_prev = false;
            } else {
                return Err("order param error".into());
            }
        }

        if let Some(v) = &param.cursor {
            if v.direction.eq_ignore_ascii_case("prev") {
                is_desc_order = !is_desc_order;
            } else if v.direction.eq_ignore_ascii_case("next") {
                // do nothing
            } else {
                return Err("cursor direction param error".into());
            }
        }

        if let Some(v) = &param.client_ip {
            sql_where.push("client_ip = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.mac {
            sql_where.push("mac = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.hostname {
            sql_where.push("hostname = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.timestamp_before {
            sql_where.push("last_query_timestamp <= ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.timestamp_after {
            sql_where.push("last_query_timestamp >= ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.cursor {
            if is_cursor_prev {
                if let Some(id) = &v.id {
                    if is_desc_order {
                        sql_where.push("id > ?".to_string());
                    } else {
                        sql_where.push("id < ?".to_string());
                    }

                    sql_param.push(id.to_string());
                    order_timestamp_first = false;
                }
            } else {
                if let Some(id) = &v.id {
                    if is_desc_order {
                        sql_where.push("id < ?".to_string());
                    } else {
                        sql_where.push("id > ?".to_string());
                    }

                    sql_param.push(id.to_string());
                    order_timestamp_first = false;
                }
            }
        }

        if is_cursor_prev {
            is_desc_order = !is_desc_order;
        }

        if is_desc_order {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY last_query_timestamp DESC, id DESC");
            } else {
                sql_order.push_str(" ORDER BY id DESC, last_query_timestamp DESC");
            }
        } else {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY last_query_timestamp ASC, id ASC");
            } else {
                sql_order.push_str(" ORDER BY id ASC, last_query_timestamp ASC");
            }
        }

        let sql_where = if sql_where.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", sql_where.join(" AND "))
        };

        Ok((sql_where, sql_order, sql_param))
    }

    pub fn get_client_list(
        &self,
        param: Option<&ClientListGetParam>,
    ) -> Result<QueryClientListResult, Box<dyn Error>> {
        let query_start = std::time::Instant::now();
        let mut cursor_reverse = false;

        let mut ret = QueryClientListResult {
            client_list: vec![],
            total_count: 0,
            step_by_cursor: false,
        };

        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let (sql_where, sql_order, mut sql_param) = Self::get_client_sql_where(param)?;

        let mut sql = String::new();
        sql.push_str("SELECT id, client_ip, mac, hostname, last_query_timestamp FROM client");

        sql.push_str(sql_where.as_str());
        sql.push_str(sql_order.as_str());

        if let Some(p) = param {
            let mut with_offset = true;
            if let Some(cursor) = &p.cursor {
                if cursor.id.is_some() {
                    sql.push_str(" LIMIT ?");
                    sql_param.push(p.page_size.to_string());
                    with_offset = false;
                }

                if cursor.direction.eq_ignore_ascii_case("prev") {
                    cursor_reverse = true;
                }
            }

            if with_offset {
                sql.push_str(" LIMIT ? OFFSET ?");
                sql_param.push(p.page_size.to_string());
                sql_param.push(((p.page_num - 1) * p.page_size).to_string());
            }
        }

        self.debug_query_plan(conn, sql.clone(), &sql_param);
        let stmt = conn.prepare(&sql);
        if let Err(e) = stmt {
            dns_log!(LogLevel::ERROR, "get_client_list error: {}", e);
            return Err("get_client_list error".into());
        }
        let mut stmt = stmt?;

        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| {
            Ok(ClientData {
                id: row.get(0)?,
                client_ip: row.get(1)?,
                mac: row.get(2)?,
                hostname: row.get(3)?,
                last_query_timestamp: row.get(4)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.client_list.push(row);
                }
            }
        }

        if cursor_reverse {
            ret.client_list.reverse();
        }

        if let Some(p) = param {
            if let Some(v) = &p.cursor {
                ret.total_count = v.total_count;
                ret.step_by_cursor = true;
            } else {
                let total_count = self.get_client_list_count(param);
                ret.total_count = total_count;
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "domain_list time: {}ms",
            query_start.elapsed().as_millis()
        );
        Ok(ret)
    }

    pub fn delete_client_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM client WHERE id = ?", &[&id]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_db_size(&self) -> u64 {
        let db_file = self.get_db_file_path();
        let mut total_size = 0;
        if db_file.is_none() {
            return 0;
        }

        let db_file = db_file.unwrap();
        let wal_file = db_file.clone() + "-wal";

        let metadata = fs::metadata(db_file);
        if let Err(_) = metadata {
            return 0;
        }
        total_size += metadata.unwrap().len();

        let wal_metadata = fs::metadata(wal_file);
        if let Ok(wal_metadata) = wal_metadata {
            let wal_size = wal_metadata.len();
            total_size += wal_size;
        }

        total_size
    }

    pub fn close(&self) {
        // A first-time index build holds the writer lock, so closing waits for
        // it (about 17 s on a 1.4e7-row log, once per database).
        let mut conn = self.conn.lock().unwrap();
        self.query_index_ready.store(false, Ordering::Release);
        *self.path.lock().unwrap() = None;
        if conn.as_ref().is_none() {
            return;
        }

        if let Some(t) = conn.take() {
            let _ = t.close();
        }
    }
}

impl Drop for DB {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod query_index_tests {
    use super::*;

    /// A realistic wall-clock base: insert_domain buckets rows by local day.
    const BASE: u64 = 1_790_000_000_000;

    const DOMAINS: [&str; 5] = [
        "a.example.com",
        "b.test.org",
        "cdn.example.net",
        "x.y",
        "rare.example.org",
    ];

    struct Fixture {
        _dir: tempfile::TempDir,
        path: String,
        db: DB,
        rows: Vec<(u64, u64, String)>,
    }

    fn row(i: u64) -> DomainData {
        // 150 distinct timestamps for hundreds of rows: they run against
        // insertion order and every one is shared, also within each domain, so
        // page boundaries split equal timestamps and only the id orders them.
        let timestamp = BASE + (i * 7919) % 150 * 10;
        let domain = if i.is_multiple_of(97) {
            DOMAINS[4]
        } else {
            DOMAINS[(i % 4) as usize]
        };
        DomainData {
            id: 0,
            timestamp,
            domain: domain.to_string(),
            domain_type: 1,
            client: format!("10.0.0.{}", i % 5),
            domain_group: "g".to_string(),
            reply_code: (i % 3) as u16,
            query_time: 1,
            ping_time: -1.0,
            is_blocked: i.is_multiple_of(4),
            is_cached: false,
        }
    }

    fn all_rows(conn: &Connection) -> Vec<(u64, u64, String)> {
        let mut stmt = conn
            .prepare("SELECT id, timestamp, domain FROM domain")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// A database as an older plugin leaves it: log rows, no query index and
    /// no dictionary entries for them.
    fn legacy_fixture(count: u64) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("smartdns.db").to_str().unwrap().to_string();
        {
            let db = DB::new();
            db.open(&path).unwrap();
            db.close();
        }
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP INDEX idx_domain_domain_timestamp; DROP TABLE domain_name;")
            .unwrap();
        let mut stmt = conn
            .prepare(
                "INSERT INTO domain (timestamp, domain, domain_type, client, domain_group, \
                reply_code, query_time, ping_time, is_blocked, is_cached) \
                VALUES (?, ?, 1, ?, 'g', ?, 1, -1, ?, 0)",
            )
            .unwrap();
        for i in 0..count {
            let d = row(i);
            stmt.execute(rusqlite::params![
                d.timestamp,
                d.domain,
                d.client,
                d.reply_code,
                d.is_blocked as i32
            ])
            .unwrap();
        }
        drop(stmt);
        let rows = all_rows(&conn);
        drop(conn);
        let db = DB::new();
        db.open(&path).unwrap();
        Fixture {
            _dir: dir,
            path,
            db,
            rows,
        }
    }

    fn ready_fixture(count: u64) -> Fixture {
        let f = legacy_fixture(count);
        f.db.prepare_query_index().unwrap();
        f
    }

    fn raw(f: &Fixture) -> Connection {
        Connection::open(&f.path).unwrap()
    }

    fn index_exists(f: &Fixture) -> bool {
        DB::query_index_exists(&raw(f)).unwrap()
    }

    fn names(f: &Fixture) -> Vec<String> {
        let conn = raw(f);
        let mut stmt = conn
            .prepare("SELECT domain FROM domain_name ORDER BY domain")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    fn distinct_domains(f: &Fixture) -> Vec<String> {
        let conn = raw(f);
        let mut stmt = conn
            .prepare("SELECT DISTINCT domain FROM domain ORDER BY domain")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn existing_log_gets_index_and_full_dictionary() {
        let f = legacy_fixture(300);
        assert!(!f.db.query_index_ready());
        assert!(!index_exists(&f));
        assert!(names(&f).is_empty());

        f.db.prepare_query_index().unwrap();
        assert!(f.db.query_index_ready());
        assert!(index_exists(&f));
        assert_eq!(names(&f), distinct_domains(&f));
        let temp_store: i64 =
            f.db.conn
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .query_row("PRAGMA temp_store", [], |r| r.get(0))
                .unwrap();
        assert_eq!(
            temp_store, 2,
            "temp_store must return to MEMORY after the build"
        );
    }

    #[test]
    fn readiness_is_not_persisted_across_opens() {
        let f = ready_fixture(50);
        f.db.close();
        // An older plugin logs a new domain without maintaining the dictionary.
        raw(&f)
            .execute(
                "INSERT INTO domain (timestamp, domain, domain_type, client, domain_group, \
                reply_code, query_time, ping_time) VALUES (5, 'late.example', 1, 'c', 'g', 0, 1, -1)",
                [],
            )
            .unwrap();
        let db = DB::new();
        db.open(&f.path).unwrap();
        assert!(!db.query_index_ready());
        db.prepare_query_index().unwrap();
        let conn = Connection::open(&f.path).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM domain_name WHERE domain = 'late.example'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn failed_build_keeps_reads_on_the_original_sql() {
        let f = legacy_fixture(20);
        // A table squatting on the index name makes CREATE INDEX fail for real.
        raw(&f)
            .execute_batch("CREATE TABLE idx_domain_domain_timestamp (x)")
            .unwrap();
        assert!(f.db.prepare_query_index().is_err());
        assert!(!f.db.query_index_ready());
        let temp_store: i64 =
            f.db.conn
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .query_row("PRAGMA temp_store", [], |r| r.get(0))
                .unwrap();
        assert_eq!(temp_store, 2);
    }

    #[test]
    fn inserts_and_maintenance_keep_dictionary_exact() {
        let f = ready_fixture(40);
        f.db.insert_domain(&vec![DomainData {
            domain: "new.example".into(),
            ..row(1)
        }])
        .unwrap();
        assert!(names(&f).contains(&"new.example".to_string()));
        raw(&f)
            .execute("DELETE FROM domain WHERE domain = 'x.y'", [])
            .unwrap();
        f.db.maintain_query_index().unwrap();
        assert_eq!(names(&f), distinct_domains(&f));
    }

    fn expected(f: &Fixture, keep: &dyn Fn(&(u64, u64, String)) -> bool, desc: bool) -> Vec<u64> {
        let mut rows: Vec<&(u64, u64, String)> = f.rows.iter().filter(|r| keep(r)).collect();
        rows.sort_by_key(|r| (r.1, r.0));
        if desc {
            rows.reverse();
        }
        rows.iter().map(|r| r.0).collect()
    }

    fn ids(list: &QueryDomainListResult) -> Vec<u64> {
        list.domain_list.iter().map(|d| d.id).collect()
    }

    fn walk_cursor(f: &Fixture, base: &DomainListGetParam, total: u64) -> Vec<u64> {
        let mut seen = Vec::new();
        let mut p = base.clone();
        loop {
            let page = f.db.get_domain_list(Some(&p)).unwrap();
            if page.domain_list.is_empty() {
                break;
            }
            if p.cursor.is_none() {
                assert_eq!(page.total_count, total);
            }
            let last = page.domain_list.last().unwrap().id;
            seen.extend(ids(&page));
            p = base.clone();
            p.cursor = Some(DomainListGetParamCursor {
                id: Some(last),
                total_count: total,
                direction: "next".to_string(),
            });
        }
        seen
    }

    #[test]
    fn time_ordered_reads_match_query_time_order_on_every_page() {
        let f = ready_fixture(600);
        let a_rows: Vec<u64> = f
            .rows
            .iter()
            .filter(|r| r.2 == "a.example.com")
            .map(|r| r.1)
            .collect();
        let distinct: std::collections::HashSet<u64> = a_rows.iter().copied().collect();
        assert!(
            distinct.len() < a_rows.len(),
            "fixture must share timestamps within a domain"
        );
        type Filter<'a> = (Option<&'a str>, Option<&'a str>, Box<dyn Fn(&str) -> bool>);
        let filters: Vec<Filter> = vec![
            (None, None, Box::new(|_| true)),
            (
                Some("a.example.com"),
                None,
                Box::new(|d| d == "a.example.com"),
            ),
            (
                Some("rare.example.org"),
                Some("equals"),
                Box::new(|d| d == "rare.example.org"),
            ),
            (
                Some("example"),
                Some("contains"),
                Box::new(|d| d.contains("example")),
            ),
            (
                Some("EXAMPLE.n"),
                Some("contains"),
                Box::new(|d| d.contains("example.n")),
            ),
            (Some("no-such"), Some("contains"), Box::new(|_| false)),
        ];
        let bounds = [(None, None), (Some(BASE + 1_200), Some(BASE + 300))];
        for (domain, mode, keep_domain) in &filters {
            for (before, after) in bounds {
                for desc in [true, false] {
                    let keep = |r: &(u64, u64, String)| {
                        keep_domain(&r.2)
                            && before.is_none_or(|b| r.1 <= b)
                            && after.is_none_or(|a| r.1 >= a)
                    };
                    let want = expected(&f, &keep, desc);
                    let mut p = DomainListGetParam::new();
                    p.domain = domain.map(|v| v.to_string());
                    p.domain_filter_mode = mode.map(|v| v.to_string());
                    p.timestamp_before = before;
                    p.timestamp_after = after;
                    p.order = Some(if desc { "desc" } else { "asc" }.to_string());
                    p.page_size = 7;
                    let ctx = format!(
                        "{:?} {:?} {:?} {:?} desc={}",
                        domain, mode, before, after, desc
                    );

                    assert_eq!(
                        f.db.get_domain_list_count(Some(&p)),
                        want.len() as u64,
                        "{}",
                        ctx
                    );
                    p.page_num = 3;
                    let page = f.db.get_domain_list(Some(&p)).unwrap();
                    let from = (14).min(want.len());
                    assert_eq!(
                        ids(&page),
                        want[from..(from + 7).min(want.len())].to_vec(),
                        "{}",
                        ctx
                    );
                    p.page_num = 1;
                    assert_eq!(walk_cursor(&f, &p, want.len() as u64), want, "{}", ctx);

                    // Stepping back from any page returns the page before it.
                    if want.len() > 14 {
                        let mut prev = p.clone();
                        prev.cursor = Some(DomainListGetParamCursor {
                            id: Some(want[14]),
                            total_count: want.len() as u64,
                            direction: "prev".to_string(),
                        });
                        let page = f.db.get_domain_list(Some(&prev)).unwrap();
                        assert_eq!(ids(&page), want[7..14].to_vec(), "prev {}", ctx);
                    }
                }
            }
        }
    }

    #[test]
    fn id_ordered_combinations_are_unchanged() {
        let f = ready_fixture(300);
        let mut p = DomainListGetParam::new();
        p.domain = Some("a.example.com".to_string());
        p.is_blocked = Some(true);
        p.page_size = 1000;
        let mut want: Vec<u64> = f
            .rows
            .iter()
            .filter(|r| r.2 == "a.example.com")
            .map(|r| r.0)
            .filter(|id| {
                raw(&f)
                    .query_row("SELECT is_blocked FROM domain WHERE id = ?", [id], |r| {
                        r.get::<_, i64>(0)
                    })
                    .unwrap()
                    == 1
            })
            .collect();
        want.sort();
        want.reverse();
        assert_eq!(ids(&f.db.get_domain_list(Some(&p)).unwrap()), want);
    }

    #[test]
    fn id_ordered_cursor_paging_keeps_time_bounds() {
        let f = ready_fixture(300);
        let (before, after) = (BASE + 1_200, BASE + 300);
        for (b, a) in [
            (Some(before), None),
            (None, Some(after)),
            (Some(before), Some(after)),
        ] {
            for desc in [true, false] {
                let mut want: Vec<u64> = raw(&f)
                    .prepare(
                        "SELECT id FROM domain WHERE client = '10.0.0.1' \
                        AND timestamp <= ?1 AND timestamp >= ?2 ORDER BY id",
                    )
                    .unwrap()
                    .query_map(
                        [b.map_or(i64::MAX, |v| v as i64), a.map_or(0, |v| v as i64)],
                        |r| r.get(0),
                    )
                    .unwrap()
                    .map(|r| r.unwrap())
                    .collect();
                if desc {
                    want.reverse();
                }
                let mut p = DomainListGetParam::new();
                p.client = Some("10.0.0.1".to_string());
                p.timestamp_before = b;
                p.timestamp_after = a;
                p.order = Some(if desc { "desc" } else { "asc" }.to_string());
                p.page_size = 7;
                assert_eq!(
                    walk_cursor(&f, &p, want.len() as u64),
                    want,
                    "{:?} {:?} desc={}",
                    b,
                    a,
                    desc
                );
                // Stepping back from the second page returns the first.
                let first = f.db.get_domain_list(Some(&p)).unwrap();
                let mut back = p.clone();
                back.cursor = Some(DomainListGetParamCursor {
                    id: Some(want[7]),
                    total_count: want.len() as u64,
                    direction: "prev".to_string(),
                });
                assert_eq!(
                    ids(&f.db.get_domain_list(Some(&back)).unwrap()),
                    ids(&first)
                );
            }
        }
    }

    #[test]
    fn client_cursor_paging_keeps_order_and_time_bounds() {
        let f = ready_fixture(1);
        let clients: Vec<ClientData> = (0..60u64)
            .map(|i| ClientData {
                id: 0,
                hostname: String::new(),
                client_ip: format!("10.1.0.{}", i),
                mac: String::new(),
                last_query_timestamp: BASE + (i * 7919) % 40 * 10,
            })
            .collect();
        f.db.insert_client(&clients).unwrap();
        let (before, after) = (BASE + 300, BASE + 80);
        for (b, a) in [
            (None, None),
            (Some(before), None),
            (None, Some(after)),
            (Some(before), Some(after)),
        ] {
            for desc in [true, false] {
                let mut want: Vec<u64> = raw(&f)
                    .prepare(
                        "SELECT id FROM client WHERE last_query_timestamp <= ?1 \
                        AND last_query_timestamp >= ?2 ORDER BY id",
                    )
                    .unwrap()
                    .query_map(
                        [b.map_or(i64::MAX, |v| v as i64), a.map_or(0, |v| v as i64)],
                        |r| r.get(0),
                    )
                    .unwrap()
                    .map(|r| r.unwrap())
                    .collect();
                if desc {
                    want.reverse();
                }
                let ctx = format!("{:?} {:?} desc={}", b, a, desc);
                let mut p = ClientListGetParam::new();
                p.timestamp_before = b;
                p.timestamp_after = a;
                p.order = Some(if desc { "desc" } else { "asc" }.to_string());
                p.page_size = 7;
                let page = |p: &ClientListGetParam| -> Vec<u64> {
                    f.db.get_client_list(Some(p))
                        .unwrap()
                        .client_list
                        .iter()
                        .map(|c| c.id as u64)
                        .collect()
                };
                let first = page(&p);
                let mut seen = first.clone();
                let mut q = p.clone();
                while let Some(&last) = seen.last() {
                    q.cursor = Some(ClientListGetParamCursor {
                        id: Some(last),
                        total_count: want.len() as u64,
                        direction: "next".to_string(),
                    });
                    let next = page(&q);
                    if next.is_empty() {
                        break;
                    }
                    seen.extend(next);
                }
                assert_eq!(seen, want, "{}", ctx);
                q.cursor = Some(ClientListGetParamCursor {
                    id: Some(want[7]),
                    total_count: want.len() as u64,
                    direction: "prev".to_string(),
                });
                assert_eq!(page(&q), first, "{}", ctx);
            }
        }
    }

    #[test]
    fn suffix_and_prefix_filters_match_their_names() {
        let f = ready_fixture(200);
        for (mode, value, keep) in [
            ("endswith", "example.com", "a.example.com"),
            ("startswith", "cdn.", "cdn.example.net"),
        ] {
            let mut p = DomainListGetParam::new();
            p.domain = Some(value.to_string());
            p.domain_filter_mode = Some(mode.to_string());
            p.page_size = 1000;
            let got = f.db.get_domain_list(Some(&p)).unwrap();
            let want = f.rows.iter().filter(|r| r.2 == keep).count();
            assert_eq!(got.domain_list.len(), want, "{}", mode);
            assert!(got.domain_list.iter().all(|d| d.domain == keep), "{}", mode);
        }
    }

    #[test]
    fn missing_cursor_row_falls_back_to_id_paging() {
        let f = ready_fixture(200);
        let victim = f.rows[100].0;
        raw(&f)
            .execute("DELETE FROM domain WHERE id = ?", [victim])
            .unwrap();
        let mut p = DomainListGetParam::new();
        p.domain = Some("example".to_string());
        p.domain_filter_mode = Some("contains".to_string());
        p.page_size = 5;
        p.cursor = Some(DomainListGetParamCursor {
            id: Some(victim),
            total_count: 0,
            direction: "next".to_string(),
        });
        let page = ids(&f.db.get_domain_list(Some(&p)).unwrap());
        assert_eq!(page.len(), 5);
        assert!(page.windows(2).all(|w| w[0] > w[1]) && page.iter().all(|id| *id < victim));
    }

    #[test]
    fn not_ready_reads_use_the_original_sql() {
        let f = legacy_fixture(100);
        let mut p = DomainListGetParam::new();
        p.domain = Some("a.example.com".to_string());
        let conn = raw(&f);
        assert!(f.db.time_ordered_query(&conn, &p).is_none());
        // Results come from the original id-ordered SQL.
        p.page_size = 1000;
        let mut want: Vec<u64> = f
            .rows
            .iter()
            .filter(|r| r.2 == "a.example.com")
            .map(|r| r.0)
            .collect();
        want.sort();
        want.reverse();
        assert_eq!(ids(&f.db.get_domain_list(Some(&p)).unwrap()), want);
    }

    #[test]
    fn invalid_parameters_still_fail_once_ready() {
        let f = ready_fixture(20);
        let mut p = DomainListGetParam::new();
        p.order = Some("sideways".to_string());
        assert!(f.db.get_domain_list(Some(&p)).is_err());
        let mut p = DomainListGetParam::new();
        p.cursor = Some(DomainListGetParamCursor {
            id: Some(f.rows[0].0),
            total_count: 1,
            direction: "up".to_string(),
        });
        assert!(f.db.get_domain_list(Some(&p)).is_err());
        let mut p = DomainListGetParam::new();
        p.domain = Some("example".to_string());
        p.domain_filter_mode = Some("fuzzy".to_string());
        assert!(f.db.get_domain_list(Some(&p)).is_err());
    }

    #[test]
    fn new_database_is_ready_without_a_build() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.db");
        let db = DB::new();
        db.open(path.to_str().unwrap()).unwrap();
        let conn = Connection::open(&path).unwrap();
        assert!(DB::query_index_exists(&conn).unwrap());
        db.prepare_query_index().unwrap();
        assert!(db.query_index_ready());
    }

    #[test]
    fn id_ordered_counts_may_seek_the_index() {
        let f = ready_fixture(50);
        let mut p = DomainListGetParam::new();
        p.domain = Some("a.example.com".to_string());
        p.is_blocked = Some(true);
        let (list_where, _, _) = DB::domain_sql_where(Some(&p), false).unwrap();
        let (count_where, _, params) = DB::domain_sql_where(Some(&p), true).unwrap();
        assert!(list_where.contains("+domain = ?"));
        assert!(count_where.contains(" domain = ?") && !count_where.contains("+domain"));
        let conn = raw(&f);
        let counted = plan(
            &conn,
            &format!("SELECT COUNT(*) FROM domain{}", count_where),
            &params,
        );
        assert!(counted.contains(QUERY_INDEX_NAME), "{}", counted);
        let want = f
            .rows
            .iter()
            .filter(|r| r.2 == "a.example.com")
            .filter(|r| {
                conn.query_row("SELECT is_blocked FROM domain WHERE id = ?", [r.0], |x| {
                    x.get::<_, i64>(0)
                })
                .unwrap()
                    == 1
            })
            .count() as u64;
        assert_eq!(f.db.get_domain_list_count(Some(&p)), want);

        p.is_blocked = None;
        p.client = Some("10.0.0.1".to_string());
        let (with_client, _, params) = DB::domain_sql_where(Some(&p), true).unwrap();
        assert!(with_client.contains("+domain = ?"), "{}", with_client);
        let counted = plan(
            &conn,
            &format!("SELECT COUNT(*) FROM domain{}", with_client),
            &params,
        );
        assert!(counted.contains("idx_domain_client"), "{}", counted);
    }

    fn plan(conn: &Connection, sql: &str, params: &[String]) -> String {
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {}", sql))
            .unwrap();
        stmt.query_map(rusqlite::params_from_iter(params), |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect::<Vec<_>>()
        .join(" | ")
    }

    #[test]
    fn plans_use_the_query_index_only_where_intended() {
        let f = ready_fixture(50);
        let conn = raw(&f);

        let mut p = DomainListGetParam::new();
        p.domain = Some("a.example.com".to_string());
        let q = f.db.time_ordered_query(&conn, &p).unwrap();
        let exact = plan(
            &conn,
            &format!(
                "SELECT id FROM domain{}{} LIMIT 20",
                q.sql_where, q.sql_order
            ),
            &q.sql_param,
        );
        assert!(
            exact.contains(QUERY_INDEX_NAME) && !exact.contains("TEMP B-TREE"),
            "{}",
            exact
        );

        let top = plan(&conn, TOP_DOMAIN_SQL, &["0".to_string()]);
        assert!(
            top.contains(&format!("COVERING INDEX {}", QUERY_INDEX_NAME)),
            "{}",
            top
        );

        p.is_blocked = Some(true);
        let (w, o, params) = DB::get_domain_sql_where(Some(&p)).unwrap();
        let combined = plan(
            &conn,
            &format!("SELECT id FROM domain{}{} LIMIT 20", w, o),
            &params,
        );
        assert!(!combined.contains(QUERY_INDEX_NAME), "{}", combined);

        let first = plan(
            &conn,
            "SELECT id FROM domain ORDER BY timestamp DESC, id DESC LIMIT 20",
            &[],
        );
        assert!(first.contains("idx_domain_timestamp"), "{}", first);
    }
}
