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

use crate::{smartdns, DnsServerType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LatencySamples {
    pub sum_ms: u64,
    pub samples: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttemptRttSamples {
    pub sum_ms: u64,
    pub samples: u64,
    pub ambiguous_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceConfigIdentity {
    pub authority: String,
    pub transport: String,
    pub port: u16,
    pub path: String,
    pub groups: Vec<String>,
    // Opaque semantic identity only; never expose credentials, pins or raw flags.
    pub identity_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamServiceDetails {
    pub service_id: String,
    pub stats_semantics: String,
    pub pool_enabled: bool,
    pub config_identity: ServiceConfigIdentity,
    pub service_status: String,
    pub endpoint_ips: Vec<String>,
    pub endpoint_count: u32,
    pub backend_cap: u32,
    pub connection_cap: u32,
    pub connection_count: u32,
    pub draining_count: u32,
    pub discovered_count: u32,
    pub rejected_count: u32,
    pub overflow_count: u32,
    pub stale: bool,
    pub query_count: u64,
    pub attempt_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub skip_count: u64,
    pub in_flight: u64,
    pub response_latency: LatencySamples,
    pub attempt_rtt: AttemptRttSamples,
    pub cooldown_remaining_ms: u64,
    pub freshness_remaining_ms: Option<u64>,
    pub freshness_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<crate::data_upstream_diagnostics::UpstreamDiagnostics>,
}

#[derive(Debug, Clone)]
pub struct UpstreamServerInfo {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub server_type: DnsServerType,
    pub total_query_count: u64,
    pub total_query_success: u64,
    pub total_query_recv_count: u64,
    pub query_success_rate: f64,
    pub avg_time: f64,
    pub status: String,
    pub security: String,
    pub service: Option<UpstreamServiceDetails>,
}

fn service_status(status: u32) -> &'static str {
    match status {
        1 => "ready", 2 => "degraded", 3 => "cooldown", 4 => "discovering",
        5 => "unavailable", 6 => "stale", _ => "unknown",
    }
}

impl UpstreamServerInfo {
    pub fn from_snapshot(row: &smartdns::smartdns_c::dns_upstream_service_snapshot_v1) -> Result<Self, String> {
        if row.port > u16::MAX as u32 { return Err("invalid service snapshot port".into()); }
        if row.endpoint_count as usize > row.selected_ips.len() || row.group_count as usize > row.groups.len() {
            return Err("invalid service snapshot cardinality".into());
        }
        let host = smartdns::snapshot_string(&row.authority)?;
        let service_id = smartdns::snapshot_string(&row.service_id)?;
        let server_type = DnsServerType::from(row.transport);
        let endpoint_ips: Vec<String> = row.selected_ips[..row.endpoint_count as usize]
            .iter().map(smartdns::snapshot_string).collect::<Result<_, _>>()?;
        let groups: Vec<String> = row.groups[..row.group_count as usize]
            .iter().map(smartdns::snapshot_string).collect::<Result<_, _>>()?;
        let pool = row.pool_enabled != 0;
        let avg_time = if pool {
            if row.response_latency_samples == 0 { 0.0 } else {
                row.response_latency_sum_ms as f64 / row.response_latency_samples as f64
            }
        } else { row.legacy_avg_time };
        let details = UpstreamServiceDetails {
            service_id: service_id.clone(), diagnostics: None,
            stats_semantics: if pool { "service-v1" } else { "legacy-endpoint-v1" }.into(),
            pool_enabled: pool,
            config_identity: ServiceConfigIdentity {
                authority: host.clone(), transport: server_type.to_string(), port: row.port as u16,
                path: smartdns::snapshot_string(&row.path)?, groups,
                identity_fingerprint: service_id,
            },
            service_status: service_status(row.status).into(),
            endpoint_ips: endpoint_ips.clone(), endpoint_count: row.endpoint_count,
            backend_cap: row.backend_cap, connection_cap: row.connection_cap,
            connection_count: row.connection_count, draining_count: row.draining_count,
            discovered_count: row.discovered_count, rejected_count: row.rejected_count,
            overflow_count: row.overflow_count, stale: row.stale != 0,
            query_count: row.query_count, attempt_count: row.attempt_count,
            success_count: row.success_count, failure_count: row.failure_count,
            skip_count: row.skip_count, in_flight: row.in_flight,
            response_latency: LatencySamples { sum_ms: row.response_latency_sum_ms, samples: row.response_latency_samples },
            attempt_rtt: AttemptRttSamples { sum_ms: row.attempt_rtt_sum_ms, samples: row.attempt_rtt_samples,
                ambiguous_count: row.attempt_rtt_ambiguous_count },
            cooldown_remaining_ms: row.cooldown_remaining_ms, freshness_remaining_ms: if row.freshness_kind == 1 { Some(row.freshness_remaining_ms) } else { None },
            freshness_status: match row.freshness_kind {
                0 => "unknown", 1 => "finite", 2 => "non_expiring", 3 => "not_applicable",
                _ => return Err("invalid freshness kind".into()),
            }.to_string(),
        };
        Ok(Self {
            host, ip: if endpoint_ips.len() == 1 { endpoint_ips[0].clone() } else { String::new() },
            port: row.port as u16, server_type,
            total_query_count: row.query_count, total_query_success: row.success_count,
            total_query_recv_count: row.recv_count,
            query_success_rate: if row.query_count == 0 { 0.0 } else { (row.success_count as f64 / row.query_count as f64 * 1000.0).round() / 10.0 },
            avg_time,
            status: if row.query_count == 0 { "Unknown" } else if row.status == 1 { "Normal" } else { "Abnormal" }.into(),
            security: smartdns::DnsServerTrustStatus::from(row.security).to_string(),
            service: Some(details),
        })
    }

    pub fn get_all() -> Result<Vec<UpstreamServerInfo>, Box<dyn std::error::Error>> {
        smartdns::DnsUpstreamServices::snapshots()?.iter().map(|row| -> Result<Self, Box<dyn std::error::Error>> {
            if row.pool_enabled == 0 { return Self::from_snapshot(row).map_err(|error| error.into()); }
            let id = smartdns::snapshot_string(&row.service_id)?;
            let (base, diagnostics) = crate::data_upstream_diagnostics::UpstreamDiagnostics::fetch(&id)?;
            let mut result = Self::from_snapshot(&base)?;
            result.service.as_mut().ok_or("missing service details")?.diagnostics = Some(diagnostics);
            Ok(result)
        }).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamBackendInfo {
    pub service_id: String,
    pub ip: String,
    pub port: u16,
    pub state: String,
    pub security: String,
    pub active_attempts: u32,
    pub attempt_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub retry_remaining_ms: u64,
}
impl UpstreamBackendInfo {
    pub fn get_all(id: &str) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        smartdns::DnsUpstreamServices::endpoints(id)?.iter().map(|row| {
            Ok(Self {
                service_id: smartdns::snapshot_string(&row.service_id)?,
                ip: smartdns::snapshot_string(&row.ip)?, port: row.port as u16,
                state: match row.state { 0 => "new", 1 => "connecting", 2 => "ready", 3 => "backoff", 4 => "draining", _ => "unknown" }.into(),
                security: smartdns::DnsServerTrustStatus::from(row.security).to_string(),
                active_attempts: row.active_attempts, attempt_count: row.attempt_count,
                success_count: row.success_count, failure_count: row.failure_count,
                retry_remaining_ms: row.retry_remaining_ms,
            })
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_api_msg::{api_msg_gen_upstream_server_list, api_msg_parse_upstream_server_list};
    use std::os::raw::c_char;

    fn text<const N: usize>(dest: &mut [c_char; N], value: &str) {
        assert!(value.len() < N);
        for (out, input) in dest.iter_mut().zip(value.bytes()) { *out = input as c_char; }
    }
    fn snapshot() -> smartdns::smartdns_c::dns_upstream_service_snapshot_v1 {
        let mut row: smartdns::smartdns_c::dns_upstream_service_snapshot_v1 = unsafe { std::mem::zeroed() };
        row.version = 1;
        row.struct_size = std::mem::size_of_val(&row) as u32;
        text(&mut row.service_id, &"a".repeat(64));
        text(&mut row.authority, "resolver.example");
        text(&mut row.path, "/dns-query");
        text(&mut row.groups[0], "default");
        row.group_count = 1;
        row.port = 443; row.transport = 3; row.pool_enabled = 1;
        row.backend_cap = 4; row.status = 1; row.security = 4;
        row
    }

    #[test]
    fn pool_snapshot_is_one_row_with_original_service_counts() {
        let mut raw = snapshot();
        raw.endpoint_count = 2;
        text(&mut raw.selected_ips[0], "192.0.2.1");
        text(&mut raw.selected_ips[1], "2001:db8::1");
        raw.query_count = 5; raw.attempt_count = 7; raw.success_count = 2;
        raw.failure_count = 1; raw.skip_count = 1; raw.in_flight = 1;
        raw.response_latency_sum_ms = 70; raw.response_latency_samples = 2;
        raw.attempt_rtt_sum_ms = 9; raw.attempt_rtt_samples = 1; raw.attempt_rtt_ambiguous_count = 1;
        let row = UpstreamServerInfo::from_snapshot(&raw).unwrap();
        assert_eq!(row.host, "resolver.example");
        assert_eq!(row.ip, "");
        assert_eq!(row.avg_time, 35.0);
        assert_eq!(row.query_success_rate, 40.0);
        let json = api_msg_gen_upstream_server_list(&vec![row]);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["upstream_server_list"].as_array().unwrap().len(), 1);
        let row = &value["upstream_server_list"][0];
        assert_eq!(row["query_count"], row["success_count"].as_u64().unwrap()
            + row["failure_count"].as_u64().unwrap() + row["skip_count"].as_u64().unwrap() + row["in_flight"].as_u64().unwrap());
        assert_eq!(row["stats_semantics"], "service-v1");
        assert_eq!(row["attempt_rtt"]["ambiguous_count"], 1);
        assert_eq!(row["config_identity"]["groups"][0], "default");
        assert!(row.get("spki").is_none());
        let parsed = api_msg_parse_upstream_server_list(&json).unwrap();
        assert_eq!(parsed[0].service.as_ref().unwrap().attempt_count, 7);
        // A refresh removing every backend does not delete or reset the row.
        raw.endpoint_count = 0; raw.status = 5;
        let empty = UpstreamServerInfo::from_snapshot(&raw).unwrap();
        assert_eq!(empty.total_query_count, 5);
        assert_eq!(empty.service.as_ref().unwrap().service_status, "unavailable");
    }

    #[test]
    fn freshness_json_is_explicit_and_never_an_infinity_integer() {
        for (kind, raw_ms, label, expected) in [
            (2, u64::MAX, "non_expiring", None),
            (2, u32::MAX as u64, "non_expiring", None),
            (0, u64::MAX, "unknown", None),
            (3, 0, "not_applicable", None),
            (1, 1234, "finite", Some(1234)),
            (1, 0, "finite", Some(0)),
            (1, u32::MAX as u64, "finite", Some(u32::MAX as u64)),
        ] {
            let mut raw = snapshot(); raw.freshness_kind = kind; raw.freshness_remaining_ms = raw_ms;
            let row = UpstreamServerInfo::from_snapshot(&raw).unwrap();
            let json = api_msg_gen_upstream_server_list(&vec![row]);
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            let row = &value["upstream_server_list"][0];
            assert_eq!(row["freshness_status"], label);
            assert_eq!(row["freshness_remaining_ms"].as_u64(), expected);
            if expected.is_none() { assert!(row["freshness_remaining_ms"].is_null()); }
        }
        let mut raw = snapshot(); raw.freshness_kind = 4;
        assert!(UpstreamServerInfo::from_snapshot(&raw).is_err());
    }

    #[test]
    fn ordinary_snapshot_keeps_old_mean_and_json_can_parse_old_rows() {
        let mut raw = snapshot();
        raw.pool_enabled = 0; raw.legacy_avg_time = 12.25; raw.endpoint_count = 1;
        text(&mut raw.selected_ips[0], "192.0.2.5");
        raw.query_count = 3; raw.success_count = 2;
        let row = UpstreamServerInfo::from_snapshot(&raw).unwrap();
        assert_eq!(row.ip, "192.0.2.5");
        assert_eq!(row.avg_time, 12.25);
        assert_eq!(row.query_success_rate, 66.7);
        let mut old = row.clone(); old.service = None;
        let json = api_msg_gen_upstream_server_list(&vec![old]);
        let parsed = api_msg_parse_upstream_server_list(&json).unwrap();
        assert!(parsed[0].service.is_none());
        assert_eq!(parsed[0].avg_time, 12.25);
    }

    #[test]
    fn snapshot_rejects_invalid_cardinality_and_unterminated_text() {
        let mut raw = snapshot(); raw.endpoint_count = 65;
        assert!(UpstreamServerInfo::from_snapshot(&raw).is_err());
        raw.endpoint_count = 0; raw.authority.fill(b'a' as c_char);
        assert!(UpstreamServerInfo::from_snapshot(&raw).is_err());
    }
}
