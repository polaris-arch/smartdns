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

mod common;

use common::TestDnsRequest;
use nix::libc::c_char;
use smartdns_ui::{http_api_msg, http_jwt::JwtClaims, smartdns::LogLevel};
use std::ffi::CString;

#[test]
fn test_rest_api_login() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let body = res.unwrap();
    println!("res: {}", body);

    let result = http_api_msg::api_msg_parse_auth_token(&body);
    assert!(result.is_ok());
    let token = result.unwrap();
    assert!(!token.token.is_empty());
    let calims = jsonwebtoken::dangerous::insecure_decode::<JwtClaims>(&token.token);
    println!("calims: {:?}", calims);
    assert_eq!(token.expires_in, "600");
    assert!(calims.is_ok());
    let calims = calims.unwrap();
    let calims = calims.claims;
    assert_eq!(calims.user, "admin");
}

#[test]
fn test_rest_api_logout() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    client.set_with_auth_header(false);
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 200);

    let ret = client.logout();
    assert!(ret.is_ok());

    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 401);
}

#[test]
fn test_rest_api_login_incorrect() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "wrongpassword");
    assert!(!res.is_ok());
    let body = res.err().unwrap().to_string();
    println!("res: {}", body);

    let result = http_api_msg::api_msg_parse_error(&body);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Incorrect username or password.");
}

#[test]
fn test_rest_api_change_password() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let password_msg =
        http_api_msg::api_msg_gen_auth_password_change("wrong_oldpassword", "newpassword");
    let c = client.put("/api/auth/password", password_msg.as_str());
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 403);

    let password_msg = http_api_msg::api_msg_gen_auth_password_change("password", "newpassword");
    let c = client.put("/api/auth/password", password_msg.as_str());
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 204);

    let res = client.login("admin", "password");
    assert!(!res.is_ok());
}

#[test]
fn test_rest_api_cache_count() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let count = http_api_msg::api_msg_parse_cache_number(&body);
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 0);
}

#[test]
fn test_rest_api_auth_refresh() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.post("/api/auth/refresh", "");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let token = http_api_msg::api_msg_parse_auth_token(&body);
    assert!(token.is_ok());
    let token = token.unwrap();
    assert!(!token.token.is_empty());
    assert_eq!(token.expires_in, "600");
    println!("token: {:?}", token);
}

#[test]
fn test_rest_api_auth_check() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let c = client.get("/api/auth/check");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 401);

    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.get("/api/auth/check");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 200);
}

#[test]
fn test_rest_api_no_permission() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let client = common::TestClient::new(&server.get_host());
    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 401);
    println!("body: {}", body);
    let error_msg = http_api_msg::api_msg_parse_error(&body);
    assert!(error_msg.is_ok());
    assert_eq!(error_msg.unwrap(), "Please login.");
}

#[test]
fn test_rest_api_404() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.post("/api/404", "");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 404);
    let error_msg = http_api_msg::api_msg_parse_error(&body);
    assert!(error_msg.is_ok());
    assert_eq!(error_msg.unwrap(), "API not found.");
}

#[test]
fn test_rest_api_log_stream() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let socket = client.websocket("/api/log/stream");
    assert!(socket.is_ok());
    let mut socket = socket.unwrap();

    _ = socket.send(tungstenite::Message::Text("aaaa".to_string()));
    _ = socket.close(None);
}

#[test]
fn test_rest_api_log_level() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.set_one_instance(true);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/log/level");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let log_level = http_api_msg::api_msg_parse_loglevel(&body);
    assert!(log_level.is_ok());
    assert_eq!(log_level.unwrap(), LogLevel::DEBUG);

    let level_msg = http_api_msg::api_msg_gen_loglevel(LogLevel::ERROR);
    let c = client.put("/api/log/level", level_msg.as_str());
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 204);
    println!("body: {}", body);

    assert_eq!(smartdns_ui::smartdns::dns_log_get_level(), LogLevel::ERROR);
}

#[test]
fn test_rest_api_get_domain() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/domain/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let count = http_api_msg::api_msg_parse_count(&body);
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 1024);

    let c = client.get("/api/domain?page_num=11&page_size=10&order=asc");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let result = http_api_msg::api_msg_parse_domain_list(&body);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 10);
    assert_eq!(result[0].id, 101);
    assert_eq!(result[0].domain, "100.com");
}

#[test]
fn test_rest_api_audit_log_stream() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let socket = client.websocket("/api/log/audit/stream");
    assert!(socket.is_ok());
    let mut socket = socket.unwrap();

    _ = socket.send(tungstenite::Message::Text("aaaa".to_string()));
    _ = socket.close(None);
}


#[test]
fn test_rest_api_get_by_id() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/domain/1000");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let result = http_api_msg::api_msg_parse_domain(&body);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, 1000);
    assert_eq!(result.domain, "999.com");
}

#[test]
fn test_rest_api_delete_domain_by_id() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.delete("/api/domain/1000");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 204);

    let c = client.get("/api/domain/1000");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 404);

    let c = client.get("/api/domain/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let count = http_api_msg::api_msg_parse_count(&body);
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 1023);
}

#[test]
fn test_rest_api_server_version() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let client = common::TestClient::new(&server.get_host());

    let c = client.get("/api/server/version");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let version = http_api_msg::api_msg_parse_version(&body);
    assert!(version.is_ok());
    let version = version.unwrap();
    assert_eq!(version.0, smartdns_ui::smartdns::smartdns_version());
    if env!("GIT_VERSION").is_empty() {
        assert_eq!(version.1, env!("CARGO_PKG_VERSION"));
        return;
    }
    let check_version = std::format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("GIT_VERSION"));
    assert_eq!(version.1, check_version);
}

#[test]
fn test_rest_api_https_server() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    server.set_https(true);
    assert!(server.start().is_ok());

    let client = common::TestClient::new(&server.get_host());

    let c = client.get("/api/server/version");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let version = http_api_msg::api_msg_parse_version(&body);
    assert!(version.is_ok());
    let version = version.unwrap();
    assert_eq!(version.0, smartdns_ui::smartdns::smartdns_version());
    if env!("GIT_VERSION").is_empty() {
        assert_eq!(version.1, env!("CARGO_PKG_VERSION"));
        return;
    }
    let check_version = std::format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("GIT_VERSION"));
    assert_eq!(version.1, check_version);
}

#[test]
fn test_rest_api_settings() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());

    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/config/settings");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let settings = http_api_msg::api_msg_parse_key_value(&body);
    assert!(settings.is_ok());

    let mut settings = std::collections::HashMap::new();
    settings.insert("key1".to_string(), "value1".to_string());
    settings.insert("key2".to_string(), "value2".to_string());
    let body = http_api_msg::api_msg_gen_key_value(&settings);
    let c = client.put("/api/config/settings", body.as_str());
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 204);

    let c = client.get("/api/config/settings");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let settings = http_api_msg::api_msg_parse_key_value(&body);
    assert!(settings.is_ok());
    let settings = settings.unwrap();
    assert_eq!(settings.len(), 7);
    assert_eq!(settings["key1"], "value1");
}

#[test]
fn test_rest_api_get_client() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::INFO);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.remote_addr = format!("client-{}", i);
        request.remote_mac = [1, 2, 3, 4, 5, i as u8];
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/client?page_size=4096");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_client_list(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.len(), 1024);
}

#[test]
fn test_rest_api_stats_top() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        if i < 512 {
            request.domain = format!("a.com");
            request.remote_addr = format!("192.168.1.1");
        } else if i < 512 + 256 + 128 {
            request.domain = format!("b.com");
            request.remote_addr = format!("192.168.1.2");
        } else {
            request.domain = format!("c.com");
            request.remote_addr = format!("192.168.1.3");
        }
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    server.get_data_server().get_stat().refresh();

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/stats/top/client");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_top_client_list(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].client_ip, "192.168.1.1");
    assert_eq!(list[0].count, 512);
    assert_eq!(list[2].client_ip, "192.168.1.3");
    assert_eq!(list[2].count, 128);

    let c = client.get("/api/stats/top/domain");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_top_domain_list(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].domain, "a.com");
    assert_eq!(list[0].count, 512);
    assert_eq!(list[2].domain, "c.com");
    assert_eq!(list[2].count, 128);
}

#[test]
fn test_rest_api_stats_overview() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let server_name;

    unsafe {
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .avg_time
            .avg_time = 22.0 as f32;
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .request
            .blocked_count = 10;
        smartdns_ui::smartdns::smartdns_c::dns_stats.request.total = 15;

        server_name = smartdns_ui::smartdns::smartdns_get_server_name();
    }

    let c = client.get("/api/stats/overview");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let overview = http_api_msg::api_msg_parse_stats_overview(&body);
    assert!(overview.is_ok());
    let overview = overview.unwrap();
    assert_eq!(overview.db_size > 0, true);
    assert_eq!(overview.server_name, server_name);
}

#[test]
fn test_rest_api_stats_metrics() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    unsafe {
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .avg_time
            .avg_time = 22.0 as f32;
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .request
            .blocked_count = 10;
        smartdns_ui::smartdns::smartdns_c::dns_stats.request.total = 15;
    }

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.remote_addr = format!("client-{}", i);
        request.is_blocked = i % 2 == 0;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let c = client.get("/api/stats/metrics");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let metrics = http_api_msg::api_msg_parse_metrics_data(&body);
    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.avg_query_time, 22.0 as f64);
    assert_eq!(metrics.cache_hit_rate, 0 as f64);
    assert_eq!(metrics.total_query_count, 1024);
    assert_eq!(metrics.block_query_count, 1024 / 2);
}

#[test]
fn test_rest_api_get_hourly_query_count() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.remote_addr = format!("client-{}", i);
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/stats/hourly-query-count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_hourly_query_count(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.hourly_query_count.len(), 1);
    assert_eq!(list.hourly_query_count[0].query_count, 1024);
}

#[test]
fn test_rest_api_server_status() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    unsafe {
        let server_type = smartdns_ui::smartdns::smartdns_c::dns_server_type_t_DNS_SERVER_UDP;
        let mut flags: smartdns_ui::smartdns::smartdns_c::client_dns_server_flags =
            std::mem::zeroed();
        let ip = CString::new("1.2.3.4").expect("CString::new failed");
        let port = 3353;
        smartdns_ui::smartdns::smartdns_c::dns_client_add_server(
            ip.as_ptr() as *const c_char,
            port,
            server_type,
            &mut flags,
        );
    }

    let c = client.get("/api/upstream-server");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let server_list = http_api_msg::api_msg_parse_upstream_server_list(&body);
    assert!(server_list.is_ok());
    let server_list = server_list.unwrap();
    assert!(server_list.len() > 0);
    let exists = server_list.iter().any(|server| server.ip == "1.2.3.4");
    assert!(exists);
}

#[test]
fn test_rest_api_cache_domains() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/cache/domains");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200, "Expected 200 OK, got {}", code);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json.get("domains").is_some(), "Response missing 'domains' field");
    let domains = json["domains"].as_array().unwrap();

    for domain in domains {
        assert!(domain.get("id").is_some());
        assert!(domain.get("domain").is_some());
        assert!(domain.get("qtype").is_some());
        assert!(domain.get("cached_time").is_some());
        assert!(domain.get("ttl_remaining").is_some());
    }
}

#[test]
fn test_rest_api_network_interfaces_requires_auth_and_has_no_wan_side_effect() {
    let mut server = common::TestServer::new();
    assert!(server.start().is_ok());
    let mut client = common::TestClient::new(&server.get_host());
    let (status, _) = client.get("/api/network/interfaces").unwrap();
    assert_eq!(status, 401);
    client.login("admin", "password").unwrap();
    let (status, body) = client.get("/api/network/interfaces").unwrap();
    assert_eq!(status, 200);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let rows = value["interface_list"].as_array().unwrap();
    assert!(rows.len() <= 256);
    let mut indices = std::collections::BTreeSet::new();
    for row in rows {
        assert!(indices.insert(row["index"].as_u64().unwrap()));
        assert!(row["name"].is_string()); assert!(row["up"].is_boolean());
        assert!(row["address4"].is_string()); assert!(row["address6"].is_string());
        assert!(row.get("selected").is_none()); // inventory never silently enables a NIC
        assert!(row.get("wan").is_none()); // interface flags cannot prove an Internet exit
    }
}

#[test]
fn test_rest_api_service_pool_configuration_and_backend_identity() {
    let mut server = common::TestServer::new();
    server.enable_mock_server();
    server.add_mock_server_conf("server-https",
        "https://resolver.example/dns-query -upstream-ip-pool -host-ip 127.0.0.1,127.0.0.2 -max-upstream-backends 4");
    server.add_mock_server_conf("server-https",
        "https://second.example/dns-query -upstream-ip-pool -host-ip 127.0.0.3,127.0.0.4");
    // Same transport and authority, but a distinct path/security identity must
    // stay a separate logical row with a distinct stable service ID.
    server.add_mock_server_conf("server-https",
        "https://resolver.example/alternate -upstream-ip-pool -host-ip 127.0.0.5,127.0.0.6");
    server.add_mock_server_conf("server", "127.0.0.9:5309");
    assert!(server.start().is_ok());
    let mut client = common::TestClient::new(&server.get_host());
    assert!(client.login("admin", "password").is_ok());
    // The fixture starts the real core on a thread; wait for its configuration
    // publication, not a timing-dependent fixed sleep.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let rows = loop {
        let (code, body) = client.get("/api/upstream-server").unwrap();
        assert_eq!(code, 200);
        let rows = http_api_msg::api_msg_parse_upstream_server_list(&body).unwrap();
        let pools: Vec<_> = rows.iter().filter(|row| row.service.as_ref().map(|v| v.pool_enabled).unwrap_or(false)).collect();
        let ready = pools.len()==3 && pools.iter().all(|row| {
            let service=row.service.as_ref().unwrap();
            service.freshness_status=="non_expiring" && service.endpoint_count==1 &&
                service.diagnostics.as_ref().map(|d| d.backends.len()==1).unwrap_or(false) && service.diagnostics.as_ref()
                .and_then(|d|d.policy.as_ref()).and_then(|p|p.get("paths")).and_then(serde_json::Value::as_array)
                .map(|paths|paths.len()==2).unwrap_or(false)
        });
        if ready {
            if let Ok(path) = std::env::var("SMARTDNS_SERVICE_API_EVIDENCE") {
                std::fs::write(path, &body).unwrap();
            }
            break rows;
        }
        assert!(std::time::Instant::now() < deadline, "core did not publish configured service");
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let pools: Vec<_> = rows.iter().filter(|row| row.service.as_ref().map(|v| v.pool_enabled).unwrap_or(false)).collect();
    assert_eq!(pools.len(), 3, "three configured services must not become six IP rows");
    for pool in &pools {
        let details = pool.service.as_ref().unwrap();
        assert_eq!(details.freshness_status, "non_expiring");
        assert_eq!(details.freshness_remaining_ms, None);
        let policy=details.diagnostics.as_ref().unwrap().policy.as_ref().unwrap();
        assert_eq!(policy["version"],1);assert_eq!(policy["response_timeout_ms"],5000);
        assert_eq!(policy["query_timeout_ms"],8000);assert_eq!(policy["paths"].as_array().unwrap().len(),2);
        assert!(policy["events"].as_array().unwrap().len()<=32);
    }
    let ids: std::collections::HashSet<_> = pools.iter()
        .map(|row| &row.service.as_ref().unwrap().service_id).collect();
    assert_eq!(ids.len(), 3, "same-protocol/same-authority rows need distinct keys");
    assert_eq!(rows.len(), 4);
    let ordinary = rows.iter().find(|row| row.ip == "127.0.0.9").unwrap();
    assert!(!ordinary.service.as_ref().unwrap().pool_enabled);
    assert_eq!(ordinary.service.as_ref().unwrap().freshness_status, "not_applicable");
    assert_eq!(ordinary.service.as_ref().unwrap().freshness_remaining_ms, None);
    assert_eq!(ordinary.service.as_ref().unwrap().stats_semantics, "endpoint-outcome-v1");
    assert_eq!(ordinary.port, 5309);
    let endpoint = ordinary.service.as_ref().unwrap();
    assert_eq!(endpoint.service_id.len(), 64);
    let diagnostics = endpoint.diagnostics.as_ref().expect("ordinary endpoints need real diagnostic data");
    assert_eq!(diagnostics.backends.len(), 1); assert_eq!(diagnostics.backends[0].ip, "127.0.0.9");
    assert!(endpoint.response_statistics.is_some());
    let (code, body) = client.get(&format!("/api/upstream-server/{}/backends", endpoint.service_id)).unwrap();
    assert_eq!(code, 200);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["backend_list"][0]["ip"], "127.0.0.9");
    assert!(body["backend_list"][0]["http_429"].is_u64());
    assert!(body["backend_list"][0]["sends_peak_100ms"].is_u64());
    let row = pools.iter().find(|row| row.host == "resolver.example"
        && row.service.as_ref().unwrap().config_identity.path == "/dns-query").unwrap();
    assert_eq!(row.host, "resolver.example");
    assert_eq!(row.ip, "127.0.0.1", "the logical row exposes its single healthy candidate");
    let details = row.service.as_ref().unwrap();
    assert_eq!(details.stats_semantics, "service-v1");
    assert_eq!(details.endpoint_count, 1);
    assert_eq!(details.endpoint_ips, vec!["127.0.0.1"]);
    assert_eq!(details.backend_cap, 2);
    assert_eq!(details.connection_cap, 1, "one WAN keeps one healthy IPv4 connection");
    let (code, body) = client.get(&format!("/api/upstream-server/{}/backends", details.service_id)).unwrap();
    assert_eq!(code, 200);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["backend_list"].as_array().unwrap().len(), 1);
    let (code, _) = client.get("/api/upstream-server/not-an-id/backends").unwrap();
    assert_eq!(code, 400);
    // The historical helper's set_with_auth_header argument actually sets
    // no_auth_header; use a genuinely fresh unauthenticated client instead.
    let anonymous = common::TestClient::new(&server.get_host());
    let (code, _) = anonymous.get(&format!("/api/upstream-server/{}/backends", details.service_id)).unwrap();
    assert_eq!(code, 401);
}

#[test]
fn test_rest_api_drop_counter_reports_accumulated_value() {
    let mut server = common::TestServer::new();
    assert!(server.start().is_ok());
    let stats = server.get_data_server().get_stat();
    stats.add_request_drop(2);
    stats.add_request_drop(3);
    let mut client = common::TestClient::new(&server.get_host());
    assert!(client.login("admin", "password").is_ok());
    let (code, body) = client.get("/api/stats/metrics").unwrap();
    assert_eq!(code, 200);
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["request_drop_count"], 5);
}
