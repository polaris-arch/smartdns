//! Bounded failure evidence has independent retention from the general event ring.
use crate::smartdns::smartdns_c as ffi;
use serde_json::{json, Value};
use std::ffi::{c_char, CStr};

fn text(raw: &[c_char]) -> String {
    let bytes: Vec<u8> = raw.iter().take_while(|v| **v != 0).map(|v| *v as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn event(raw: &ffi::dns_upstream_failure_event_v1) -> Value {
    let e = &raw.event;
    let c = &raw.context;
    let p = &raw.progress;
    let elapsed = |end: u64, start: u64| if start > 0 && end >= start { Some(end - start) } else { None };
    json!({
        "sequence": e.sequence, "timestamp_ms": if c.unix_ms > 0 { Some(c.unix_ms) } else { None },
        "age_ms": e.age_ms, "query_id": e.query_id, "domain": text(&c.domain), "qtype": c.qtype,
        "origin_flags":raw.origin_flags,"queue_wait_ms":raw.queue_wait_ms,
        "interface":text(&raw.interface),"wan_generation":raw.wan_generation,
        "quic_close":if raw.quic_close_valid != 0 {Some(json!({
            "code":format!("0x{:x}",raw.quic_close_code),"frame":format!("0x{:x}",raw.quic_close_frame),
            "local":raw.quic_close_local != 0,"transport":raw.quic_close_transport != 0
        }))} else {None},
        "ip": text(&e.ip), "family": e.family, "port": e.port,
        "kind": e.kind, "phase": e.phase, "code": e.code, "system_error": e.system_error,
        "elapsed_ms": e.elapsed_ms, "limit_ms": e.limit_ms, "message": text(&e.message),
        "tls_error": e.tls_error, "connection_generation": raw.connection_generation,
        "active_attempts": if e.kind != 2 || raw.tls_operation != 0 {Some(raw.active_attempts)} else {None},
        "tls_operation": raw.tls_operation,
        "tls_errors": raw.tls_errors[..(raw.tls_error_count as usize).min(raw.tls_errors.len())].to_vec(),
        "tls_error_overflow": raw.tls_error_overflow, "timeout_stage": raw.timeout_stage,
        "dns_response": if c.dns_summary_valid != 0 { Some(json!({
            "rcode":c.rcode,"truncated":c.truncated != 0,"answers":c.answers,"authority":c.authority,
            "additional":c.additional,"a":c.a_records,"aaaa":c.aaaa_records,
            "cname":c.cname_records,"soa":c.soa_records
        })) } else { None },
        "progress": {"generation":p.generation,"wire_started":p.wire_started != 0,
            "request_complete":p.request_complete != 0,"headers_received":p.headers_received != 0,
            "http_status":p.http_status,"admission_to_send_ms":elapsed(p.first_sent_tick,p.admitted_tick),
            "send_duration_ms":elapsed(p.complete_tick,p.first_sent_tick),
            "headers_wait_ms":elapsed(p.headers_tick,p.complete_tick),
            "since_last_send_ms":elapsed(e.tick_ms,p.last_sent_tick)}
    })
}

pub(crate) fn snapshot(raw: &ffi::dns_upstream_failure_snapshot_v1) -> Option<Value> {
    if raw.version != 1 || raw.struct_size as usize != std::mem::size_of_val(raw)
        || raw.timeout_count as usize > raw.timeouts.len() || raw.io_count as usize > raw.io_errors.len() {
        return None;
    }
    const CODES: &[&str] = &["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
        "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI", "12", "13", "14", "15", "OTHER"];
    const STAGES: &[&str] = &["unknown", "not_sent", "sending", "wait_headers", "read_body", "wait_response"];
    let rcodes: Vec<_> = raw.rcode_counts.iter().enumerate().filter(|(_, n)| **n != 0).map(|(i, n)| {
        let last = &raw.last_rcode[i];
        json!({"code": i, "name": CODES[i], "count": n,
            "last_event": if last.event.sequence > 0 { Some(event(last)) } else { None }})
    }).collect();
    let stages: std::collections::BTreeMap<_, _> = STAGES.iter().zip(raw.timeout_stages).map(|(k, v)| (*k, v)).collect();
    Some(json!({"version":1,"retention":"process_lifetime","rcodes":rcodes,"timeout_stages":stages,
        "timeouts":raw.timeouts[..raw.timeout_count as usize].iter().map(event).collect::<Vec<_>>(),
        "io_errors":raw.io_errors[..raw.io_count as usize].iter().map(event).collect::<Vec<_>>()}))
}

pub(crate) fn fetch(id: &CStr) -> Option<Value> {
    let mut raw = unsafe { std::mem::zeroed() };
    if unsafe { ffi::dns_client_get_service_failures_v1(id.as_ptr(), &mut raw) } != 0 { return None; }
    snapshot(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quic_codes_are_lossless_and_missing_error_activity_stays_unknown() {
        let mut raw: ffi::dns_upstream_failure_event_v1 = unsafe { std::mem::zeroed() };
        raw.event.kind = 2; raw.quic_close_valid = 1; raw.quic_close_code = 1u64 << 63;
        let value = event(&raw);
        assert_eq!(value["quic_close"]["code"], "0x8000000000000000");
        assert!(value["active_attempts"].is_null());
        raw.tls_operation = 4; raw.active_attempts = 2;
        assert_eq!(event(&raw)["active_attempts"], 2);
    }
    #[test]
    fn rcode_evidence_survives_other_events_and_missing_progress_stays_unknown() {
        let mut raw: ffi::dns_upstream_failure_snapshot_v1 = unsafe { std::mem::zeroed() };
        raw.version = 1; raw.struct_size = std::mem::size_of_val(&raw) as u32;
        raw.rcode_counts[2] = 80; raw.last_rcode[2].event.sequence = 4;
        raw.last_rcode[2].event.code = 2; raw.last_rcode[2].context.unix_ms = 123456789;
        let value = snapshot(&raw).unwrap();
        assert_eq!(value["rcodes"][0]["name"], "SERVFAIL");
        assert_eq!(value["rcodes"][0]["count"], 80);
        assert_eq!(value["rcodes"][0]["last_event"]["timestamp_ms"], 123456789u64);
        assert!(value["rcodes"][0]["last_event"]["progress"]["headers_wait_ms"].is_null());
        raw.timeout_count = 9; assert!(snapshot(&raw).is_none());
    }
}
