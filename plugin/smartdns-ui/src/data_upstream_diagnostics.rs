//! Outcome dimensions are separate: each breakdown closes to its own total;
//! observed error events are not exclusive causes and never a denominator.
use crate::smartdns::smartdns_c;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::CString};

const ENDS: &[&str] = &["other_result", "deadline", "budget_or_cancel", "shutdown", "other", "unaccepted_result"];
const WAITS: &[&str] = &["unrecorded", "rate_limit", "cooldown", "recovery_probe", "no_backend",
    "send_turn", "inflight_limit", "connect_or_write", "scheduler_delay"];
const EVENTS: &[&str] = &["http_429", "http_503", "http_other", "dns_rcode", "dns_callback_rejected",
    "attempt_timeout", "io_or_protocol_error"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamDiagnostics {
    pub version: u32,
    pub qps: u32,
    pub burst: u32,
    pub cooldown_ms: u32,
    pub failure_end: BTreeMap<String, u64>,
    pub skip_end: BTreeMap<String, u64>,
    pub skip_wait: BTreeMap<String, u64>,
    pub failure_last_event: BTreeMap<String, u64>,
    pub events: BTreeMap<String, u64>,
    pub client_loop: serde_json::Value,
}

fn named(names: &[&str], values: &[u64]) -> Result<BTreeMap<String, u64>, String> {
    if names.len() != values.len() { return Err("incompatible diagnostic dimensions".into()); }
    Ok(names.iter().zip(values).map(|(k, v)| (k.to_string(), *v)).collect())
}
fn closes(values: &[u64], expected: u64) -> bool {
    values.iter().try_fold(0u64, |sum, value| sum.checked_add(*value)) == Some(expected)
}

impl UpstreamDiagnostics {
    pub fn from_snapshot(base: &smartdns_c::dns_upstream_service_snapshot_v1,
        raw: &smartdns_c::dns_upstream_service_diagnostics_v1) -> Result<Self, String> {
        if raw.version != 1 || raw.struct_size as usize != std::mem::size_of_val(raw)
            || raw.cooldown_ms == 0 || raw.cooldown_ms > 10000
            || !closes(&[base.success_count, base.failure_count, base.skip_count, base.in_flight], base.query_count)
            || !closes(&raw.failure_end, base.failure_count)
            || !closes(&raw.failure_last_event, base.failure_count)
            || !closes(&raw.skip_end, base.skip_count) || !closes(&raw.skip_wait, base.skip_count) {
            return Err("incompatible or inconsistent service diagnostics".into());
        }
        let last: Vec<_> = std::iter::once("none").chain(EVENTS.iter().copied()).collect();
        Ok(Self {
            version: 1, qps: raw.qps, burst: raw.burst, cooldown_ms: raw.cooldown_ms,
            failure_end: named(ENDS, &raw.failure_end)?, skip_end: named(ENDS, &raw.skip_end)?,
            skip_wait: named(WAITS, &raw.skip_wait)?, failure_last_event: named(&last, &raw.failure_last_event)?,
            events: named(EVENTS, &raw.events)?, client_loop: serde_json::Value::Null,
        })
    }

    pub fn fetch(id: &str) -> Result<(smartdns_c::dns_upstream_service_snapshot_v1, Self), String> {
        if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("invalid service identifier".into()); }
        let id = CString::new(id).map_err(|_| "invalid service identifier")?;
        let mut base = unsafe { std::mem::zeroed() };
        let mut raw = unsafe { std::mem::zeroed() };
        if unsafe { smartdns_c::dns_client_get_service_diagnostics_v1(id.as_ptr(), &mut base, &mut raw) } != 0 {
            return Err("service diagnostic snapshot unavailable".into());
        }
        let mut value = Self::from_snapshot(&base, &raw)?;
        let mut loop_raw: smartdns_c::dns_client_loop_diagnostics_v1 = unsafe { std::mem::zeroed() };
        if unsafe { smartdns_c::dns_client_get_loop_diagnostics_v1(&mut loop_raw) } == 0
            && loop_raw.version == 1 && loop_raw.struct_size as usize == std::mem::size_of_val(&loop_raw) {
            let percent = if loop_raw.cpu_clock_available != 0 && loop_raw.sample_wall_ms != 0 {
                Some(loop_raw.sample_cpu_ns as f64 / (loop_raw.sample_wall_ms as f64 * 10000.0))
            } else { None };
            value.client_loop = serde_json::json!({
                "thread_id": loop_raw.thread_id, "cpu_percent": percent, "cpu_total_ns": loop_raw.cpu_total_ns,
                "sample_wall_ms": loop_raw.sample_wall_ms, "sample_tick_ms": loop_raw.sample_tick_ms,
                "sample_age_ms": loop_raw.sample_age_ms,
                "iterations": loop_raw.iterations, "zero_waits": loop_raw.zero_waits,
                "zero_wait_no_events": loop_raw.zero_wait_no_events, "ready_events": loop_raw.ready_events,
                "wakeups": loop_raw.wakeups, "periodic_runs": loop_raw.periodic_runs,
            });
        }
        Ok((base, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_dimensions_close_without_hiding_skips_or_error_events() {
        let mut base: smartdns_c::dns_upstream_service_snapshot_v1 = unsafe { std::mem::zeroed() };
        let mut raw: smartdns_c::dns_upstream_service_diagnostics_v1 = unsafe { std::mem::zeroed() };
        raw.version = 1; raw.struct_size = std::mem::size_of_val(&raw) as u32; raw.cooldown_ms = 1000;
        base.query_count = 10; base.success_count = 5; base.failure_count = 2; base.skip_count = 3;
        raw.failure_end[0] = 1; raw.failure_end[1] = 1; raw.failure_last_event[0] = 1; raw.failure_last_event[1] = 1;
        raw.skip_end[0] = 3; raw.skip_wait[2] = 3; raw.events[0] = 7;
        let d = UpstreamDiagnostics::from_snapshot(&base, &raw).unwrap();
        assert_eq!(d.failure_end["other_result"], 1); assert_eq!(d.skip_wait["cooldown"], 3);
        assert_eq!(d.events["http_429"], 7);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<UpstreamDiagnostics>(&json).unwrap(), d);
        raw.skip_wait[2] = 2;
        assert!(UpstreamDiagnostics::from_snapshot(&base, &raw).is_err());
        raw.skip_wait[2] = 3; raw.cooldown_ms = 10001;
        assert!(UpstreamDiagnostics::from_snapshot(&base, &raw).is_err());
    }
}
