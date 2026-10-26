//! Provider-level queue, per-exit pacing, and bounded refresh-room observations.
use crate::smartdns::smartdns_c as ffi;
use serde_json::{Value, json};
use std::ffi::{CStr, c_char};

fn text(raw: &[c_char]) -> String {
    let bytes: Vec<u8> = raw.iter().take_while(|v| **v != 0).map(|v| *v as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
pub(crate) fn snapshot(raw: &ffi::dns_upstream_runtime_v1) -> Option<Value> {
    if raw.version != 1 || raw.struct_size as usize != std::mem::size_of_val(raw)
        || raw.wan_count == 0 || raw.wan_count as usize > raw.wans.len() || raw.qps_mode > 2 { return None; }
    let wans: Vec<_> = raw.wans[..raw.wan_count as usize].iter().map(|w| json!({
        "interface":text(&w.interface),"interface_index":w.interface_index,"generation":w.generation,
        "family_mask":w.family_mask,"connected":w.connected != 0,"connected_family":w.connected_family,
        "ip":text(&w.ip),"source":text(&w.source),
        "current_rate":if w.rate_known != 0 {Some(w.current_rate)} else {None},
        "known_good_rate":if w.known_good_rate > 0 {Some(w.known_good_rate)} else {None},
        "probe_ceiling":if w.rate_known != 0 {Some(w.probe_ceiling)} else {None},
        "cooldown_remaining_ms":w.cooldown_remaining_ms,"retry_remaining_ms":w.retry_remaining_ms,
        "quota_group_http_429":w.http_429,
        "last_backpressure_ms":if w.last_backpressure_unix_ms > 0 {Some(w.last_backpressure_unix_ms)} else {None}
    })).collect();
    let qps_mode = ["off", "fixed_service", "adaptive_per_exit"][raw.qps_mode as usize];
    Some(json!({"version":1,"qps_mode":qps_mode,
        "configured_cap":raw.configured_cap,"foreground_waiting":raw.foreground_waiting,
        "refresh_waiting":raw.refresh_waiting,"prefetch_waiting":raw.prefetch_waiting,"wans":wans}))
}
pub(crate) fn fetch(id: &CStr) -> Option<Value> {
    let mut raw = unsafe { std::mem::zeroed() };
    if unsafe { ffi::dns_client_get_service_runtime_v1(id.as_ptr(), &mut raw) } != 0 { return None; }
    let mut value = snapshot(&raw)?;
    let mut queue: ffi::dns_refresh_queue_snapshot_v1 = unsafe { std::mem::zeroed() };
    if unsafe { ffi::dns_server_get_refresh_queue_v1(&mut queue) } == 0 && queue.version == 1
        && queue.struct_size as usize == std::mem::size_of_val(&queue) && queue.queued <= 512 && queue.active <= 64 {
        let sum = [queue.queued as u64, queue.active as u64, queue.completed, queue.dropped, queue.skipped_fresh]
            .into_iter().try_fold(0u64, |total, n| total.checked_add(n));
        if sum == Some(queue.enqueued) { value["refresh_queue"] = json!({
            "scope":"process","queued":queue.queued,"active":queue.active,"peak":queue.peak,
            "enqueued":queue.enqueued,"merged":queue.merged,"admitted":queue.dispatched,
            "rejected":queue.rejected,"dropped":queue.dropped,"completed":queue.completed,
            "skipped_fresh":queue.skipped_fresh,"dispatch_errors":queue.dispatch_errors,
            "oldest_wait_ms":queue.oldest_wait_ms,"metadata_bytes":queue.metadata_bytes
        }); }
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_rate_is_not_a_verified_limit() {
        let mut raw: ffi::dns_upstream_runtime_v1 = unsafe { std::mem::zeroed() };
        raw.struct_size = std::mem::size_of_val(&raw) as u32; raw.version = 1; raw.wan_count = 1;
        raw.qps_mode = 2; raw.configured_cap = 40;
        let unknown = snapshot(&raw).unwrap(); assert!(unknown["wans"][0]["current_rate"].is_null());
        raw.wans[0].rate_known = 1; raw.wans[0].current_rate = 20;
        let observed = snapshot(&raw).unwrap(); assert_eq!(observed["wans"][0]["current_rate"], 20);
        assert!(observed["wans"][0]["known_good_rate"].is_null());
        raw.wan_count = 17; assert!(snapshot(&raw).is_none());
    }
}
