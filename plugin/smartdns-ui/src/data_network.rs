//! A portable interface inventory, independent of a router vendor or WAN daemon.
use crate::smartdns::smartdns_c as ffi;
use serde::Serialize;
use std::{error::Error, ffi::c_char};

#[derive(Debug, Serialize)]
pub(crate) struct NetworkInterface {
    name: String, index: u32, up: bool, running: bool, loopback: bool, point_to_point: bool,
    ipv4_count: u32, ipv6_count: u32, address4: String, address6: String,
    kind: String, master_index: u32, default_route4: bool, default_route6: bool,
    link_inventory_complete: bool, route_inventory_complete: bool,
    role: &'static str, recommended: bool,
}

pub(crate) fn interfaces() -> Result<Vec<NetworkInterface>, Box<dyn Error>> {
    let mut raw: Vec<ffi::dns_network_interface_v1> = (0..ffi::DNS_NETWORK_INTERFACES_MAX)
        .map(|_| unsafe { std::mem::zeroed() }).collect();
    let count = unsafe { ffi::dns_client_get_network_interfaces_v1(raw.as_mut_ptr(), raw.len() as u32) };
    if count < 0 || count as usize > raw.len() { return Err("network interface snapshot unavailable".into()); }
    let text = |s: &[c_char]| {
        String::from_utf8_lossy(&s.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect::<Vec<_>>()).into_owned()
    };
    raw[..count as usize].iter().map(|item| {
        if item.version != 1 || item.struct_size as usize != std::mem::size_of_val(item) || item.index == 0 {
            return Err("incompatible network interface snapshot".into());
        }
        let role = ["other", "default_exit", "ppp", "name_hint", "internal", "tunnel"]
            .get(item.role as usize).copied().ok_or("invalid interface recommendation")?;
        Ok(NetworkInterface { name: text(&item.name), index:item.index, up:item.up != 0,
            running:item.running != 0, loopback:item.loopback != 0, point_to_point:item.point_to_point != 0,
            ipv4_count:item.ipv4_count, ipv6_count:item.ipv6_count,
            address4:text(&item.address4), address6:text(&item.address6),
            kind:text(&item.kind), master_index:item.master_index,
            default_route4:item.default_route4 != 0, default_route6:item.default_route6 != 0,
            link_inventory_complete:item.link_inventory_complete != 0, route_inventory_complete:item.route_inventory_complete != 0,
            role, recommended:item.recommended != 0 })
    }).collect()
}
