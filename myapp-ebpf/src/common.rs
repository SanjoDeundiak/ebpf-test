use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::TcContext;

use aya_log_ebpf::info;

use core::mem;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;

use myapp_common::conversion::{convert_ockam_to_tcp, convert_tcp_to_ockam};
use myapp_common::{PortMapInfo, OCKAM_TCP_PORTAL_PROTOCOL};

#[map]
static INLET_PORT_MAP: HashMap<u16, PortMapInfo> = HashMap::pinned(1024, 0);

#[map]
static OUTLET_PORT_MAP: HashMap<u16, PortMapInfo> = HashMap::pinned(1024, 0);

#[inline(always)]
pub fn try_handle(ctx: TcContext, ingress: bool) -> Result<i32, i32> {
    let ethhdr = ptr_at::<EthHdr>(&ctx, 0).ok_or(TC_ACT_PIPE)?;

    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    // TODO: Account for IPv4 options
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(TC_ACT_PIPE)?;
    let ipv4hdr_stack = unsafe { *ipv4hdr };

    if ingress && ipv4hdr_stack.proto == IpProto::Tcp {
        return handle_tcp(&ctx, ipv4hdr);
    }

    if !ingress && ipv4hdr_stack.proto as u8 == OCKAM_TCP_PORTAL_PROTOCOL {
        return handle_ockam_tcp_portal_protocol(&ctx, ipv4hdr);
    }

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn handle_tcp(ctx: &TcContext, ipv4hdr: *mut Ipv4Hdr) -> Result<i32, i32> {
    let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(TC_ACT_PIPE)?;
    let tcphdr_clone = unsafe { *tcphdr };

    let src_port = u16::from_be(tcphdr_clone.source);
    let dst_port = u16::from_be(tcphdr_clone.dest);

    let syn = tcphdr_clone.syn();
    let ack = tcphdr_clone.ack();
    let fin = tcphdr_clone.fin();

    let src_ip = unsafe { (*ipv4hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr() };

    info!(
        ctx,
        "TCP PACKET SRC: {}.{}.{}.{}:{}, DST: {}.{}.{}.{}:{}. SYN {} ACK {} FIN {}",
        src_ip.octets()[0],
        src_ip.octets()[1],
        src_ip.octets()[2],
        src_ip.octets()[3],
        src_port,
        dst_ip.octets()[0],
        dst_ip.octets()[1],
        dst_ip.octets()[2],
        dst_ip.octets()[3],
        dst_port,
        syn,
        ack,
        fin,
    );

    // Inlet logic
    if let Some(_port_info) = unsafe { INLET_PORT_MAP.get(&dst_port) } {
        info!(ctx, "INLET: Converting TCP packet to OCKAM");
        convert_tcp_to_ockam(ipv4hdr);
        return Ok(TC_ACT_PIPE);
    }

    // Outlet
    if let Some(_port_info) = unsafe { OUTLET_PORT_MAP.get(&src_port) } {
        info!(ctx, "OUTLET: Converting TCP packet to OCKAM");
        convert_tcp_to_ockam(ipv4hdr);
        return Ok(TC_ACT_PIPE);
    }

    info!(ctx, "Skipping TCP packet");

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn handle_ockam_tcp_portal_protocol(ctx: &TcContext, ipv4hdr: *mut Ipv4Hdr) -> Result<i32, i32> {
    let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(TC_ACT_PIPE)?;
    let tcphdr_clone = unsafe { *tcphdr };

    let src_port = u16::from_be(tcphdr_clone.source);
    let dst_port = u16::from_be(tcphdr_clone.dest);

    let syn = tcphdr_clone.syn();
    let ack = tcphdr_clone.ack();
    let fin = tcphdr_clone.fin();

    let src_ip = unsafe { (*ipv4hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr() };

    info!(
        ctx,
        "OCKAM TCP PORTAL PACKET SRC: {}.{}.{}.{}:{}, DST: {}.{}.{}.{}:{}. SYN {} ACK {} FIN {}",
        src_ip.octets()[0],
        src_ip.octets()[1],
        src_ip.octets()[2],
        src_ip.octets()[3],
        src_port,
        dst_ip.octets()[0],
        dst_ip.octets()[1],
        dst_ip.octets()[2],
        dst_ip.octets()[3],
        dst_port,
        syn,
        ack,
        fin,
    );

    // Inlet logic
    if let Some(_port_info) = unsafe { INLET_PORT_MAP.get(&src_port) } {
        info!(ctx, "INLET: Converting OCKAM packet to TCP");
        convert_ockam_to_tcp(ipv4hdr);
        return Ok(TC_ACT_PIPE);
    }

    // Outlet logic
    if let Some(_port_info) = unsafe { OUTLET_PORT_MAP.get(&dst_port) } {
        info!(ctx, "OUTLET: Converting OCKAM packet to TCP");
        convert_ockam_to_tcp(ipv4hdr);
        return Ok(TC_ACT_PIPE);
    }

    info!(ctx, "Skipping OCKAM packet");

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Option<*mut T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *mut T)
}
