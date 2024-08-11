use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT};
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::bpf_csum_diff;
use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::programs::TcContext;
use aya_ebpf::{memcpy, memset};
use aya_log_ebpf::info;
use core::mem;
use core::net::Ipv4Addr;
use core::num::TryFromIntError;
use core::{slice, str};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use myapp_common::checksum::{iph_update_csum, udph_update_csum};
use myapp_common::{
    replace_dst_ip, replace_src_ip, tcp_replace_dst_port, tcp_replace_src_port,
    udp_replace_dst_port, udp_replace_src_port,
};

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 1500],
}

// #[map]
// pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
pub fn try_handle(ctx: TcContext, ingress: bool) -> Result<i32, i32> {
    let ethhdr = ptr_at::<EthHdr>(&ctx, 0).ok_or(TC_ACT_PIPE)?;

    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(TC_ACT_PIPE)?;

    if unsafe { (*ipv4hdr).proto } == IpProto::Tcp {
        return handle_tcp(&ctx, ipv4hdr, ingress);
    }

    if unsafe { (*ipv4hdr).proto } == IpProto::Udp {
        return handle_udp(&ctx, ipv4hdr, ingress);
    }

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn handle_udp(ctx: &TcContext, ipv4hdr: *mut Ipv4Hdr, ingress: bool) -> Result<i32, i32> {
    let udphdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(TC_ACT_PIPE)?;
    let udphdr_clone = unsafe { *udphdr };

    let src_port = u16::from_be(udphdr_clone.source);
    let dst_port = u16::from_be(udphdr_clone.dest);

    // if ingress && dst_port != 6000 {
    //     return Ok(TC_ACT_PIPE);
    // }
    //
    // if !ingress && src_port != 6000 {
    //     return Ok(TC_ACT_PIPE);
    // }

    let src_ip = unsafe { (*ipv4hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr() };

    let mode = if ingress { "ingress" } else { "egress" };

    info!(
        ctx,
        "{} UDP PACKET SRC: {}.{}.{}.{}:{}, DST: {}.{}.{}.{}:{}",
        mode,
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
    );

    // if ingress {
    //     udp_handle_ingress(ctx, ipv4hdr, udphdr)?;
    // } else {
    //     udp_handle_egress(ctx, ipv4hdr, udphdr)?;
    // }

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn handle_tcp(ctx: &TcContext, ipv4hdr: *mut Ipv4Hdr, ingress: bool) -> Result<i32, i32> {
    let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(TC_ACT_PIPE)?;
    let tcphdr_clone = unsafe { *tcphdr };

    let src_port = u16::from_be(tcphdr_clone.source);
    let dst_port = u16::from_be(tcphdr_clone.dest);

    if ingress && dst_port != 6000 {
        info!(ctx, "Skipping TCP packet INGRESS dst_port {}", dst_port);
        return Ok(TC_ACT_PIPE);
    }

    if !ingress && src_port != 6000 {
        info!(ctx, "Skipping TCP packet EGRESS src_port {}", src_port);
        return Ok(TC_ACT_PIPE);
    }

    let syn = tcphdr_clone.syn();
    let ack = tcphdr_clone.ack();
    let fin = tcphdr_clone.fin();

    // if syn != 0 && ack != 0 {
    //     info!(&ctx, "Drop SYN ACK packet");
    //     return Ok(TC_ACT_SHOT);
    // }
    //
    // if ack != 0 {
    //     info!(&ctx, "Drop ACK packet");
    //     return Ok(TC_ACT_SHOT);
    // }

    // let body_str = {
    {
        let skb_len = ctx.skb.len() as usize;

        let tcphdr_len = (tcphdr_clone.doff() as usize) * 4;

        let start = ctx.data();
        let end = ctx.data_end();

        if end < start {
            return Ok(TC_ACT_PIPE);
        }

        // TODO: Is that correct
        let contiguous_len = end - start;

        info!(ctx, "Contiguous len {}", contiguous_len);
        info!(ctx, "SKB len {}", skb_len);
        info!(ctx, "TCP Header len {}", tcphdr_len);

        let body_len = skb_len - tcphdr_len - EthHdr::LEN - Ipv4Hdr::LEN;

        info!(ctx, "body_len: {}", body_len);

        // let mut buffer = [0u8; 128];

        // match ctx.load_bytes(tcphdr_len, &mut buffer) {
        //     Ok(_) => {
        //         info!(ctx, "SUCCESS");
        //     }
        //     Err(err) => {
        //         info!(ctx, "error loading bytes: {}", err);
        //         return Ok(TC_ACT_PIPE);
        //     }
        // }

        // unsafe {
        // static mut BUFFER: [u8; 512] = [0u8; 512];

        // if ctx.skb.pull_data(skb_len).is_ok() {
        //     info!(ctx, "New contiguous len {}", ctx.data_end() - ctx.data());
        // } else {
        //     info!(ctx, "Error pulling");
        // }

        // if let Ok(read) = ctx.skb.load_bytes(contiguous_len, &mut BUFFER) {
        // to_hex(&BUFFER[..read])
        // } else {
        //     return Ok(TC_ACT_PIPE);
        // }
        // }
    };

    let src_ip = unsafe { (*ipv4hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr() };

    let mode = if ingress { "ingress" } else { "egress" };

    info!(
        ctx,
        "{} TCP PACKET SRC: {}.{}.{}.{}:{}, DST: {}.{}.{}.{}:{}. SYN {} ACK {} FIN {}", //. Body: {body_str}",
        mode,
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

    if ingress {
        info!(ctx, "Converting TCP packet to UDP");
        return if convert_tcp_to_udp(ctx, ipv4hdr, tcphdr, ctx.skb.len()).is_err() {
            info!(ctx, "Couldn't convert TCP packet to UDP");
            Ok(TC_ACT_SHOT)
        } else {
            Ok(TC_ACT_PIPE)
        };
    }

    // if ingress {
    //     tcp_handle_ingress(ctx, ipv4hdr, tcphdr)?;
    // } else {
    //     tcp_handle_egress(ctx, ipv4hdr, tcphdr)?;
    // }

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
pub fn convert_tcp_to_udp(
    ctx: &TcContext,
    ipv4hdr: *mut Ipv4Hdr,
    tcphdr: *mut TcpHdr,
    skb_len: u32,
) -> Result<(), ()> {
    let new_len = skb_len - ((EthHdr::LEN + Ipv4Hdr::LEN) as u32);
    let new_len = match u16::try_from(new_len) {
        Ok(new_len) => new_len,
        Err(_) => {
            return Err(());
        }
    };

    info!(ctx, "New_len: {}", new_len);

    unsafe {
        (*ipv4hdr).proto = IpProto::Udp;
        iph_update_csum(ipv4hdr);

        let tcphdr_clone = *tcphdr;

        let udphdr = tcphdr as *mut UdpHdr;

        info!(
            ctx,
            "SRC: {} DST: {}", tcphdr_clone.source, tcphdr_clone.dest
        );

        (*udphdr).source = tcphdr_clone.source;
        (*udphdr).dest = tcphdr_clone.dest;
        (*udphdr).len = new_len;
        (*udphdr).check = 0x0000;

        // Move tcphdr.seq

        // udph_update_csum(udphdr);
    }

    Ok(())
}

#[inline(always)]
fn tcp_handle_egress(
    ctx: &TcContext,
    ipv4hdr: *mut Ipv4Hdr,
    tcphdr: *mut TcpHdr,
) -> Result<(), i32> {
    let dst_addr = unsafe { (*ipv4hdr).dst_addr() };
    if dst_addr.octets()[3] == 2 {
        info!(ctx, "REPLACING TCP EGRESS DST IP");

        replace_dst_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 1));
    }

    let dst_port = u16::from_be(unsafe { (*tcphdr).dest });
    if dst_port == 5000 {
        info!(ctx, "REPLACING TCP EGRESS DST PORT");

        tcp_replace_dst_port(tcphdr, 5001);
    }

    Ok(())
}

#[inline(always)]
fn tcp_handle_ingress(
    ctx: &TcContext,
    ipv4hdr: *mut Ipv4Hdr,
    tcphdr: *mut TcpHdr,
) -> Result<(), i32> {
    let src_addr = unsafe { (*ipv4hdr).src_addr() };
    if src_addr.octets()[3] == 1 {
        info!(ctx, "REPLACING TCP INGRESS SRC IP");

        replace_src_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 2));
    }

    let src_port = u16::from_be(unsafe { (*tcphdr).source });
    if src_port == 5001 {
        info!(ctx, "REPLACING TCP INGRESS SRC PORT");

        tcp_replace_src_port(tcphdr, 5000);
    }

    Ok(())
}

#[inline(always)]
fn udp_handle_egress(
    ctx: &TcContext,
    ipv4hdr: *mut Ipv4Hdr,
    udphdr: *mut UdpHdr,
) -> Result<(), i32> {
    let dst_addr = unsafe { (*ipv4hdr).dst_addr() };
    if dst_addr.octets()[3] == 2 {
        info!(ctx, "REPLACING UDP EGRESS DST IP");

        replace_dst_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 1));
    }

    let dst_port = u16::from_be(unsafe { (*udphdr).dest });
    if dst_port == 5000 {
        info!(ctx, "REPLACING UDP EGRESS DST PORT");

        udp_replace_dst_port(udphdr, 5001);
    }

    Ok(())
}

#[inline(always)]
fn udp_handle_ingress(
    ctx: &TcContext,
    ipv4hdr: *mut Ipv4Hdr,
    udphdr: *mut UdpHdr,
) -> Result<(), i32> {
    let src_addr = unsafe { (*ipv4hdr).src_addr() };
    if src_addr.octets()[3] == 1 {
        info!(ctx, "REPLACING UDP INGRESS SRC IP");

        replace_src_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 2));
    }

    let src_port = u16::from_be(unsafe { (*udphdr).source });
    if src_port == 5001 {
        info!(ctx, "REPLACING UDP INGRESS SRC PORT");

        udp_replace_src_port(udphdr, 5000);
    }

    Ok(())
}

// fn half_byte_to_hex(half_byte: u8) -> u8 {
//     let ch = match half_byte {
//         0 => '0',
//         1 => '1',
//         2 => '2',
//         3 => '3',
//         4 => '4',
//         5 => '5',
//         6 => '6',
//         7 => '7',
//         8 => '8',
//         9 => '9',
//         10 => 'A',
//         11 => 'B',
//         12 => 'C',
//         13 => 'D',
//         14 => 'E',
//         15 => 'F',
//         _ => panic!(),
//     };
//
//     ch as u8
// }
//
// fn byte_to_hex(byte: u8) -> (u8, u8) {
//     (half_byte_to_hex(byte / 16), half_byte_to_hex(byte % 16))
// }
//
// const BUFFER_STR: [u8; 128] = [0u8; 128];
//
// fn to_hex(slice: &[u8]) -> &str {
//     unsafe {
//         memset(BUFFER_STR.as_mut_ptr(), 0, 128);
//         memcpy(BUFFER_STR.as_mut_ptr(), "NO BODY".as_ptr() as *mut u8, 7)
//     }
//
//     if slice.len() > 64 {
//         return unsafe { str::from_raw_parts(BUFFER_STR.as_ptr(), 7) };
//     }
//
//     let mut i = 0usize;
//     for byte in &slice[..] {
//         let (hex1, hex2) = byte_to_hex(*byte);
//         BUFFER_STR[i] = hex1;
//         BUFFER_STR[i + 1] = hex2;
//
//         i += 2;
//     }
//
//     unsafe { str::from_raw_parts(BUFFER_STR.as_ptr(), i) }
// }

#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Option<*mut T> {
    // TODO: Should we instead use load and store bytes?

    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *mut T)
}
