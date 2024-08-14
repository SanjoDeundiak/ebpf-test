use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;

use aya_ebpf::memcpy;
use core::mem;
use core::mem::offset_of;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use myapp_common::checksum::iph_update_csum;
use myapp_common::OCKAM_TCP_PORTAL_PROTOCOL;

const INLET_PORT: u16 = 6666;
const SERVER_PORT: u16 = 7777;

#[inline(always)]
pub fn try_handle(ctx: TcContext, ingress: bool) -> Result<i32, i32> {
    let ethhdr = ptr_at::<EthHdr>(&ctx, 0).ok_or(TC_ACT_PIPE)?;

    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    // TODO: Account for IPv4 options
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(TC_ACT_PIPE)?;
    let ipv4hdr_stack = unsafe { *ipv4hdr };

    if ipv4hdr_stack.proto == IpProto::Tcp {
        return handle_tcp(&ctx, ipv4hdr, ingress);
    }

    if ipv4hdr_stack.proto as u8 == OCKAM_TCP_PORTAL_PROTOCOL {
        return handle_ockam_tcp_portal_protocol(&ctx, ipv4hdr, ingress);
    }

    Ok(TC_ACT_PIPE)
}

// #[inline(always)]
// fn handle_udp(ctx: &TcContext, ipv4hdr: &Ipv4Hdr, ingress: bool) -> Result<i32, i32> {
//     let udphdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(TC_ACT_PIPE)?;
//     let udphdr_clone = unsafe { *udphdr };
//
//     let src_port = u16::from_be(udphdr_clone.source);
//     let dst_port = u16::from_be(udphdr_clone.dest);
//
//     // if ingress && dst_port != 6000 {
//     //     return Ok(TC_ACT_PIPE);
//     // }
//     //
//     // if !ingress && src_port != 6000 {
//     //     return Ok(TC_ACT_PIPE);
//     // }
//
//     let src_ip = ipv4hdr.src_addr();
//     let dst_ip = ipv4hdr.dst_addr();
//
//     let mode = if ingress { "ingress" } else { "egress" };
//
//     let skb_len = ctx.skb.len() as usize;
//
//     info!(ctx, "SKB len {}", skb_len);
//
//     let payload_len = skb_len - UdpHdr::LEN - EthHdr::LEN - Ipv4Hdr::LEN;
//
//     info!(ctx, "Payload len {}", payload_len);
//
//     info!(
//         ctx,
//         "{} UDP PACKET SRC: {}.{}.{}.{}:{}, DST: {}.{}.{}.{}:{}. Len={}. Check={}",
//         mode,
//         src_ip.octets()[0],
//         src_ip.octets()[1],
//         src_ip.octets()[2],
//         src_ip.octets()[3],
//         src_port,
//         dst_ip.octets()[0],
//         dst_ip.octets()[1],
//         dst_ip.octets()[2],
//         dst_ip.octets()[3],
//         dst_port,
//         udphdr_clone.len,
//         udphdr_clone.check
//     );
//
//     // if !ingress && src_port == 6000 {
//     //     info!(ctx, "Converting egress TCP packet to UDP");
//     //     return match convert_udp_to_tcp(ctx, ethhdr, ipv4hdr, udphdr) {
//     //         Ok(_) => {
//     //             info!(ctx, "Converted egress UDP packet to TCP");
//     //             Ok(TC_ACT_PIPE)
//     //         }
//     //         Err(err) => {
//     //             info!(
//     //                 ctx,
//     //                 "Couldn't convert egress UDP packet to TCP. Error {}", err
//     //             );
//     //             Ok(TC_ACT_SHOT)
//     //         }
//     //     };
//     // }
//
//     // if ingress {
//     //     udp_handle_ingress(ctx, ipv4hdr, udphdr)?;
//     // } else {
//     //     udp_handle_egress(ctx, ipv4hdr, udphdr)?;
//     // }
//
//     Ok(TC_ACT_PIPE)
// }

#[inline(always)]
fn handle_tcp(ctx: &TcContext, ipv4hdr: *mut Ipv4Hdr, ingress: bool) -> Result<i32, i32> {
    let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(TC_ACT_PIPE)?;
    let tcphdr_clone = unsafe { *tcphdr };

    let src_port = u16::from_be(tcphdr_clone.source);
    let dst_port = u16::from_be(tcphdr_clone.dest);

    //
    // if !ingress && dst_port != 6000 {
    //     info!(ctx, "Skipping TCP packet EGRESS dst_port {}", dst_port);
    //     return Ok(TC_ACT_PIPE);
    // }
    //
    // if ingress && src_port != 6000 {
    //     info!(ctx, "Skipping TCP packet INGRESS src_port {}", src_port);
    //     return Ok(TC_ACT_PIPE);
    // }

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

    let src_ip = unsafe { (*ipv4hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr() };

    let mode = if ingress { "ingress" } else { "egress" };

    info!(
        ctx,
        "{} TCP PACKET SRC: {}.{}.{}.{}:{}, DST: {}.{}.{}.{}:{}. SYN {} ACK {} FIN {}",
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

    // Inlet logic
    if ingress && dst_port == INLET_PORT {
        info!(ctx, "OUTLET: Converting ingress TCP packet to OCKAM");
        convert_tcp_to_ockam(ipv4hdr);
        info!(ctx, "OUTLET: Converted ingress TCP packet to OCKAM");
        return Ok(TC_ACT_PIPE);
    }

    // Outlet
    if ingress && src_port == SERVER_PORT {
        info!(ctx, "OUTLET: Converting ingress TCP packet to OCKAM");
        convert_tcp_to_ockam(ipv4hdr);
        info!(ctx, "OUTLET: Converted ingress TCP packet to OCKAM");
        return Ok(TC_ACT_PIPE);
    }

    // if ingress {
    //     tcp_handle_ingress(ctx, ipv4hdr, tcphdr)?;
    // } else {
    //     tcp_handle_egress(ctx, ipv4hdr, tcphdr)?;
    // }

    info!(ctx, "Skipping TCP packet");

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn handle_ockam_tcp_portal_protocol(
    ctx: &TcContext,
    ipv4hdr: *mut Ipv4Hdr,
    ingress: bool,
) -> Result<i32, i32> {
    let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(TC_ACT_PIPE)?;
    let tcphdr_clone = unsafe { *tcphdr };

    let src_port = u16::from_be(tcphdr_clone.source);
    let dst_port = u16::from_be(tcphdr_clone.dest);

    let syn = tcphdr_clone.syn();
    let ack = tcphdr_clone.ack();
    let fin = tcphdr_clone.fin();

    let src_ip = unsafe { (*ipv4hdr).src_addr() };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr() };

    let mode = if ingress { "ingress" } else { "egress" };

    info!(
        ctx,
        "{} OCKAM TCP PORTAL PACKET SRC: {}.{}.{}.{}:{}, DST: {}.{}.{}.{}:{}. SYN {} ACK {} FIN {}",
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

    // Inlet logic
    if !ingress && src_port == INLET_PORT {
        info!(ctx, "INLET: Converting egress OCKAM packet to TCP");
        convert_ockam_to_tcp(ipv4hdr);
        info!(ctx, "INLET: Converted egress OCKAM packet to TCP");
        return Ok(TC_ACT_PIPE);
    }

    // Outlet logic
    if !ingress && dst_port == SERVER_PORT {
        info!(ctx, "OUTLET: Converting egress OCKAM packet to TCP");
        convert_ockam_to_tcp(ipv4hdr);
        info!(ctx, "OUTLET: Converted egress OCKAM packet to TCP");
        return Ok(TC_ACT_PIPE);
    }

    info!(ctx, "Skipping OCKAM packet");

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
pub fn convert_tcp_to_ockam(ipv4hdr: *mut Ipv4Hdr) {
    unsafe {
        // Basically ipv4hdr.proto = OCKAM_TCP_PORTAL_PROTOCOL, that can't be done cause type-safety
        memcpy(
            (ipv4hdr as *mut u8).add(offset_of!(Ipv4Hdr, proto)),
            &mut OCKAM_TCP_PORTAL_PROTOCOL as *mut u8,
            1,
        );
    }

    iph_update_csum(ipv4hdr);
}

#[inline(always)]
pub fn convert_ockam_to_tcp(ipv4hdr: *mut Ipv4Hdr) {
    unsafe {
        (*ipv4hdr).proto = IpProto::Tcp;
    }

    iph_update_csum(ipv4hdr);
}

// #[inline(always)]
// pub fn convert_tcp_to_udp(
//     ctx: &TcContext,
//     ethhdr: *mut EthHdr,
//     ipv4hdr: *mut Ipv4Hdr,
//     tcphdr: *mut TcpHdr,
// ) -> Result<(), c_long> {
//     let ethhdr_clone = unsafe { *ethhdr };
//     let mut ipv4hdr_clone = unsafe { *ipv4hdr };
//     let tcphdr_clone = unsafe { *tcphdr };
//
//     let tcphdr_len = (tcphdr_clone.doff() as u32) * 4;
//     let tcp_payload_len = ctx.len() - tcphdr_len - EthHdr::LEN as u32 - Ipv4Hdr::LEN as u32;
//
//     let mut tcphdr_binary = [0u8; 60];
//     let tcphdr_slice = unsafe { slice::from_raw_parts(tcphdr as *const u8, tcphdr_len as usize) };
//     tcphdr_binary[..tcphdr_len as usize].copy_from_slice(tcphdr_slice);
//
//     if tcphdr_len > 60 || tcphdr_len < 20 {
//         return Err(-55);
//     }
//
//     let tcphdr_binary_slice = &tcphdr_binary[..tcphdr_len as usize];
//
//     let new_payload_len = tcp_payload_len + tcphdr_len; // We don't need to duplicate ports so, - 4;
//     let new_udp_len = new_payload_len + UdpHdr::LEN as u32;
//     let new_ipv4_len = new_udp_len + Ipv4Hdr::LEN as u32;
//     let new_skb_len = new_ipv4_len + EthHdr::LEN as u32;
//     let len_diff = new_skb_len as i32 - ctx.len() as i32;
//
//     info!(
//         ctx,
//         "New payload len: {}. New UDP len: {}, New IPv4 len: {}, New SKB len: {}. Len diff: {}",
//         new_payload_len,
//         new_udp_len,
//         new_ipv4_len,
//         new_skb_len,
//         len_diff
//     );
//
//     info!(ctx, "Changing SKB size to {} bytes", new_skb_len);
//     ctx.skb.adjust_room(len_diff, BPF_ADJ_ROOM_NET, 0)?;
//     info!(ctx, "New length: {}", ctx.len());
//
//     ipv4hdr_clone.tot_len = (new_ipv4_len as u16).to_be();
//     ipv4hdr_clone.proto = IpProto::Udp;
//
//     iph_update_csum(&mut ipv4hdr_clone);
//
//     let udphdr = UdpHdr {
//         source: tcphdr_clone.source,
//         dest: tcphdr_clone.dest,
//         len: (new_udp_len as u16).to_be(),
//         check: 0,
//     };
//
//     ctx.skb.store(0, &ethhdr_clone, 0)?;
//     ctx.skb.store(EthHdr::LEN, &ipv4hdr_clone, 0)?;
//     ctx.skb.store(EthHdr::LEN + Ipv4Hdr::LEN, &udphdr, 0)?;
//
//     if ctx.len() >= (EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as u32 + tcphdr_len {
//         ctx.skb.store_bytes(
//             EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN,
//             tcphdr_binary_slice,
//             0,
//         )?;
//     } else {
//         return Err(-56);
//     }
//
//     // ctx.l4_csum_replace(
//     //     EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check),
//     //     0,
//     //     1,
//     //     BPF_F_PSEUDO_HDR,
//     // )?;
//
//     // let new_len = ctx.len() - ((EthHdr::LEN + Ipv4Hdr::LEN) as u32);
//     // let new_len = match u16::try_from(new_len) {
//     //     Ok(new_len) => new_len,
//     //     Err(_) => {
//     //         return Err(());
//     //     }
//     // };
//     //
//     // info!(ctx, "New_len: {}", new_len);
//
//     // unsafe {
//     //     (*ipv4hdr).proto = IpProto::Udp;
//     //     iph_update_csum(ipv4hdr);
//     //
//     //     let tcphdr_clone = *tcphdr;
//     //
//     //     let udphdr = tcphdr as *mut UdpHdr;
//     //
//     //     // info!(
//     //     //     ctx,
//     //     //     "SRC: {} DST: {}", tcphdr_clone.source, tcphdr_clone.dest
//     //     // );
//     //
//     //     (*udphdr).source = tcphdr_clone.source;
//     //     (*udphdr).dest = tcphdr_clone.dest;
//     //     (*udphdr).len = new_len;
//     //     // (*udphdr).check = 0x0000;
//     //
//     //     // Move tcphdr.seq
//     //
//     //     // udph_update_csum(udphdr);
//     // }
//
//     Ok(())
// }

// #[inline(always)]
// fn tcp_handle_egress(
//     ctx: &TcContext,
//     ipv4hdr: *mut Ipv4Hdr,
//     tcphdr: *mut TcpHdr,
// ) -> Result<(), i32> {
//     let dst_addr = unsafe { (*ipv4hdr).dst_addr() };
//     if dst_addr.octets()[3] == 2 {
//         info!(ctx, "REPLACING TCP EGRESS DST IP");
//
//         replace_dst_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 1));
//     }
//
//     let dst_port = u16::from_be(unsafe { (*tcphdr).dest });
//     if dst_port == 5000 {
//         info!(ctx, "REPLACING TCP EGRESS DST PORT");
//
//         tcp_replace_dst_port(tcphdr, 5001);
//     }
//
//     Ok(())
// }
//
// #[inline(always)]
// fn tcp_handle_ingress(
//     ctx: &TcContext,
//     ipv4hdr: *mut Ipv4Hdr,
//     tcphdr: *mut TcpHdr,
// ) -> Result<(), i32> {
//     let src_addr = unsafe { (*ipv4hdr).src_addr() };
//     if src_addr.octets()[3] == 1 {
//         info!(ctx, "REPLACING TCP INGRESS SRC IP");
//
//         replace_src_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 2));
//     }
//
//     let src_port = u16::from_be(unsafe { (*tcphdr).source });
//     if src_port == 5001 {
//         info!(ctx, "REPLACING TCP INGRESS SRC PORT");
//
//         tcp_replace_src_port(tcphdr, 5000);
//     }
//
//     Ok(())
// }

// #[inline(always)]
// fn udp_handle_egress(
//     ctx: &TcContext,
//     ipv4hdr: *mut Ipv4Hdr,
//     udphdr: *mut UdpHdr,
// ) -> Result<(), i32> {
//     let dst_addr = unsafe { (*ipv4hdr).dst_addr() };
//     if dst_addr.octets()[3] == 2 {
//         info!(ctx, "REPLACING UDP EGRESS DST IP");
//
//         replace_dst_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 1));
//     }
//
//     let dst_port = u16::from_be(unsafe { (*udphdr).dest });
//     if dst_port == 5000 {
//         info!(ctx, "REPLACING UDP EGRESS DST PORT");
//
//         udp_replace_dst_port(udphdr, 5001);
//     }
//
//     Ok(())
// }
//
// #[inline(always)]
// fn udp_handle_ingress(
//     ctx: &TcContext,
//     ipv4hdr: *mut Ipv4Hdr,
//     udphdr: *mut UdpHdr,
// ) -> Result<(), i32> {
//     let src_addr = unsafe { (*ipv4hdr).src_addr() };
//     if src_addr.octets()[3] == 1 {
//         info!(ctx, "REPLACING UDP INGRESS SRC IP");
//
//         replace_src_ip(ipv4hdr, Ipv4Addr::new(127, 0, 0, 2));
//     }
//
//     let src_port = u16::from_be(unsafe { (*udphdr).source });
//     if src_port == 5001 {
//         info!(ctx, "REPLACING UDP INGRESS SRC PORT");
//
//         udp_replace_src_port(udphdr, 5000);
//     }
//
//     Ok(())
// }

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
