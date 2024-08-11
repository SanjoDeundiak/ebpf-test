#![no_std]

pub mod checksum;
pub mod checksum_helpers;

use crate::checksum::{iph_update_csum, tcph_update_csum, udph_update_csum};
use core::net::Ipv4Addr;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

#[inline(always)]
pub fn replace_src_ip(ipv4hdr: *mut Ipv4Hdr, new_ip: Ipv4Addr) {
    unsafe {
        (*ipv4hdr).set_src_addr(new_ip);
    }
    iph_update_csum(ipv4hdr);
}

#[inline(always)]
pub fn convert_tcp_to_udp(
    ipv4hdr: *mut Ipv4Hdr,
    tcphdr: *mut TcpHdr,
    skb_len: u32,
) -> Result<(), ()> {
    let tcphdr_len = unsafe { ((*tcphdr).doff() as u32) * 4 };

    let new_len = skb_len - tcphdr_len - ((EthHdr::LEN + Ipv4Hdr::LEN) as u32);
    let new_len = match u16::try_from(new_len) {
        Ok(new_len) => new_len,
        Err(_) => {
            return Err(());
        }
    };

    unsafe {
        (*ipv4hdr).proto = IpProto::Udp;
        iph_update_csum(ipv4hdr);

        let udphdr = tcphdr as *mut UdpHdr;

        // Move tcphdr.seq

        (*udphdr).len = new_len;
        udph_update_csum(udphdr);
    }

    Ok(())
}

#[inline(always)]
pub fn replace_dst_ip(ipv4hdr: *mut Ipv4Hdr, new_ip: Ipv4Addr) {
    // TODO: Should ctx.l3_csum_replace or ctx.l4_csum_replace be used instead?

    unsafe {
        (*ipv4hdr).set_dst_addr(new_ip);
    }
    iph_update_csum(ipv4hdr);
}

#[inline(always)]
pub fn tcp_replace_src_port(tcphdr: *mut TcpHdr, new_port: u16) {
    unsafe {
        (*tcphdr).source = new_port.to_be();
    }
    tcph_update_csum(tcphdr);
}

#[inline(always)]
pub fn tcp_replace_dst_port(tcphdr: *mut TcpHdr, new_port: u16) {
    unsafe {
        (*tcphdr).dest = new_port.to_be();
    }
    tcph_update_csum(tcphdr);
}

#[inline(always)]
pub fn udp_replace_src_port(udphdr: *mut UdpHdr, new_port: u16) {
    unsafe {
        (*udphdr).source = new_port.to_be();
    }
    udph_update_csum(udphdr);
}

#[inline(always)]
pub fn udp_replace_dst_port(udphdr: *mut UdpHdr, new_port: u16) {
    unsafe {
        (*udphdr).dest = new_port.to_be();
    }
    udph_update_csum(udphdr);
}

//
// #[inline(always)]
// pub fn udph_csum(udph: *mut UdpHdr) -> u16 {
//     let csum = unsafe {
//         (*udph).check = 0;
//         bpf_csum_diff(
//             core::ptr::null_mut(),
//             0,
//             udph as *mut u32,
//             size_of::<UdpHdr>() as u32,
//             0,
//         ) as u64
//     };
//     csum_fold_helper(csum)
// }
//
// #[inline(always)]
// pub fn tcph_csum(tcph: *mut TcpHdr) -> u16 {
//     let csum = unsafe {
//         (*tcph).check = 0;
//         bpf_csum_diff(
//             core::ptr::null_mut(),
//             0,
//             tcph as *mut u32,
//             size_of::<TcpHdr>() as u32,
//             0,
//         ) as u64
//     };
//     csum_fold_helper(csum)
// }
