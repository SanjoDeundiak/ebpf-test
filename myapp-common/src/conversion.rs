use crate::checksum::iph_update_csum;
use crate::OCKAM_TCP_PORTAL_PROTOCOL;
use core::mem::offset_of;
use core::ptr::copy_nonoverlapping;
use network_types::ip::{IpProto, Ipv4Hdr};

pub fn convert_tcp_to_ockam(ipv4hdr: *mut Ipv4Hdr) {
    unsafe {
        // Basically ipv4hdr.proto = OCKAM_TCP_PORTAL_PROTOCOL, that can't be done cause type-safety
        #[allow(const_item_mutation)]
        copy_nonoverlapping(
            &mut OCKAM_TCP_PORTAL_PROTOCOL as *mut u8,
            (ipv4hdr as *mut u8).add(offset_of!(Ipv4Hdr, proto)),
            1,
        );
    }

    iph_update_csum(ipv4hdr);
}

pub fn convert_ockam_to_tcp(ipv4hdr: *mut Ipv4Hdr) {
    unsafe {
        (*ipv4hdr).proto = IpProto::Tcp;
    }

    iph_update_csum(ipv4hdr);
}
