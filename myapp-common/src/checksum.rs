use crate::checksum_helpers::checksum_typed;
use network_types::ip::Ipv4Hdr;
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

#[inline(always)]
pub fn iph_update_csum(iph: *mut Ipv4Hdr) {
    unsafe {
        (*iph).check = 0;

        let check = checksum_typed(*iph);

        (*iph).check = check;
    }
}

#[inline(always)]
// FIXME: Probably incorrect.
pub fn tcph_update_csum(tcph: *mut TcpHdr) {
    unsafe {
        (*tcph).check = 0;

        let check = checksum_typed(*tcph);

        (*tcph).check = check;
    }
}

#[inline(always)]
// FIXME: Probably incorrect.
pub fn udph_update_csum(udph: *mut UdpHdr) {
    unsafe {
        (*udph).check = 0;

        // let check = checksum_typed(*udph);

        // (*udph).check = check;
    }
}

#[cfg(test)]
mod tests {
    use crate::checksum::iph_update_csum;
    use network_types::ip::{IpProto, Ipv4Hdr};

    #[test]
    fn test() {
        let mut ipv4hdr = Ipv4Hdr {
            _bitfield_align_1: [],
            _bitfield_1: Default::default(), // FIXME
            tos: 0,
            tot_len: 0x28u16.to_be(),
            id: 17581u16.to_be(),
            frag_off: 0, // FIXME
            ttl: 64,
            proto: IpProto::Udp,
            check: 0,
            src_addr: u32::from_le_bytes([127, 0, 0, 1]),
            dst_addr: u32::from_le_bytes([127, 0, 0, 1]),
        };

        iph_update_csum(&mut ipv4hdr);

        assert_eq!(ipv4hdr.check, 0xf821u16.to_be())
    }
}
