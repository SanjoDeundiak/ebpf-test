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
