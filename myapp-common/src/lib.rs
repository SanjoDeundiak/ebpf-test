#![no_std]

pub mod checksum;
pub mod checksum_helpers;
pub mod conversion;

pub const OCKAM_TCP_PORTAL_PROTOCOL: u8 = 217;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortMapInfo {
    pub pid: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortMapInfo {}
