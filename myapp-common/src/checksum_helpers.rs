use core::ptr;

// Converts a checksum into u16
pub fn fold(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return !(csum as u16);
}

pub fn sum_typed<T>(packet: T) -> u64 {
    sum(ptr::addr_of!(packet) as *const u8, size_of::<T>())
}

pub fn sum(p: *const u8, size: usize) -> u64 {
    let mut res = 0u64;

    let mut p = p as *const u16;

    unsafe {
        for _ in 0..size / 2 {
            res = res + (p.read_unaligned() as u64);
            p = p.add(1);
        }
    }

    res
}

pub fn checksum(p: *const u8, size: usize) -> u16 {
    fold(sum(p, size))
}

pub fn checksum_typed<T>(packet: T) -> u16 {
    fold(sum_typed(packet))
}

#[cfg(test)]
mod tests {
    use crate::checksum_helpers::{checksum, checksum_typed, fold, sum, sum_typed};
    use core::ptr;

    #[test]
    fn fold_test() {
        assert_eq!(fold(0x24E17), 0xB1E6);
    }

    #[repr(C)]
    struct Packet {
        f0: u16,
        f1: u16,
        f2: u16,
        f3: u16,
        f4: u16,
        f5: u16,
        f6: u16,
        f7: u16,
        f8: u16,
        f9: u16,
    }

    #[test]
    fn sum_test() {
        let packet = Packet {
            f0: 0x4500,
            f1: 0x003c,
            f2: 0x1c46,
            f3: 0x4000,
            f4: 0x4006,
            f5: 0x0000,
            f6: 0xac10,
            f7: 0x0a63,
            f8: 0xac10,
            f9: 0x0a0c,
        };

        assert_eq!(
            packet.f0 as u64
                + packet.f1 as u64
                + packet.f2 as u64
                + packet.f3 as u64
                + packet.f4 as u64
                + packet.f5 as u64
                + packet.f6 as u64
                + packet.f7 as u64
                + packet.f8 as u64
                + packet.f9 as u64,
            0x24E17
        );

        assert_eq!(
            sum(ptr::addr_of!(packet) as *const u8, size_of::<Packet>()),
            0x24E17
        );
        assert_eq!(sum_typed(packet), 0x24E17);
    }

    #[test]
    fn checksum_test() {
        let packet = Packet {
            f0: 0x4500,
            f1: 0x003c,
            f2: 0x1c46,
            f3: 0x4000,
            f4: 0x4006,
            f5: 0x0000,
            f6: 0xac10,
            f7: 0x0a63,
            f8: 0xac10,
            f9: 0x0a0c,
        };

        assert_eq!(
            packet.f0 as u64
                + packet.f1 as u64
                + packet.f2 as u64
                + packet.f3 as u64
                + packet.f4 as u64
                + packet.f5 as u64
                + packet.f6 as u64
                + packet.f7 as u64
                + packet.f8 as u64
                + packet.f9 as u64,
            0x24E17
        );

        assert_eq!(
            checksum(ptr::addr_of!(packet) as *const u8, size_of::<Packet>()),
            0xB1E6
        );
        assert_eq!(checksum_typed(packet), 0xB1E6);
    }
}
