#![no_std]
#![no_main]
#![feature(str_from_raw_parts)]

use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

mod common;

#[classifier]
pub fn ingress(ctx: TcContext) -> i32 {
    match common::try_handle(ctx, true) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
