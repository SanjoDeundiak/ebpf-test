#![no_std]
#![no_main]
#![feature(str_from_raw_parts)]

use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

mod common;

#[classifier]
pub fn ockam_ingress(ctx: TcContext) -> i32 {
    common::try_handle(ctx, true).unwrap_or_else(|ret| ret)
}

#[classifier]
pub fn ockam_egress(ctx: TcContext) -> i32 {
    common::try_handle(ctx, false).unwrap_or_else(|ret| ret)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
