#![no_std]
#![no_main]
#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::correctness)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![warn(clippy::style)]
#![warn(clippy::suspicious)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::wildcard_dependencies)]

use aya_ebpf::{
    EbpfContext,
    bindings::sk_action,
    helpers::{bpf_get_current_comm, generated::bpf_get_current_cgroup_id},
    macros::{cgroup_sock_addr, map},
    maps::RingBuf,
    programs::SockAddrContext,
};
use roy_common::*;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(10 * 1024, 0); // Let's see if 1KiB is enough

#[allow(clippy::needless_pass_by_value)]
#[cgroup_sock_addr(connect4)]
pub fn roy4(ctx: SockAddrContext) -> i32 {
    // aya_log_ebpf::debug!(&ctx, "Enter");
    let sock_addr = unsafe { &*ctx.sock_addr };
    let cgroup = unsafe { bpf_get_current_cgroup_id() };
    let cmd = bpf_get_current_comm().unwrap_or_default();

    if let Some(mut buf) = EVENTS.reserve::<Event>(0) {
        buf.write(Event {
            ipv: 0,
            pid: ctx.pid(),
            cgroup,
            cmd,
            addr4: sock_addr.user_ip4,
            addr6: Default::default(),
            port: sock_addr.user_port,
        });
        buf.submit(0);
    }
    sk_action::SK_PASS.cast_signed()
}

#[allow(clippy::needless_pass_by_value)]
#[cgroup_sock_addr(connect6)]
pub fn roy6(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &*ctx.sock_addr };
    let cgroup = unsafe { bpf_get_current_cgroup_id() };
    let cmd = bpf_get_current_comm().unwrap_or_default();
    let ipv6 = sock_addr.user_ip6;

    if let Some(mut buf) = EVENTS.reserve::<Event>(0) {
        buf.write(Event {
            ipv: 1,
            pid: ctx.pid(),
            cgroup,
            cmd,
            addr4: Default::default(),
            addr6: [ipv6[0], ipv6[1], ipv6[2], ipv6[3]], // This has to be this way. Otherwise verifier rejects due to "dereference of modified ctx ptr R1 off=8 disallowed". This might be llvm use memcpy on input and output pointers.
            port: sock_addr.user_port,
        });
        buf.submit(0);
    }
    sk_action::SK_PASS.cast_signed()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
