#![no_std]
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

use bytemuck::{Pod, Zeroable};

#[derive(Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct Event {
    pub cgroup: u64,
    pub cmd: [u8; 16],
    pub pid: u32,
    pub addr4: u32,
    pub addr6: [u32; 4],
    pub port: u32,
    pub ipv: u32, // 0 is IPv4, 1 is IPv6
}
