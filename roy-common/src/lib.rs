#![no_std]

use bytemuck::{Pod, Zeroable};

#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct EventV4 {
    pub cgroup: u64,
    pub cmd: [u8; 16],
    pub pid: u32,
    pub addr: u32,
    pub port: u32,
    pub padding: u32,
}
