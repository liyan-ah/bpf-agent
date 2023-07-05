#![no_std]
#![no_main]

mod event;

use aya_bpf::{cty::c_long, helpers, macros::uprobe, programs::ProbeContext};

use aya_log_ebpf::info;
use bpf_agent_common::Name;

#[uprobe(name = "bpf_agent")]
pub fn bpf_agent(ctx: ProbeContext) -> u32 {
    match try_bpf_agent(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bpf_agent(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function getaddrinfo called by /home/odin/pdliyan");
    let name_addr: u64 = unsafe { (*ctx.regs).rsp + 8 * 1 };
    let name_length_addr: u64 = unsafe { (*ctx.regs).rsp + 8 * 2 };

    //0. read name.addr
    let name_addr: Result<u64, c_long> =
        unsafe { helpers::bpf_probe_read_user(name_addr as *const u64) };
    if let Err(_) = name_addr {
        return Ok(0);
    }
    let addr = name_addr.unwrap();

    //1. read name.length
    let name_length: Result<u64, c_long> =
        unsafe { helpers::bpf_probe_read_user(name_length_addr as *const u64) };
    if let Err(_) = name_length {
        return Ok(0);
    }
    let length = name_length.unwrap();

    //2. read name
    let name: Result<[u8; 128], c_long> =
        unsafe { helpers::bpf_probe_read_user(addr as *const [u8; 128]) };
    match name {
        Ok(v) => {
            info!(&ctx, "name: {} {}", v[0], v[1]);
            info!(&ctx, "length, {}", length);
            let name_event = Name {
                name: v,
                name_length: length,
            };
            unsafe { event::EVENTS.output(&ctx, &name_event, 0) };
        }
        Err(_) => {
            return Ok(0);
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
