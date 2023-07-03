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
    let name_addr: u64 = ctx.arg(0).ok_or(0u32)?;
    let name_length: u64 = ctx.arg(1).ok_or(1u32)?;
    let name: Result<[u8; 200], c_long> =
        unsafe { helpers::bpf_probe_read_user(name_addr as *const [u8; 200]) };
    match name {
        Ok(v) => {
            let name_event = Name {
                name: v.clone(),
                name_length,
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
