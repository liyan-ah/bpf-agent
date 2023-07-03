use aya_bpf::{macros::map, maps::PerfEventArray};
use bpf_agent_common::Name;

#[map(name = "EVENTS")]
pub static mut EVENTS: PerfEventArray<Name> =
    PerfEventArray::with_max_entries(1024, 0);
