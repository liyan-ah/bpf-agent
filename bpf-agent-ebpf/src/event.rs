use aya_bpf::{maps::PerfEventArray, macros::map};

pub struct Name {
    pub name: [u8; 200],
}

#[map(name = "EVENTS")]
pub static mut EVENTS: PerfEventArray<Name> =
    PerfEventArray::with_max_entries(1024, 0);
