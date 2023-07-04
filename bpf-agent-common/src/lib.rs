#![no_std]

pub struct Name {
    pub name: [u8; 128],
    pub name_length: u64,
}
