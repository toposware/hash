/// Base power map of the Rescue S-Box
pub const ALPHA: u32 = 3;

/// Inverse power map
pub const INV_ALPHA: [u64; 4] = [
    0xaaaaaaaaaaaaaaab,
    0xaaaaaaaaaaaaaaaa,
    0xaaaaaaaaaaaaaaaa,
    0x0555555555555560,
];
