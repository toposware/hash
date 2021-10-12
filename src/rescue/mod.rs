/// MDS matrix for Rescue
pub mod mds;
/// Round constants for Rescue
pub mod round_constants;
/// S-Box for Rescue
pub mod sbox;
/// Transcript for Rescue
pub mod transcript;


// RESCUE CONSTANTS
// ================================================================================================

/// Function state is set to 4 field elements or 128 bytes;
/// 2 elements of the state are reserved for capacity
pub const STATE_WIDTH: usize = 4;
/// 2 elements of the state are reserved for rate
pub const RATE_WIDTH: usize = 2;

/// Two elements (64-bytes) are returned as digest.
pub const DIGEST_SIZE: usize = 2;

/// The number of rounds is set to 14 to provide 128-bit security level with 50% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
pub const NUM_HASH_ROUNDS: usize = 14;
