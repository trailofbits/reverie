use serde::de::{Deserialize, Deserializer};
use serde::ser::{SerializeSeq, Serializer};
use serde::Serialize;

mod prf;
mod prng;
mod tree;

pub use prf::PRF;
pub use tree::TreePRF;

pub use blake3::{Hash, Hasher};

// we target 128-bits of security
pub const KEY_SIZE: usize = 16;

// hash digest size is 2*KEY_SIZE to mitigate birthday attacks
pub const HASH_SIZE: usize = KEY_SIZE * 2;

/// We use blake3 in keyed mode as the commitment scheme:
/// blake3 takes a 256-bit key (for 256-bits of security when used as a MAC),
/// however we set the last 128-bit of the key to 0 to obtain a
/// commitment scheme with:
///
/// - 128 bits of computational blinding
/// - 128 bits of computational binding
///
/// This also means that a single PRF output can be used as commitment randomness directly.
pub fn commit(key: &[u8; KEY_SIZE]) -> Hasher {
    let mut bkey: [u8; 32] = [0u8; 32];
    bkey[..16].copy_from_slice(&key[..]);
    Hasher::new_keyed(&bkey)
}
