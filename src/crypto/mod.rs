mod merkle;
mod ring;
mod tree;

use std::io;

use crate::util::*;

use rand_chacha::rand_core::{RngCore as _, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand_core::{self, RngCore};

use serde::de::{Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeTuple, Serializer};
use serde::{Deserialize, Serialize};

use std::fmt;

pub use merkle::{MerkleSet, MerkleSetProof};
pub use ring::RingHasher;
pub use tree::TreePrf;

// we target 128-bits of PQ security
pub const KEY_SIZE: usize = 32;

pub const HASH_SIZE: usize = 32;

#[derive(Debug, Default, Clone)]
pub struct Hasher(blake3::Hasher);

#[derive(Clone, PartialEq, Eq)]
pub struct Hash(blake3::Hash);

impl fmt::Debug for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_fmt(format_args!("{:?}", self.0))
    }
}

#[derive(Debug)]
pub struct Prg(ChaCha12Rng);

pub fn commit(key: &[u8; KEY_SIZE], value: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(value);
    Hash(hasher.finalize())
}

pub fn kdf(context: &str, key_material: &[u8]) -> [u8; KEY_SIZE] {
    let mut output = [0u8; KEY_SIZE];
    blake3::derive_key(context, key_material, &mut output);
    output
}

pub fn hash(material: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(material);
    hasher.finalize()
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_bytes()[..]
    }
}

impl Hash {
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        self.0.as_bytes()
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tup = serializer.serialize_tuple(HASH_SIZE)?;
        for b in self.0.as_bytes().iter() {
            tup.serialize_element(b)?;
        }
        tup.end()
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVistor();
        impl<'de> Visitor<'de> for HashVistor {
            type Value = Hash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a sequence of flat nodes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut hash: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
                for b in hash.iter_mut() {
                    *b = seq.next_element()?.unwrap();
                }
                Ok(Hash(blake3::Hash::from(hash)))
            }
        }
        deserializer.deserialize_tuple(HASH_SIZE, HashVistor())
    }
}

impl Hasher {
    pub fn new() -> Hasher {
        Hasher(blake3::Hasher::new())
    }

    pub fn new_keyed(key: &[u8; KEY_SIZE]) -> Hasher {
        Hasher(blake3::Hasher::new_keyed(key))
    }

    pub fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    pub fn finalize(&self) -> Hash {
        Hash(self.0.finalize())
    }
}
impl io::Write for Hasher {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.0.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Prg {
    pub fn new(seed: [u8; KEY_SIZE]) -> Self {
        Self(ChaCha12Rng::from_seed(seed))
    }
}

impl RngCore for Prg {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }

    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
}

// benchmark to compare the performance of cryptographic primitives
#[cfg(test)]
mod tests {
    use test::Bencher;

    use aes::{Aes128, BlockCipher, NewBlockCipher};

    use blake3::Hasher;

    use cipher::generic_array::GenericArray;

    #[bench]
    fn bench_aes128(b: &mut Bencher) {
        let key = [0u8; 16];
        let mut blk = test::black_box([0u8; 16]);
        let mut slc = GenericArray::from_mut_slice(&mut blk);
        let bc = Aes128::new(GenericArray::from_slice(&key));

        // every step produces 64-bytes of pseudo random
        b.iter(|| {
            bc.encrypt_block(&mut slc);
            bc.encrypt_block(&mut slc);
            bc.encrypt_block(&mut slc);
            bc.encrypt_block(&mut slc);
        });
    }

    #[bench]
    fn bench_blake3(b: &mut Bencher) {
        let key = [0u8; 32];
        let hasher = Hasher::new_keyed(&key);
        let mut reader = hasher.finalize_xof();

        // every step produces 64-bytes of pseudo random
        b.iter(|| {
            let mut output = test::black_box([0u8; 64]);
            reader.fill(&mut output[..]);
        })
    }
}
