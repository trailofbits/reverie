mod ring;
mod tree;

use crate::util::*;

use rand_chacha::ChaCha12Rng;
use rand_core::{Error, RngCore, SeedableRng};

pub use blake3::{Hash, Hasher, OutputReader};

pub use ring::RingHasher;

pub use tree::TreePRF;

// we target 128-bits of PQ security
pub const KEY_SIZE: usize = 32;

pub const HASH_SIZE: usize = 32;

pub struct PRG(ChaCha12Rng);

impl PRG {
    pub fn new(seed: [u8; KEY_SIZE]) -> Self {
        Self(ChaCha12Rng::from_seed(seed))
    }
}

impl RngCore for PRG {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
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

    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;
    use aes::Aes128;

    use blake3::Hasher;

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
