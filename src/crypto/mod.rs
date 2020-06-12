mod tree;

pub use tree::TreePRF;

pub use blake3::{Hash, Hasher};

// we target 128-bits of security
pub const KEY_SIZE: usize = 16;

// benchmark to compare the performance of cryptographic primitives
#[cfg(test)]
#[cfg(feature = "unstable")]
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
