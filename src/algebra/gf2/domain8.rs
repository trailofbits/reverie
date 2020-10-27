use super::*;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct GF2P8 {}

impl GF2P8 {
    // This codes assumes that a bounds check has been done prior to the call.
    #[inline(always)]
    #[cfg(any(all(not(target_feature = "avx2"), not(target_feature = "sse2")), test))]
    fn convert_generic(dst: &mut [BitSharing8], src: &[BitBatch]) {
        let mut idx = 0;
        for i in 0..BATCH_SIZE_BYTES {
            // extract a byte from each player batch
            let mut shares: [u8; 8] = unsafe {
                [
                    src.get_unchecked(0).0[i],
                    src.get_unchecked(1).0[i],
                    src.get_unchecked(2).0[i],
                    src.get_unchecked(3).0[i],
                    src.get_unchecked(4).0[i],
                    src.get_unchecked(5).0[i],
                    src.get_unchecked(6).0[i],
                    src.get_unchecked(7).0[i],
                ]
            };

            // extract 8 sharings from a byte-sized batch from each player
            for _ in 0..8 {
                // pack a single sharing
                let mut r: u8 = 0;
                for j in 0..8 {
                    r <<= 1;
                    r |= shares[j] >> 7;
                    shares[j] <<= 1;
                }

                // write a single sharing to the output
                unsafe { *dst.get_unchecked_mut(idx) = BitSharing8(r) };
                idx += 1;
            }
        }
    }

    #[target_feature(enable = "avx2")]
    #[cfg(target_feature = "avx2")]
    unsafe fn convert_avx2(dst: &mut [BitSharing8], src: &[BitBatch]) {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;

        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // transpose four batches at a time, byte-by-byte
        for i in (0..BATCH_SIZE_BYTES).step_by(4) {
            // pack 4 bytes from 8 different shares
            let mut v = _mm256_set_epi8(
                src.get_unchecked(0).0[i] as i8,
                src.get_unchecked(1).0[i] as i8,
                src.get_unchecked(2).0[i] as i8,
                src.get_unchecked(3).0[i] as i8,
                src.get_unchecked(4).0[i] as i8,
                src.get_unchecked(5).0[i] as i8,
                src.get_unchecked(6).0[i] as i8,
                src.get_unchecked(7).0[i] as i8,
                src.get_unchecked(0).0[i + 1] as i8,
                src.get_unchecked(1).0[i + 1] as i8,
                src.get_unchecked(2).0[i + 1] as i8,
                src.get_unchecked(3).0[i + 1] as i8,
                src.get_unchecked(4).0[i + 1] as i8,
                src.get_unchecked(5).0[i + 1] as i8,
                src.get_unchecked(6).0[i + 1] as i8,
                src.get_unchecked(7).0[i + 1] as i8,
                src.get_unchecked(0).0[i + 2] as i8,
                src.get_unchecked(1).0[i + 2] as i8,
                src.get_unchecked(2).0[i + 2] as i8,
                src.get_unchecked(3).0[i + 2] as i8,
                src.get_unchecked(4).0[i + 2] as i8,
                src.get_unchecked(5).0[i + 2] as i8,
                src.get_unchecked(6).0[i + 2] as i8,
                src.get_unchecked(7).0[i + 2] as i8,
                src.get_unchecked(0).0[i + 3] as i8,
                src.get_unchecked(1).0[i + 3] as i8,
                src.get_unchecked(2).0[i + 3] as i8,
                src.get_unchecked(3).0[i + 3] as i8,
                src.get_unchecked(4).0[i + 3] as i8,
                src.get_unchecked(5).0[i + 3] as i8,
                src.get_unchecked(6).0[i + 3] as i8,
                src.get_unchecked(7).0[i + 3] as i8,
            );

            // calculate the 8 sharings
            let mut idx = i * 8;
            for _ in 0..8 {
                let mask = _mm256_movemask_epi8(v);
                dst[idx] = BitSharing8((mask >> 24) as u8);
                dst[idx + 8] = BitSharing8((mask >> 16) as u8);
                dst[idx + 16] = BitSharing8((mask >> 8) as u8);
                dst[idx + 24] = BitSharing8(mask as u8);
                v = _mm256_add_epi8(v, v);
                idx += 1;
            }

            // assert all bits consumed
            debug_assert_eq!(
                {
                    let v = _mm256_add_epi8(v, v);
                    _mm256_movemask_epi8(v)
                },
                0
            )
        }
    }

    #[target_feature(enable = "sse2")]
    #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
    unsafe fn convert_sse2(dst: &mut [BitSharing8], src: &[BitBatch]) {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;

        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // transpose four batches at a time, byte-by-byte
        for i in (0..BATCH_SIZE_BYTES).step_by(2) {
            // pack 2 bytes from 8 different shares
            let mut v = _mm_set_epi8(
                src.get_unchecked(0).0[i] as i8,
                src.get_unchecked(1).0[i] as i8,
                src.get_unchecked(2).0[i] as i8,
                src.get_unchecked(3).0[i] as i8,
                src.get_unchecked(4).0[i] as i8,
                src.get_unchecked(5).0[i] as i8,
                src.get_unchecked(6).0[i] as i8,
                src.get_unchecked(7).0[i] as i8,
                src.get_unchecked(0).0[i + 1] as i8,
                src.get_unchecked(1).0[i + 1] as i8,
                src.get_unchecked(2).0[i + 1] as i8,
                src.get_unchecked(3).0[i + 1] as i8,
                src.get_unchecked(4).0[i + 1] as i8,
                src.get_unchecked(5).0[i + 1] as i8,
                src.get_unchecked(6).0[i + 1] as i8,
                src.get_unchecked(7).0[i + 1] as i8,
            );

            // calculate the 8 sharings
            let mut idx = i * 8;
            for _ in 0..8 {
                let mask = _mm_movemask_epi8(v);
                dst[idx] = BitSharing8((mask >> 8) as u8);
                dst[idx + 8] = BitSharing8(mask as u8);
                v = _mm_add_epi8(v, v);
                idx += 1;
            }

            // assert all bits consumed
            debug_assert_eq!(
                {
                    let v = _mm_add_epi8(v, v);
                    _mm_movemask_epi8(v)
                },
                0
            )
        }
    }

    #[target_feature(enable = "avx2")]
    #[cfg(target_feature = "avx2")]
    unsafe fn convert_inv_avx2(dst: &mut [BitBatch], src: &[BitSharing8]) {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;

        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // use 2 x 256-bit registers
        let mut v: [__m256i; 2] = [
            _mm256_set_epi8(
                src[0x00].0 as i8,
                src[0x01].0 as i8,
                src[0x02].0 as i8,
                src[0x03].0 as i8,
                src[0x04].0 as i8,
                src[0x05].0 as i8,
                src[0x06].0 as i8,
                src[0x07].0 as i8,
                src[0x08].0 as i8,
                src[0x09].0 as i8,
                src[0x0a].0 as i8,
                src[0x0b].0 as i8,
                src[0x0c].0 as i8,
                src[0x0d].0 as i8,
                src[0x0e].0 as i8,
                src[0x0f].0 as i8,
                src[0x10].0 as i8,
                src[0x11].0 as i8,
                src[0x12].0 as i8,
                src[0x13].0 as i8,
                src[0x14].0 as i8,
                src[0x15].0 as i8,
                src[0x16].0 as i8,
                src[0x17].0 as i8,
                src[0x18].0 as i8,
                src[0x19].0 as i8,
                src[0x1a].0 as i8,
                src[0x1b].0 as i8,
                src[0x1c].0 as i8,
                src[0x1d].0 as i8,
                src[0x1e].0 as i8,
                src[0x1f].0 as i8,
            ),
            _mm256_set_epi8(
                src[0x20].0 as i8,
                src[0x21].0 as i8,
                src[0x22].0 as i8,
                src[0x23].0 as i8,
                src[0x24].0 as i8,
                src[0x25].0 as i8,
                src[0x26].0 as i8,
                src[0x27].0 as i8,
                src[0x28].0 as i8,
                src[0x29].0 as i8,
                src[0x2a].0 as i8,
                src[0x2b].0 as i8,
                src[0x2c].0 as i8,
                src[0x2d].0 as i8,
                src[0x2e].0 as i8,
                src[0x2f].0 as i8,
                src[0x30].0 as i8,
                src[0x31].0 as i8,
                src[0x32].0 as i8,
                src[0x33].0 as i8,
                src[0x34].0 as i8,
                src[0x35].0 as i8,
                src[0x36].0 as i8,
                src[0x37].0 as i8,
                src[0x38].0 as i8,
                src[0x39].0 as i8,
                src[0x3a].0 as i8,
                src[0x3b].0 as i8,
                src[0x3c].0 as i8,
                src[0x3d].0 as i8,
                src[0x3e].0 as i8,
                src[0x3f].0 as i8,
            ),
        ];

        for p in 0..<Self as Domain>::Sharing::DIMENSION {
            for i in 0..2 {
                let base = i * 4;
                let mask = _mm256_movemask_epi8(v[i]);
                (dst[p].0)[base] = (mask >> 24) as u8;
                (dst[p].0)[base + 1] = (mask >> 16) as u8;
                (dst[p].0)[base + 2] = (mask >> 8) as u8;
                (dst[p].0)[base + 3] = mask as u8;
                v[i] = _mm256_add_epi8(v[i], v[i]);
            }
        }
    }

    #[target_feature(enable = "sse2")]
    #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
    unsafe fn convert_inv_sse2(dst: &mut [BitBatch], src: &[BitSharing8]) {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;

        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // use 4 x 128-bit registers
        let mut v: [__m128i; 4] = [
            _mm_set_epi8(
                src[0x00].0 as i8,
                src[0x01].0 as i8,
                src[0x02].0 as i8,
                src[0x03].0 as i8,
                src[0x04].0 as i8,
                src[0x05].0 as i8,
                src[0x06].0 as i8,
                src[0x07].0 as i8,
                src[0x08].0 as i8,
                src[0x09].0 as i8,
                src[0x0a].0 as i8,
                src[0x0b].0 as i8,
                src[0x0c].0 as i8,
                src[0x0d].0 as i8,
                src[0x0e].0 as i8,
                src[0x0f].0 as i8,
            ),
            _mm_set_epi8(
                src[0x10].0 as i8,
                src[0x11].0 as i8,
                src[0x12].0 as i8,
                src[0x13].0 as i8,
                src[0x14].0 as i8,
                src[0x15].0 as i8,
                src[0x16].0 as i8,
                src[0x17].0 as i8,
                src[0x18].0 as i8,
                src[0x19].0 as i8,
                src[0x1a].0 as i8,
                src[0x1b].0 as i8,
                src[0x1c].0 as i8,
                src[0x1d].0 as i8,
                src[0x1e].0 as i8,
                src[0x1f].0 as i8,
            ),
            _mm_set_epi8(
                src[0x20].0 as i8,
                src[0x21].0 as i8,
                src[0x22].0 as i8,
                src[0x23].0 as i8,
                src[0x24].0 as i8,
                src[0x25].0 as i8,
                src[0x26].0 as i8,
                src[0x27].0 as i8,
                src[0x28].0 as i8,
                src[0x29].0 as i8,
                src[0x2a].0 as i8,
                src[0x2b].0 as i8,
                src[0x2c].0 as i8,
                src[0x2d].0 as i8,
                src[0x2e].0 as i8,
                src[0x2f].0 as i8,
            ),
            _mm_set_epi8(
                src[0x30].0 as i8,
                src[0x31].0 as i8,
                src[0x32].0 as i8,
                src[0x33].0 as i8,
                src[0x34].0 as i8,
                src[0x35].0 as i8,
                src[0x36].0 as i8,
                src[0x37].0 as i8,
                src[0x38].0 as i8,
                src[0x39].0 as i8,
                src[0x3a].0 as i8,
                src[0x3b].0 as i8,
                src[0x3c].0 as i8,
                src[0x3d].0 as i8,
                src[0x3e].0 as i8,
                src[0x3f].0 as i8,
            ),
        ];

        for p in 0..<Self as Domain>::Sharing::DIMENSION {
            for i in 0..4 {
                let base = i * 2;
                let mask = _mm_movemask_epi8(v[i]);
                (dst[p].0)[base] = (mask >> 8) as u8;
                (dst[p].0)[base + 1] = mask as u8;
                v[i] = _mm_add_epi8(v[i], v[i]);
            }
        }
    }

    // This codes assumes that a bounds check has been done prior to the call.
    #[inline(always)]
    #[cfg(any(all(not(target_feature = "avx2"), not(target_feature = "sse2")), test))]
    fn convert_inv_generic(dst: &mut [BitBatch], src: &[BitSharing8]) {
        for i in 0..BATCH_SIZE_BYTES {
            // for every byte in the batch
            let off = i * 8;
            for j in 0..BitSharing8::DIMENSION {
                // for every player
                let s = BitSharing8::DIMENSION - 1 - j;
                let mut b = (src[off].0 >> s) & 1;
                b <<= 1;
                b |= (src[off + 1].0 >> s) & 1;
                b <<= 1;
                b |= (src[off + 2].0 >> s) & 1;
                b <<= 1;
                b |= (src[off + 3].0 >> s) & 1;
                b <<= 1;
                b |= (src[off + 4].0 >> s) & 1;
                b <<= 1;
                b |= (src[off + 5].0 >> s) & 1;
                b <<= 1;
                b |= (src[off + 6].0 >> s) & 1;
                b <<= 1;
                b |= (src[off + 7].0 >> s) & 1;
                dst[j].0[i] = b;
            }
        }
    }
}

impl Domain for GF2P8 {
    type Scalar = BitScalar;
    type Batch = BitBatch;
    type Sharing = BitSharing8;

    const PLAYERS: usize = 8;
    const PREPROCESSING_REPETITIONS: usize = 252;
    const ONLINE_REPETITIONS: usize = 44;

    #[inline(always)]
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        // do a single bounds check up front
        assert_eq!(src.len(), Self::PLAYERS);
        assert!(dst.len() >= Self::Batch::DIMENSION);

        // x86 specializations: prefer AVX2, then SSE2, falling back
        // on the unoptimized version.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(target_feature = "avx2")]
            return unsafe { Self::convert_avx2(dst, src) };

            #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
            return unsafe { Self::convert_sse2(dst, src) };

            #[cfg(not(any(target_feature = "sse2", target_feature = "avx2")))]
            return Self::convert_generic(dst, src);
        }

        // All other platforms: use the unoptimized version.
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        Self::convert_generic(dst, src);
    }

    // converts 64 sharings between 8 players to 8 batches of 64 sharings:
    // one batch per player.
    #[inline(always)]
    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        // there should be enough sharings to fill a batch
        assert_eq!(src.len(), Self::Batch::DIMENSION);

        // there will be one batch per player
        assert_eq!(dst.len(), Self::Sharing::DIMENSION);

        // x86 specializations: prefer AVX2, then SSE2, falling back
        // on the unoptimized version.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(target_feature = "avx2")]
            return unsafe { Self::convert_inv_avx2(dst, src) };

            #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
            return unsafe { Self::convert_inv_sse2(dst, src) };

            #[cfg(not(any(target_feature = "sse2", target_feature = "avx2")))]
            return Self::convert_inv_generic(dst, src);
        }

        // All other platforms: use the unoptimized version.
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        Self::convert_inv_generic(dst, src);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    // test the platform dependent optimized version against the generic implementation
    #[test]
    fn test_convert() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let batches: [_; 8] = [
                BitBatch::gen(&mut rng),
                BitBatch::gen(&mut rng),
                BitBatch::gen(&mut rng),
                BitBatch::gen(&mut rng),
                //
                BitBatch::gen(&mut rng),
                BitBatch::gen(&mut rng),
                BitBatch::gen(&mut rng),
                BitBatch::gen(&mut rng),
            ];

            let mut shares_1 = [BitSharing8::ZERO; 64];
            let mut shares_2 = [BitSharing8::ZERO; 64];
            GF2P8::convert(&mut shares_1, &batches);
            GF2P8::convert_generic(&mut shares_2, &batches);
            assert_eq!(&shares_1[..], &shares_2[..]);

            let mut batches_1 = [BitBatch::ZERO; 8];
            let mut batches_2 = [BitBatch::ZERO; 8];
            GF2P8::convert_inv(&mut batches_1, &shares_1);
            GF2P8::convert_inv_generic(&mut batches_2, &shares_1);
            assert_eq!(batches_1, batches);
            assert_eq!(batches_2, batches);
        }
    }
}

#[cfg(test)]
mod benchmark {
    use super::*;

    use rand::thread_rng;
    use ::test::{black_box, Bencher};

    #[bench]
    fn bench_gf2p8_convert(b: &mut Bencher) {
        let mut rng = thread_rng();

        let v: [BitBatch; 8] = [
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            //
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
        ];

        b.iter(|| {
            black_box({
                let mut sharing: [BitSharing8; 64] = [BitSharing8::ZERO; 64];
                GF2P8::convert(&mut sharing[..], &v[..]);
                sharing
            })
        });
    }

    #[bench]
    fn bench_gf2p8_convert_generic(b: &mut Bencher) {
        let mut rng = thread_rng();

        let v: [BitBatch; 8] = [
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            //
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
        ];

        b.iter(|| {
            black_box({
                let mut sharing: [BitSharing8; 64] = [BitSharing8::ZERO; 64];
                GF2P8::convert_generic(&mut sharing[..], &v[..]);
                sharing
            })
        });
    }

    #[bench]
    fn bench_gf2p8_convert_inv(b: &mut Bencher) {
        let mut rng = thread_rng();

        let batches: [_; 8] = [
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            //
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
        ];

        let mut shares = [BitSharing8::ZERO; 64];
        GF2P8::convert(&mut shares, &batches);

        b.iter(|| {
            black_box({
                let mut b = [BitBatch::ZERO; 8];
                GF2P8::convert_inv(&mut b, &shares);
                b
            })
        });
    }

    #[bench]
    fn bench_gf2p8_convert_inv_generic(b: &mut Bencher) {
        let mut rng = thread_rng();

        let batches: [_; 8] = [
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            //
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
            BitBatch::gen(&mut rng),
        ];

        let mut shares = [BitSharing8::ZERO; 64];
        GF2P8::convert(&mut shares, &batches);

        b.iter(|| {
            black_box({
                let mut b = [BitBatch::ZERO; 8];
                GF2P8::convert_inv_generic(&mut b, &shares);
                b
            })
        });
    }
}
