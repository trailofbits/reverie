use super::*;

use std::mem::MaybeUninit;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct GF2P64 {}

impl GF2P64 {
    // // x86 / x86_64 SSE, MMX impl.
    // #[target_feature(enable = "sse")]
    // #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    // unsafe fn convert_sse(dst: &mut [<Self as Domain>::Sharing], src: &[<Self as Domain>::Batch]) {
    //     // do a single range-check up front
    //     assert!(dst.len() >= <Self as Domain>::Batch::DIMENSION);

    //     // transpose batch, byte-by-byte
    //     for i in 0..BATCH_SIZE_BYTES {
    //         // pack 1 byte from 64 different players
    //         let mut v: [__m64; 8] = [
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x00).0[i] as i8,
    //                 src.get_unchecked(0x01).0[i] as i8,
    //                 src.get_unchecked(0x02).0[i] as i8,
    //                 src.get_unchecked(0x03).0[i] as i8,
    //                 src.get_unchecked(0x04).0[i] as i8,
    //                 src.get_unchecked(0x05).0[i] as i8,
    //                 src.get_unchecked(0x06).0[i] as i8,
    //                 src.get_unchecked(0x07).0[i] as i8,
    //             ),
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x08).0[i] as i8,
    //                 src.get_unchecked(0x09).0[i] as i8,
    //                 src.get_unchecked(0x0a).0[i] as i8,
    //                 src.get_unchecked(0x0b).0[i] as i8,
    //                 src.get_unchecked(0x0c).0[i] as i8,
    //                 src.get_unchecked(0x0d).0[i] as i8,
    //                 src.get_unchecked(0x0e).0[i] as i8,
    //                 src.get_unchecked(0x0f).0[i] as i8,
    //             ),
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x10).0[i] as i8,
    //                 src.get_unchecked(0x11).0[i] as i8,
    //                 src.get_unchecked(0x12).0[i] as i8,
    //                 src.get_unchecked(0x13).0[i] as i8,
    //                 src.get_unchecked(0x14).0[i] as i8,
    //                 src.get_unchecked(0x15).0[i] as i8,
    //                 src.get_unchecked(0x16).0[i] as i8,
    //                 src.get_unchecked(0x17).0[i] as i8,
    //             ),
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x18).0[i] as i8,
    //                 src.get_unchecked(0x19).0[i] as i8,
    //                 src.get_unchecked(0x1a).0[i] as i8,
    //                 src.get_unchecked(0x1b).0[i] as i8,
    //                 src.get_unchecked(0x1c).0[i] as i8,
    //                 src.get_unchecked(0x1d).0[i] as i8,
    //                 src.get_unchecked(0x1e).0[i] as i8,
    //                 src.get_unchecked(0x1f).0[i] as i8,
    //             ),
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x20).0[i] as i8,
    //                 src.get_unchecked(0x21).0[i] as i8,
    //                 src.get_unchecked(0x22).0[i] as i8,
    //                 src.get_unchecked(0x23).0[i] as i8,
    //                 src.get_unchecked(0x24).0[i] as i8,
    //                 src.get_unchecked(0x25).0[i] as i8,
    //                 src.get_unchecked(0x26).0[i] as i8,
    //                 src.get_unchecked(0x27).0[i] as i8,
    //             ),
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x28).0[i] as i8,
    //                 src.get_unchecked(0x29).0[i] as i8,
    //                 src.get_unchecked(0x2a).0[i] as i8,
    //                 src.get_unchecked(0x2b).0[i] as i8,
    //                 src.get_unchecked(0x2c).0[i] as i8,
    //                 src.get_unchecked(0x2d).0[i] as i8,
    //                 src.get_unchecked(0x2e).0[i] as i8,
    //                 src.get_unchecked(0x2f).0[i] as i8,
    //             ),
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x30).0[i] as i8,
    //                 src.get_unchecked(0x31).0[i] as i8,
    //                 src.get_unchecked(0x32).0[i] as i8,
    //                 src.get_unchecked(0x33).0[i] as i8,
    //                 src.get_unchecked(0x34).0[i] as i8,
    //                 src.get_unchecked(0x35).0[i] as i8,
    //                 src.get_unchecked(0x36).0[i] as i8,
    //                 src.get_unchecked(0x37).0[i] as i8,
    //             ),
    //             _mm_set_pi8(
    //                 src.get_unchecked(0x38).0[i] as i8,
    //                 src.get_unchecked(0x39).0[i] as i8,
    //                 src.get_unchecked(0x3a).0[i] as i8,
    //                 src.get_unchecked(0x3b).0[i] as i8,
    //                 src.get_unchecked(0x3c).0[i] as i8,
    //                 src.get_unchecked(0x3d).0[i] as i8,
    //                 src.get_unchecked(0x3e).0[i] as i8,
    //                 src.get_unchecked(0x3f).0[i] as i8,
    //             ),
    //         ];

    //         // calculate the 8 sharings
    //         let mut idx = i * 8;

    //         for _ in 0..8 {
    //             let mut res: [u8; 8] = [0u8; 8];

    //             for i in 0..8 {
    //                 res[i] = (_m_pmovmskb(v[i]) & 0xff) as u8;
    //                 v[i] = _mm_add_pi8(v[i], v[i]);
    //             }

    //             dst[idx] = BitSharing64(u64::from_le_bytes(res));
    //             idx += 1;
    //         }
    //     }
    // }

    // x86 / x86_64 AVX2 impl.
    #[target_feature(enable = "avx2")]
    #[cfg(target_feature = "avx2")]
    unsafe fn convert_avx2(dst: &mut [<Self as Domain>::Sharing], src: &[<Self as Domain>::Batch]) {
        // do a single range-check up front
        assert!(dst.len() >= <Self as Domain>::Batch::DIMENSION);

        macro_rules! pack {
            ($x:expr, $y:expr) => {
                src.get_unchecked($x).0[$y] as i8
            };
        }

        macro_rules! pack8x4 {
            ($x:expr, $y:expr) => {
                _mm256_set_epi8(
                    pack!($x, $y),
                    pack!($x + 1, $y),
                    pack!($x + 2, $y),
                    pack!($x + 3, $y),
                    pack!($x + 4, $y),
                    pack!($x + 5, $y),
                    pack!($x + 6, $y),
                    pack!($x + 7, $y),
                    pack!($x, $y + 1),
                    pack!($x + 1, $y + 1),
                    pack!($x + 2, $y + 1),
                    pack!($x + 3, $y + 1),
                    pack!($x + 4, $y + 1),
                    pack!($x + 5, $y + 1),
                    pack!($x + 6, $y + 1),
                    pack!($x + 7, $y + 1),
                    pack!($x, $y + 2),
                    pack!($x + 1, $y + 2),
                    pack!($x + 2, $y + 2),
                    pack!($x + 3, $y + 2),
                    pack!($x + 4, $y + 2),
                    pack!($x + 5, $y + 2),
                    pack!($x + 6, $y + 2),
                    pack!($x + 7, $y + 2),
                    pack!($x, $y + 3),
                    pack!($x + 1, $y + 3),
                    pack!($x + 2, $y + 3),
                    pack!($x + 3, $y + 3),
                    pack!($x + 4, $y + 3),
                    pack!($x + 5, $y + 3),
                    pack!($x + 6, $y + 3),
                    pack!($x + 7, $y + 3),
                )
            };
        }

        // transpose four batches at a time, byte-by-byte
        for i in (0..BATCH_SIZE_BYTES).step_by(4) {
            // pack 4 bytes from 64 different players
            let mut v: [__m256i; 8] = [
                pack8x4!(0x00, i),
                pack8x4!(0x08, i),
                pack8x4!(0x10, i),
                pack8x4!(0x18, i),
                pack8x4!(0x20, i),
                pack8x4!(0x28, i),
                pack8x4!(0x30, i),
                pack8x4!(0x38, i),
            ];

            // calculate the 8 sharings
            let mut idx = i * 8;
            for _ in 0..8 {
                let mut res_0: [u8; 8] = [0u8; 8];
                let mut res_1: [u8; 8] = [0u8; 8];
                let mut res_2: [u8; 8] = [0u8; 8];
                let mut res_3: [u8; 8] = [0u8; 8];

                for i in 0..8 {
                    let mask = _mm256_movemask_epi8(v[i]);
                    res_0[i] = (mask >> 24) as u8;
                    res_1[i] = (mask >> 16) as u8;
                    res_2[i] = (mask >> 8) as u8;
                    res_3[i] = mask as u8;
                    v[i] = _mm256_add_epi8(v[i], v[i]);
                }

                dst[idx] = BitSharing64(u64::from_le_bytes(res_0));
                dst[idx + 8] = BitSharing64(u64::from_le_bytes(res_1));
                dst[idx + 16] = BitSharing64(u64::from_le_bytes(res_2));
                dst[idx + 24] = BitSharing64(u64::from_le_bytes(res_3));
                idx += 1;
            }
        }
    }

    // x86 / x86_64 SSE2 impl.
    #[target_feature(enable = "sse2")]
    #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
    unsafe fn convert_sse2(dst: &mut [<Self as Domain>::Sharing], src: &[<Self as Domain>::Batch]) {
        // do a single range-check up front
        assert!(dst.len() >= <Self as Domain>::Batch::DIMENSION);

        macro_rules! pack {
            ($x:expr, $y:expr) => {
                src.get_unchecked($x).0[$y] as i8
            };
        }

        macro_rules! pack8x2 {
            ($x:expr, $y:expr) => {
                _mm_set_epi8(
                    pack!($x, $y),
                    pack!($x + 1, $y),
                    pack!($x + 2, $y),
                    pack!($x + 3, $y),
                    pack!($x + 4, $y),
                    pack!($x + 5, $y),
                    pack!($x + 6, $y),
                    pack!($x + 7, $y),
                    pack!($x, $y + 1),
                    pack!($x + 1, $y + 1),
                    pack!($x + 2, $y + 1),
                    pack!($x + 3, $y + 1),
                    pack!($x + 4, $y + 1),
                    pack!($x + 5, $y + 1),
                    pack!($x + 6, $y + 1),
                    pack!($x + 7, $y + 1),
                )
            };
        }

        // transpose two batches at a time, byte-by-byte
        for i in (0..BATCH_SIZE_BYTES).step_by(2) {
            // pack 2 bytes from 64 different players
            let mut v: [__m128i; 8] = [
                pack8x2!(0x00, i),
                pack8x2!(0x08, i),
                pack8x2!(0x10, i),
                pack8x2!(0x18, i),
                pack8x2!(0x20, i),
                pack8x2!(0x28, i),
                pack8x2!(0x30, i),
                pack8x2!(0x38, i),
            ];

            // calculate the 8 sharings
            let mut idx = i * 8;
            for _ in 0..8 {
                let mut res_lo: [u8; 8] = [0u8; 8];
                let mut res_hi: [u8; 8] = [0u8; 8];

                for i in 0..8 {
                    let mask = _mm_movemask_epi8(v[i]);
                    res_lo[i] = (mask >> 8) as u8;
                    res_hi[i] = mask as u8;
                    v[i] = _mm_add_epi8(v[i], v[i]);
                }

                dst[idx] = BitSharing64(u64::from_le_bytes(res_lo));
                dst[idx + 8] = BitSharing64(u64::from_le_bytes(res_hi));
                idx += 1;
            }
        }
    }

    #[target_feature(enable = "sse")]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe fn convert_inv_sse(
        dst: &mut [<Self as Domain>::Batch],
        src: &[<Self as Domain>::Sharing],
    ) {
        let mut sharings: [[u8; 8]; <Self as Domain>::Batch::DIMENSION] =
            MaybeUninit::uninit().assume_init();

        for i in 0..<Self as Domain>::Batch::DIMENSION {
            sharings[i] = src[i].0.to_le_bytes();
        }

        macro_rules! pack {
            ( $x:expr, $y:expr ) => {
                *sharings.get_unchecked($x).get_unchecked($y) as i8
            };
        }

        macro_rules! pack8 {
            ( $x:expr, $y:expr ) => {
                _mm_set_pi8(
                    pack!($x, $y),
                    pack!($x + 1, $y),
                    pack!($x + 2, $y),
                    pack!($x + 3, $y),
                    pack!($x + 4, $y),
                    pack!($x + 5, $y),
                    pack!($x + 6, $y),
                    pack!($x + 7, $y),
                )
            };
        }

        // transpose batch, byte-by-byte
        for i in 0..(<Self as Domain>::Sharing::DIMENSION / 8) {
            // pack 1 byte from 64 different players
            let mut v: [__m64; 8] = [
                pack8!(0x00, i),
                pack8!(0x08, i),
                pack8!(0x10, i),
                pack8!(0x18, i),
                pack8!(0x20, i),
                pack8!(0x28, i),
                pack8!(0x30, i),
                pack8!(0x38, i),
            ];

            // calculate the 8 sharings
            let mut idx = i * 8;

            for _ in 0..8 {
                dst[idx] = BitBatch([
                    (_m_pmovmskb(*v.get_unchecked(0)) & 0xff) as u8,
                    (_m_pmovmskb(*v.get_unchecked(1)) & 0xff) as u8,
                    (_m_pmovmskb(*v.get_unchecked(2)) & 0xff) as u8,
                    (_m_pmovmskb(*v.get_unchecked(3)) & 0xff) as u8,
                    //
                    (_m_pmovmskb(*v.get_unchecked(4)) & 0xff) as u8,
                    (_m_pmovmskb(*v.get_unchecked(5)) & 0xff) as u8,
                    (_m_pmovmskb(*v.get_unchecked(6)) & 0xff) as u8,
                    (_m_pmovmskb(*v.get_unchecked(7)) & 0xff) as u8,
                ]);

                for i in 0..8 {
                    v[i] = _mm_add_pi8(v[i], v[i]);
                }

                idx += 1;
            }
        }
    }
}

impl Domain for GF2P64 {
    type Scalar = BitScalar;
    type Batch = BitBatch;
    type Sharing = BitSharing64;

    const PLAYERS: usize = 64;
    const PREPROCESSING_REPETITIONS: usize = 631;
    const ONLINE_REPETITIONS: usize = 23;

    #[inline(always)]
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        // do a single bounds check up front
        assert_eq!(src.len(), Self::PLAYERS);

        // If we have AVX2, prefer it.
        #[cfg(target_feature = "avx2")]
        return unsafe { Self::convert_avx2(dst, src) };

        // Otherwise, fall back on SSE2.
        #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
        return unsafe { Self::convert_sse2(dst, src) };

        // Without either, fail.
        #[cfg(not(any(target_feature = "avx2", target_feature = "sse2")))]
        compile_error!("unsupported platform: requires x86{-64} with SSE2 or AVX2");
    }

    #[inline(always)]
    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        assert_eq!(src.len(), Self::Batch::DIMENSION);
        assert_eq!(dst.len(), Self::Sharing::DIMENSION);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return unsafe { Self::convert_inv_sse(dst, src) };

        // Without either, fail.
        #[cfg(not(any(target_feature = "avx2", target_feature = "sse2")))]
        compile_error!("unsupported platform: requires x86{-64} with SSE2 or AVX2");
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::*;

    use rand::thread_rng;
    use rand::Rng;
    use test::{black_box, Bencher};

    #[bench]
    fn bench_gf2p8_convert(b: &mut Bencher) {
        let mut rng = thread_rng();

        let mut v: [BitBatch; 8] = [
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
}
