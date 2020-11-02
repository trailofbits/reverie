use super::*;

use std::mem::MaybeUninit;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct GF2P64 {}

impl GF2P64 {
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

    #[target_feature(enable = "avx2")]
    #[cfg(target_feature = "avx2")]
    unsafe fn convert_inv_avx2(
        dst: &mut [<Self as Domain>::Batch],
        src: &[<Self as Domain>::Sharing],
    ) {
        // NOTE(ww): This is safe, since we fully initialize sharings immediately below.
        // We could probably avoid this with an impl `From<Domain::Sharing> for ...`
        #[allow(clippy::uninit_assumed_init)]
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

        macro_rules! pack8x4 {
            ( $x:expr, $y:expr ) => {
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

        // transpose 4 batches at a time, byte-by-byte
        for i in (0..(<Self as Domain>::Sharing::DIMENSION / 8)).step_by(4) {
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
                let masks: [_; 8] = [
                    _mm256_movemask_epi8(v[0]),
                    _mm256_movemask_epi8(v[1]),
                    _mm256_movemask_epi8(v[2]),
                    _mm256_movemask_epi8(v[3]),
                    //
                    _mm256_movemask_epi8(v[4]),
                    _mm256_movemask_epi8(v[5]),
                    _mm256_movemask_epi8(v[6]),
                    _mm256_movemask_epi8(v[7]),
                ];

                dst[idx] = BitBatch([
                    (masks[0] >> 24) as u8,
                    (masks[1] >> 24) as u8,
                    (masks[2] >> 24) as u8,
                    (masks[3] >> 24) as u8,
                    (masks[4] >> 24) as u8,
                    (masks[5] >> 24) as u8,
                    (masks[6] >> 24) as u8,
                    (masks[7] >> 24) as u8,
                ]);

                dst[idx + 8] = BitBatch([
                    (masks[0] >> 16) as u8,
                    (masks[1] >> 16) as u8,
                    (masks[2] >> 16) as u8,
                    (masks[3] >> 16) as u8,
                    (masks[4] >> 16) as u8,
                    (masks[5] >> 16) as u8,
                    (masks[6] >> 16) as u8,
                    (masks[7] >> 16) as u8,
                ]);

                dst[idx + 16] = BitBatch([
                    (masks[0] >> 8) as u8,
                    (masks[1] >> 8) as u8,
                    (masks[2] >> 8) as u8,
                    (masks[3] >> 8) as u8,
                    (masks[4] >> 8) as u8,
                    (masks[5] >> 8) as u8,
                    (masks[6] >> 8) as u8,
                    (masks[7] >> 8) as u8,
                ]);

                dst[idx + 24] = BitBatch([
                    masks[0] as u8,
                    masks[1] as u8,
                    masks[2] as u8,
                    masks[3] as u8,
                    masks[4] as u8,
                    masks[5] as u8,
                    masks[6] as u8,
                    masks[7] as u8,
                ]);

                for i in 0..8 {
                    v[i] = _mm256_add_epi8(v[i], v[i]);
                }

                idx += 1;
            }
        }
    }

    #[target_feature(enable = "sse2")]
    #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
    unsafe fn convert_inv_sse2(
        dst: &mut [<Self as Domain>::Batch],
        src: &[<Self as Domain>::Sharing],
    ) {
        // NOTE(ww): This is safe, since we fully initialize sharings immediately below.
        // We could probably avoid this with an impl `From<Domain::Sharing> for ...`
        #[allow(clippy::uninit_assumed_init)]
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

        macro_rules! pack8x2 {
            ( $x:expr, $y:expr ) => {
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
        for i in (0..(<Self as Domain>::Sharing::DIMENSION / 8)).step_by(2) {
            // pack 2 bytes from 64 different players
            let mut vecs: [__m128i; 8] = [
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
                let masks: [_; 8] = [
                    _mm_movemask_epi8(vecs[0]),
                    _mm_movemask_epi8(vecs[1]),
                    _mm_movemask_epi8(vecs[2]),
                    _mm_movemask_epi8(vecs[3]),
                    //
                    _mm_movemask_epi8(vecs[4]),
                    _mm_movemask_epi8(vecs[5]),
                    _mm_movemask_epi8(vecs[6]),
                    _mm_movemask_epi8(vecs[7]),
                ];

                dst[idx] = BitBatch([
                    (masks[0] >> 8) as u8,
                    (masks[1] >> 8) as u8,
                    (masks[2] >> 8) as u8,
                    (masks[3] >> 8) as u8,
                    (masks[4] >> 8) as u8,
                    (masks[5] >> 8) as u8,
                    (masks[6] >> 8) as u8,
                    (masks[7] >> 8) as u8,
                ]);

                dst[idx + 8] = BitBatch([
                    masks[0] as u8,
                    masks[1] as u8,
                    masks[2] as u8,
                    masks[3] as u8,
                    masks[4] as u8,
                    masks[5] as u8,
                    masks[6] as u8,
                    masks[7] as u8,
                ]);

                for vec in &mut vecs {
                    *vec = _mm_add_epi8(*vec, *vec);
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

    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        assert_eq!(src.len(), Self::Batch::DIMENSION);
        assert_eq!(dst.len(), Self::Sharing::DIMENSION);

        // If we have AVX2, prefer it.
        #[cfg(target_feature = "avx2")]
        return unsafe { Self::convert_inv_avx2(dst, src) };

        // Otherwise, fall back on SSE2.
        #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
        return unsafe { Self::convert_inv_sse2(dst, src) };

        // Without either, fail.
        #[cfg(not(any(target_feature = "avx2", target_feature = "sse2")))]
        compile_error!("unsupported platform: requires x86{-64} with SSE2 or AVX2");
    }
}
