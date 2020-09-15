use super::*;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct GF2P8 {}

impl GF2P8 {
    // This codes assumes that a bounds heck has been done prior to the call.
    #[inline(always)]
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

    #[target_feature(enable = "sse")]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe fn convert_sse(dst: &mut [BitSharing8], src: &[BitBatch]) {
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // transpose batch, byte-by-byte
        for i in 0..BATCH_SIZE_BYTES {
            // pack 1 bytes from 8 different shar
            let mut v = _mm_set_pi8(
                src.get_unchecked(0).0[i] as i8,
                src.get_unchecked(1).0[i] as i8,
                src.get_unchecked(2).0[i] as i8,
                src.get_unchecked(3).0[i] as i8,
                src.get_unchecked(4).0[i] as i8,
                src.get_unchecked(5).0[i] as i8,
                src.get_unchecked(6).0[i] as i8,
                src.get_unchecked(7).0[i] as i8,
            );

            // calculate the 8 sharings
            let mut idx = i * 8;
            for _ in 0..8 {
                dst[idx] = BitSharing8((_m_pmovmskb(v) & 0xff) as u8);
                v = _mm_add_pi8(v, v);
                idx += 1;
            }

            // assert all bits consumed
            debug_assert_eq!(
                {
                    let v = _mm_add_pi8(v, v);
                    _m_pmovmskb(v)
                },
                0
            )
        }
    }

    #[target_feature(enable = "sse")]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe fn convert_inv_sse(dst: &mut [BitBatch], src: &[BitSharing8]) {
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // use 8 x 64-bit registers
        let mut v: [__m64; 8] = [
            _mm_set_pi8(
                src[0x00].0 as i8,
                src[0x01].0 as i8,
                src[0x02].0 as i8,
                src[0x03].0 as i8,
                src[0x04].0 as i8,
                src[0x05].0 as i8,
                src[0x06].0 as i8,
                src[0x07].0 as i8,
            ),
            _mm_set_pi8(
                src[0x08].0 as i8,
                src[0x09].0 as i8,
                src[0x0a].0 as i8,
                src[0x0b].0 as i8,
                src[0x0c].0 as i8,
                src[0x0d].0 as i8,
                src[0x0e].0 as i8,
                src[0x0f].0 as i8,
            ),
            _mm_set_pi8(
                src[0x10].0 as i8,
                src[0x11].0 as i8,
                src[0x12].0 as i8,
                src[0x13].0 as i8,
                src[0x14].0 as i8,
                src[0x15].0 as i8,
                src[0x16].0 as i8,
                src[0x17].0 as i8,
            ),
            _mm_set_pi8(
                src[0x18].0 as i8,
                src[0x19].0 as i8,
                src[0x1a].0 as i8,
                src[0x1b].0 as i8,
                src[0x1c].0 as i8,
                src[0x1d].0 as i8,
                src[0x1e].0 as i8,
                src[0x1f].0 as i8,
            ),
            _mm_set_pi8(
                src[0x20].0 as i8,
                src[0x21].0 as i8,
                src[0x22].0 as i8,
                src[0x23].0 as i8,
                src[0x24].0 as i8,
                src[0x25].0 as i8,
                src[0x26].0 as i8,
                src[0x27].0 as i8,
            ),
            _mm_set_pi8(
                src[0x28].0 as i8,
                src[0x29].0 as i8,
                src[0x2a].0 as i8,
                src[0x2b].0 as i8,
                src[0x2c].0 as i8,
                src[0x2d].0 as i8,
                src[0x2e].0 as i8,
                src[0x2f].0 as i8,
            ),
            _mm_set_pi8(
                src[0x30].0 as i8,
                src[0x31].0 as i8,
                src[0x32].0 as i8,
                src[0x33].0 as i8,
                src[0x34].0 as i8,
                src[0x35].0 as i8,
                src[0x36].0 as i8,
                src[0x37].0 as i8,
            ),
            _mm_set_pi8(
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
            for i in 0..8 {
                (dst[p].0)[i] = (_m_pmovmskb(v[i]) & 0xff) as u8;
                v[i] = _mm_add_pi8(v[i], v[i]);
            }
        }
    }

    // This codes assumes that a bounds heck has been done prior to the call.
    #[inline(always)]
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

        // x86 / x86_64 SSE impl.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return unsafe { Self::convert_sse(dst, src) };

        // otherwise revert to the generic implementation (slow)
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

        // x86 / x86_64 SSE impl.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return unsafe { Self::convert_inv_sse(dst, src) };

        // otherwise revert to the generic implementation (slow)
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
            debug_assert_eq!(&shares_1[..], &shares_2[..]);

            let mut batches_1 = [BitBatch::ZERO; 8];
            let mut batches_2 = [BitBatch::ZERO; 8];
            GF2P8::convert_inv(&mut batches_1, &shares_1);
            GF2P8::convert_inv_generic(&mut batches_2, &shares_1);
            debug_assert_eq!(batches_1, batches);
            debug_assert_eq!(batches_2, batches);
        }
    }
}
