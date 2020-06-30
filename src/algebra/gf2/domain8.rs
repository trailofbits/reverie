use super::*;

use core::arch::x86_64::*;

pub struct GF2P8 {}

impl Domain for GF2P8 {
    type Batch = BitBatch;
    type Sharing = BitSharing8;

    #[inline(always)]
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        // do a single bounds check up front
        assert_eq!(src.len(), 8);

        // not supported on other platforms currently
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unimplemented!();

        // x86 / x86_64 SSE, MMX impl.
        #[target_feature(enable = "sse")]
        #[target_feature(enable = "mmx")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // do a single range-check up front
            assert!(dst.len() >= Self::Batch::DIMENSION);

            // transpose batch, byte-by-byte
            for i in 0..BATCH_SIZE_BYTES {
                // code for x86 and amd64 using SSE intrinsics

                unsafe {
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
                        *dst.get_unchecked_mut(idx) = BitSharing8((_m_pmovmskb(v) & 0xff) as u8);
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
        }
    }

    // converts 64 sharings between 8 players to 8 batches of 64 sharings,
    // one batch per player.
    #[inline(always)]
    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        // there should be enough sharings to fill a batch
        assert_eq!(src.len(), Self::Batch::DIMENSION);

        // there will be one batch per player
        assert_eq!(dst.len(), Self::Sharing::DIMENSION);

        // not supported on other platforms currently
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unimplemented!();

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // AVX2 implementation
            #[target_feature(enable = "avx2")]
            {
                // use 2 x 256-bit registers
            }

            // SSE, MMX impl.
            #[target_feature(enable = "sse")]
            #[target_feature(enable = "mmx")]
            unsafe {
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

                for p in 0..Self::Sharing::DIMENSION {
                    for i in 0..8 {
                        (dst[p].0)[i] = (_m_pmovmskb(v[i]) & 0xff) as u8;
                        v[i] = _mm_add_pi8(v[i], v[i]);
                    }
                }
            }
        }
    }
}
