use super::*;

use core::arch::x86_64::*;

mod batch;
mod scalar;
mod share;

pub use batch::BitBatch;
pub use scalar::BitScalar;
pub use share::BitSharing;

use batch::{BATCH_SIZE_BITS, BATCH_SIZE_BYTES};

pub struct GF2P8 {}

impl Domain for GF2P8 {
    type Batch = BitBatch;
    type Sharing = BitSharing;

    // across players sharings from a batch of sharings for each player
    const SHARINGS_PER_BATCH: usize = BATCH_SIZE_BITS;

    #[inline(always)]
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        debug_assert!(src.len() == 8, "source has wrong dimension");

        // not supported on other platforms atm.
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unimplemented!();

        // x86 / x86_64 SSE, MMX impl.
        #[target_feature(enable = "sse")]
        #[target_feature(enable = "mmx")]
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // do a single range-check up front
            assert!(dst.len() >= Self::SHARINGS_PER_BATCH);

            // transpose batch, byte-by-byte
            for i in 0..BATCH_SIZE_BYTES {
                // code for x86 and amd64 using SSE intrinsics

                unsafe {
                    // pack 1 bytes from 8 different shar
                    let mut v = _mm_set_pi8(
                        src[0].0[i] as i8,
                        src[1].0[i] as i8,
                        src[2].0[i] as i8,
                        src[3].0[i] as i8,
                        src[4].0[i] as i8,
                        src[5].0[i] as i8,
                        src[6].0[i] as i8,
                        src[7].0[i] as i8,
                    );

                    // calculate the 8 sharings
                    let mut idx = i * 8;
                    for _ in 0..8 {
                        *dst.get_unchecked_mut(idx) = BitSharing((_m_pmovmskb(v) & 0xff) as u8);
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
}
