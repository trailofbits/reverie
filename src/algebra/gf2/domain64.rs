use super::*;

pub struct GF2P64 {}

impl Domain for GF2P64 {
    type Batch = BitBatch;
    type Sharing = BitSharing64;

    #[inline(always)]
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        // do a single bounds check up front
        assert_eq!(src.len(), 64);

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
                    // pack 1 byte from 64 different players
                    let mut v: [__m64; 8] = [
                        _mm_set_pi8(
                            src.get_unchecked(0x00).0[i] as i8,
                            src.get_unchecked(0x01).0[i] as i8,
                            src.get_unchecked(0x02).0[i] as i8,
                            src.get_unchecked(0x03).0[i] as i8,
                            src.get_unchecked(0x04).0[i] as i8,
                            src.get_unchecked(0x05).0[i] as i8,
                            src.get_unchecked(0x06).0[i] as i8,
                            src.get_unchecked(0x07).0[i] as i8,
                        ),
                        _mm_set_pi8(
                            src.get_unchecked(0x08).0[i] as i8,
                            src.get_unchecked(0x09).0[i] as i8,
                            src.get_unchecked(0x0a).0[i] as i8,
                            src.get_unchecked(0x0b).0[i] as i8,
                            src.get_unchecked(0x0c).0[i] as i8,
                            src.get_unchecked(0x0d).0[i] as i8,
                            src.get_unchecked(0x0e).0[i] as i8,
                            src.get_unchecked(0x0f).0[i] as i8,
                        ),
                        _mm_set_pi8(
                            src.get_unchecked(0x10).0[i] as i8,
                            src.get_unchecked(0x11).0[i] as i8,
                            src.get_unchecked(0x12).0[i] as i8,
                            src.get_unchecked(0x13).0[i] as i8,
                            src.get_unchecked(0x14).0[i] as i8,
                            src.get_unchecked(0x15).0[i] as i8,
                            src.get_unchecked(0x16).0[i] as i8,
                            src.get_unchecked(0x17).0[i] as i8,
                        ),
                        _mm_set_pi8(
                            src.get_unchecked(0x18).0[i] as i8,
                            src.get_unchecked(0x19).0[i] as i8,
                            src.get_unchecked(0x1a).0[i] as i8,
                            src.get_unchecked(0x1b).0[i] as i8,
                            src.get_unchecked(0x1c).0[i] as i8,
                            src.get_unchecked(0x1d).0[i] as i8,
                            src.get_unchecked(0x1e).0[i] as i8,
                            src.get_unchecked(0x1f).0[i] as i8,
                        ),
                        _mm_set_pi8(
                            src.get_unchecked(0x20).0[i] as i8,
                            src.get_unchecked(0x21).0[i] as i8,
                            src.get_unchecked(0x22).0[i] as i8,
                            src.get_unchecked(0x23).0[i] as i8,
                            src.get_unchecked(0x24).0[i] as i8,
                            src.get_unchecked(0x25).0[i] as i8,
                            src.get_unchecked(0x26).0[i] as i8,
                            src.get_unchecked(0x27).0[i] as i8,
                        ),
                        _mm_set_pi8(
                            src.get_unchecked(0x28).0[i] as i8,
                            src.get_unchecked(0x29).0[i] as i8,
                            src.get_unchecked(0x2a).0[i] as i8,
                            src.get_unchecked(0x2b).0[i] as i8,
                            src.get_unchecked(0x2c).0[i] as i8,
                            src.get_unchecked(0x2d).0[i] as i8,
                            src.get_unchecked(0x2e).0[i] as i8,
                            src.get_unchecked(0x2f).0[i] as i8,
                        ),
                        _mm_set_pi8(
                            src.get_unchecked(0x30).0[i] as i8,
                            src.get_unchecked(0x31).0[i] as i8,
                            src.get_unchecked(0x32).0[i] as i8,
                            src.get_unchecked(0x33).0[i] as i8,
                            src.get_unchecked(0x34).0[i] as i8,
                            src.get_unchecked(0x35).0[i] as i8,
                            src.get_unchecked(0x36).0[i] as i8,
                            src.get_unchecked(0x37).0[i] as i8,
                        ),
                        _mm_set_pi8(
                            src.get_unchecked(0x38).0[i] as i8,
                            src.get_unchecked(0x39).0[i] as i8,
                            src.get_unchecked(0x3a).0[i] as i8,
                            src.get_unchecked(0x3b).0[i] as i8,
                            src.get_unchecked(0x3c).0[i] as i8,
                            src.get_unchecked(0x3d).0[i] as i8,
                            src.get_unchecked(0x3e).0[i] as i8,
                            src.get_unchecked(0x3f).0[i] as i8,
                        ),
                    ];

                    // calculate the 8 sharings
                    let mut idx = i * 8;

                    for _ in 0..8 {
                        let mut res: [u8; 8] = [0u8; 8];

                        for i in 0..8 {
                            res[i] = (_m_pmovmskb(v[i]) & 0xff) as u8;
                            v[i] = _mm_add_pi8(v[i], v[i]);
                        }

                        dst[idx] = BitSharing64(u64::from_le_bytes(res));
                        idx += 1;
                    }
                }
            }
        }
    }

    #[inline(always)]
    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        unimplemented!()
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
