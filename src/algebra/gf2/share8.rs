use super::*;

// vector element
#[derive(Copy, Clone, Debug)]
pub struct BitSharing8(pub(super) u8);

impl Add for BitSharing8 {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl Sub for BitSharing8 {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl Mul for BitSharing8 {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self(self.0 & other.0)
    }
}

impl RingElement for BitSharing8 {
    const ONE: Self = Self(0xff);
    const ZERO: Self = Self(0x00);
}

impl RingModule for BitSharing8 {
    type Scalar = BitScalar;

    const DIMENSION: usize = 8;

    #[inline(always)]
    fn action(&self, s: Self::Scalar) -> Self {
        debug_assert!(s.0 < 2, "scalar is not bit");
        BitSharing8(s.0 * self.0)
    }

    #[inline(always)]
    fn get(&self, n: usize) -> Self::Scalar {
        debug_assert!(n < 8, "get out of range");
        BitScalar((self.0 >> n) & 1)
    }

    #[inline(always)]
    fn set(&self, s: Self::Scalar, n: usize) -> Self {
        debug_assert!(s.0 < 2, "scalar is not bit");
        debug_assert!(n < 8, "set out of range");

        let mut r: u8 = self.0;
        r &= !(1 << n); // clear nth bit
        r |= s.0 << n; // set nth bit
        BitSharing8(r)
    }
}

impl Serializable for BitSharing8 {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

impl Sharing for BitSharing8 {
    // Reconstruction for the share module is the sum of the ring elements
    // This can be implemented by xoring all the bits together,
    // but calculating the parity via count_ones is faster on x86.
    fn reconstruct(&self) -> BitScalar {
        BitScalar((self.0.count_ones() & 1) as u8)
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
    fn bench_gf2p8_reconstruct(b: &mut Bencher) {
        // all this work to avoid LLVM optimizing everything away.

        let mut rng = thread_rng();

        let mut v: [BitSharing; 4] = [
            BitSharing(rng.gen()),
            BitSharing(rng.gen()),
            BitSharing(rng.gen()),
            BitSharing(rng.gen()),
        ];

        b.iter(|| {
            black_box({
                let mut s: BitScalar = BitScalar::ZERO;
                for i in 0..1_000_000 {
                    unsafe {
                        s = s + v[i % 4].reconstruct();
                    }
                }
                s
            })
        });
    }
}
