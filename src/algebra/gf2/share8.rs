use super::*;

use std::fmt;

// vector element
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct BitSharing8(pub(super) u8);

impl LocalOperation for BitSharing8 {}

impl fmt::Debug for BitSharing8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("<{:08b}> [{}]", self.0, self.reconstruct().0))
    }
}

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

impl RingModule<BitScalar> for BitSharing8 {
    const DIMENSION: usize = 8;

    #[inline(always)]
    fn action(&self, s: BitScalar) -> Self {
        debug_assert!(s.0 < 2, "scalar is not bit");
        BitSharing8(s.0 * self.0)
    }

    fn get(&self, i: usize) -> BitScalar {
        debug_assert!(i < 8);
        let i = 7 - i;
        BitScalar((self.0 >> i) & 1)
    }

    fn set(&mut self, i: usize, s: BitScalar) {
        debug_assert!(i < 8);
        let i = 7 - i;
        self.0 &= !(1 << i);
        self.0 |= s.0 << i;
    }
}

impl Serializable for BitSharing8 {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

impl Sharing<BitScalar> for BitSharing8 {
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

        let mut v: [BitSharing8; 4] = [
            BitSharing8(rng.gen()),
            BitSharing8(rng.gen()),
            BitSharing8(rng.gen()),
            BitSharing8(rng.gen()),
        ];

        b.iter(|| {
            black_box({
                let mut s: BitScalar = BitScalar::ZERO;
                for i in 0..1_000_000 {
                    s = s + v[i % 4].reconstruct();
                }
                s
            })
        });
    }

    #[bench]
    fn bench_gf2p8_action(b: &mut Bencher) {
        // all this work to avoid LLVM optimizing everything away.

        let mut rng = thread_rng();

        let v = BitSharing8(rng.gen());
        let s = BitScalar(rng.gen::<u8>() & 1);

        b.iter(|| {
            black_box(for _ in 0..1_000_000 {
                black_box({ v.action(s) });
            })
        });
    }
}
