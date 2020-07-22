use super::*;

// vector element
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BitSharing64(pub(super) u64);

impl Add for BitSharing64 {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(self.0 ^ other.0)
    }
}

impl Sub for BitSharing64 {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        self + other
    }
}

impl Mul for BitSharing64 {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self(self.0 & other.0)
    }
}

impl RingElement for BitSharing64 {
    const ONE: Self = Self(0xffff_ffff_ffff_ffff);
    const ZERO: Self = Self(0x0);
}

impl RingModule<BitScalar> for BitSharing64 {
    const DIMENSION: usize = 64;

    #[inline(always)]
    fn action(&self, s: BitScalar) -> Self {
        debug_assert!(s.0 < 2, "scalar is not bit");
        BitSharing64(if s.0 == 0 { 0 } else { self.0 })
    }

    /*
    #[inline(always)]
    fn get(&self, n: usize) -> Self::Scalar {
        debug_assert!(n < Self::DIMENSION, "get out of range");
        let n = 63 - n;
        BitScalar(((self.0 >> n) & 1) as u8)
    }

    #[inline(always)]
    fn set(&self, s: Self::Scalar, n: usize) -> Self {
        debug_assert!(s.0 < 2, "scalar is not bit");
        debug_assert!(n < Self::DIMENSION, "set out of range");
        let n = 63 - n;

        let mut r = self.0;
        r &= !(1 << n); // clear nth bit
        r |= (s.0 as u64) << n; // set nth bit
        BitSharing64(r)
    }
    */
}

impl Serializable for BitSharing64 {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

impl Sharing<BitScalar> for BitSharing64 {
    // Reconstruction for the share module is the sum of the ring elements
    // This can be implemented by xoring all the bits together,
    // but calculating the parity via count_ones is faster on x86.
    fn reconstruct(&self) -> BitScalar {
        BitScalar((self.0.count_ones() & 1) as u8)
    }
}
