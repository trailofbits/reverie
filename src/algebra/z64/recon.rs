use std::convert::{From, TryFrom};
use std::fmt;
use std::io;
use std::ops::{Add, Mul, Sub};

use num_traits::Zero;
use serde;

use crate::algebra::*;
use crate::crypto::hash::PackedHasher;
use crate::PACKED;

#[derive(Copy, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReconZ64 {
    pub(crate) pack: [u64; PACKED],
}

impl fmt::Debug for ReconZ64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:016x}, {:016x}, {:016x}, {:016x}, {:016x}, {:016x}, {:016x}, {:016x}]",
            self.pack[0],
            self.pack[1],
            self.pack[2],
            self.pack[3],
            self.pack[4],
            self.pack[5],
            self.pack[6],
            self.pack[7],
        )
    }
}

impl Recon for ReconZ64 {}

impl EqIndex for ReconZ64 {
    fn compare_index(rep1: usize, p1: usize, v1: &Self, rep2: usize, p2: usize, v2: &Self) -> bool {
        debug_assert_eq!(p1, 0);
        debug_assert_eq!(p2, 0);
        v1.pack[rep1] == v2.pack[rep2]
    }
}

impl Pack for ReconZ64 {
    fn pack(dst: &mut [Vec<u8>; PACKED], src: &[Self], selected: &[bool; PACKED]) {
        // if there is nothing to extract return early
        if selected.iter().copied().all(|v| !v) {
            return;
        }

        // allocate destinations up-front to avoid later reallocations
        for i in 0..PACKED {
            if selected[i] {
                dst[i].reserve(8 * src.len()); // each element is 64-bit (8 bytes)
            }
        }

        for elem in src {
            for i in 0..PACKED {
                if selected[i] {
                    dst[i].extend_from_slice(&elem.pack[i].to_le_bytes());
                }
            }
        }
    }

    fn unpack(dst: &mut Vec<Self>, src: &[&[u8]; PACKED]) {
        let bytes = src[0].len();

        debug_assert_eq!(bytes, src[1].len());
        debug_assert_eq!(bytes, src[2].len());
        debug_assert_eq!(bytes, src[3].len());
        debug_assert_eq!(bytes, src[4].len());
        debug_assert_eq!(bytes, src[5].len());
        debug_assert_eq!(bytes, src[6].len());
        debug_assert_eq!(bytes, src[7].len());
        debug_assert_eq!(bytes % 8, 0);

        // allocate destinations up-front to avoid later reallocations
        dst.reserve(bytes / 8);

        // split into 8 byte chunks
        let mut chunks: [_; 8] = [
            src[0].chunks_exact(8),
            src[1].chunks_exact(8),
            src[2].chunks_exact(8),
            src[3].chunks_exact(8),
            src[4].chunks_exact(8),
            src[5].chunks_exact(8),
            src[6].chunks_exact(8),
            src[7].chunks_exact(8),
        ];

        //
        for _ in 0..(bytes / 8) {
            let mut val = ReconZ64 { pack: [0u64; 8] };
            for j in 0..PACKED {
                val.pack[j] = u64::from_le_bytes(
                    chunks[j]
                        .next()
                        .map(|v| *<&[u8; 8]>::try_from(v).unwrap())
                        .unwrap_or([0u8; 8]),
                )
            }
            dst.push(val)
        }
    }
}

impl From<[u64; PACKED]> for ReconZ64 {
    fn from(pack: [u64; PACKED]) -> Self {
        ReconZ64 { pack }
    }
}

impl Default for ReconZ64 {
    fn default() -> Self {
        ReconZ64 { pack: [0; PACKED] }
    }
}

impl From<u64> for ReconZ64 {
    fn from(item: u64) -> Self {
        Self {
            pack: [item; PACKED],
        }
    }
}

impl Hashable for ReconZ64 {
    fn hash(&self, hashers: &mut PackedHasher) {
        for i in 0..PACKED {
            hashers[i].update(&self.pack[i].to_le_bytes());
        }
    }
}

impl Zero for ReconZ64 {
    fn zero() -> Self {
        ReconZ64 { pack: [0; PACKED] }
    }

    fn is_zero(&self) -> bool {
        self.pack.iter().all(|x| *x == 0)
    }
}

impl Mul for ReconZ64 {
    type Output = Self;

    fn mul(self, recon: Self) -> Self {
        let mut pack: [u64; PACKED] = [0; PACKED];
        for i in 0..PACKED {
            pack[i] = self.pack[i].wrapping_mul(recon.pack[i]);
        }
        Self { pack }
    }
}

impl Add for ReconZ64 {
    type Output = Self;

    fn add(self, recon: Self) -> Self {
        let mut pack: [u64; PACKED] = [0; PACKED];
        for i in 0..PACKED {
            pack[i] = self.pack[i].wrapping_add(recon.pack[i]);
        }
        Self { pack }
    }
}

impl Sub for ReconZ64 {
    type Output = Self;

    fn sub(self, recon: Self) -> Self {
        let mut pack: [u64; PACKED] = [0; PACKED];
        for i in 0..PACKED {
            pack[i] = self.pack[i].wrapping_sub(recon.pack[i]);
        }
        Self { pack }
    }
}

impl Serialize for ReconZ64 {
    #[inline(always)]
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        for i in 0..PACKED {
            writer.write_all(&self.pack[i].to_le_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_recon_mul() {
        let left: ReconZ64 = 36.into();
        let right: ReconZ64 = 42.into();
        let expected: ReconZ64 = (36 * 42).into();

        assert_eq!(left * right, expected);
    }

    #[test]
    fn test_recon_sub() {
        let left: ReconZ64 = 36.into();
        let right: ReconZ64 = 42.into();
        let expected: ReconZ64 = (36u64.wrapping_sub(42)).into();

        assert_eq!(left - right, expected);

        let left: ReconZ64 = 42.into();
        let right: ReconZ64 = 36.into();
        let expected: ReconZ64 = (42u64.wrapping_sub(36)).into();

        assert_eq!(left - right, expected);
    }
}
