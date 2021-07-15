use std::convert::TryFrom;
use std::fmt;
use std::ops::{Add, Sub};

use num_traits::Zero;

use crate::algebra::*;
use crate::crypto::hash::PackedHasher;
use crate::{PACKED, PLAYERS};

#[derive(Copy, Clone)]
pub struct ShareZ64 {
    pub(crate) pack: [[u64; PLAYERS]; PACKED],
}

impl EqIndex for ShareZ64 {
    #[cfg(test)]
    fn compare_index(rep1: usize, p1: usize, v1: &Self, rep2: usize, p2: usize, v2: &Self) -> bool {
        v1.pack[rep1][p1] == v2.pack[rep2][p2]
    }
}

impl fmt::Debug for ShareZ64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for rep in self.pack.iter() {
            write!(
                f,
                "[{:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x}]",
                rep[0], rep[1], rep[2], rep[3], rep[4], rep[5], rep[6], rep[7],
            )?;
        }
        Ok(())
    }
}

impl PackSelected for ShareZ64 {
    fn pack_selected(
        dst: &mut [Vec<u8>; PACKED], // serialized / packed bytes
        src: &[Self],                // source share
        selected: [usize; PACKED],   // player shares to extract
    ) {
        for elem in src {
            for i in 0..PACKED {
                if selected[i] < PLAYERS {
                    dst[i].extend_from_slice(&elem.pack[i][selected[i]].to_le_bytes());
                }
            }
        }
    }

    fn unpack_selected(
        dst: &mut Vec<Self>,       // list of sharings
        src: &[&[u8]; PACKED],     // shares for a single player per instance
        selected: [usize; PACKED], // player shares to extract
    ) {
        let bytes = src[0].len();

        debug_assert_eq!(bytes, src[1].len());
        debug_assert_eq!(bytes, src[2].len());
        debug_assert_eq!(bytes, src[3].len());
        debug_assert_eq!(bytes, src[4].len());
        debug_assert_eq!(bytes, src[5].len());
        debug_assert_eq!(bytes, src[6].len());
        debug_assert_eq!(bytes, src[7].len());
        debug_assert_eq!(bytes % 8, 0);

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

        for _ in 0..(bytes / 8) {
            let mut val = ShareZ64::default();
            for j in 0..PACKED {
                let p = selected[j];
                val.pack[j][p] = u64::from_le_bytes(
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

impl Default for ShareZ64 {
    fn default() -> Self {
        ShareZ64::zero()
    }
}

impl Hashable for ShareZ64 {
    fn hash(&self, hashers: &mut PackedHasher) {
        for i in 0..PACKED {
            for j in 0..PLAYERS {
                hashers[i].update(&self.pack[i][j].to_le_bytes());
            }
        }
    }
}

impl Add for ShareZ64 {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut sum = ShareZ64::zero();
        for i in 0..PACKED {
            for j in 0..PLAYERS {
                sum.pack[i][j] = self.pack[i][j].wrapping_add(other.pack[i][j]);
            }
        }
        sum
    }
}

impl Sub for ShareZ64 {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut dif = ShareZ64::zero();
        for i in 0..PACKED {
            for j in 0..PLAYERS {
                dif.pack[i][j] = self.pack[i][j].wrapping_sub(other.pack[i][j]);
            }
        }
        dif
    }
}

impl Zero for ShareZ64 {
    fn zero() -> Self {
        ShareZ64 {
            pack: [[0; PLAYERS]; PACKED],
        }
    }

    fn is_zero(&self) -> bool {
        self.pack.iter().all(|x| x.iter().all(|y| *y == 0))
    }
}

impl Share for ShareZ64 {}
