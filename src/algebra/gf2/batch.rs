use std::convert::{AsMut, AsRef};
use std::mem::MaybeUninit;
use std::ops::{Add, Mul, Sub};

use num_traits::identities::Zero;

use crate::algebra::Batch;
use crate::crypto::prg::PRG;

pub const BYTES: usize = 16;

#[derive(Debug, Copy, Clone, Default)]
pub struct BatchGF2 {
    pub(crate) pack: [u8; BYTES],
}

impl Batch for BatchGF2 {
    fn random(&mut self, prg: &mut PRG) {
        prg.gen(&mut self.pack);
    }
}

impl Zero for BatchGF2 {
    #[inline(always)]
    fn zero() -> Self {
        BatchGF2 { pack: [0u8; BYTES] }
    }

    fn is_zero(&self) -> bool {
        let (_prefix, aligned, _suffix) = unsafe { self.pack.align_to::<u128>() };
        debug_assert_eq!(_prefix.len(), 0);
        debug_assert_eq!(_suffix.len(), 0);
        aligned.iter().all(|&x| x == 0)
    }
}

impl AsMut<[u8]> for BatchGF2 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.pack
    }
}

impl AsRef<[u8]> for BatchGF2 {
    fn as_ref(&self) -> &[u8] {
        &self.pack
    }
}

impl Add for BatchGF2 {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        let mut res = Self {
            pack: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        for i in 0..BYTES {
            res.pack[i] = self.pack[i] ^ other.pack[i];
        }
        res
    }
}

impl Sub for BatchGF2 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self {
        let mut res = Self {
            pack: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        for i in 0..BYTES {
            res.pack[i] = self.pack[i] ^ other.pack[i];
        }
        res
    }
}

impl Mul for BatchGF2 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        let mut res = Self {
            pack: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        for i in 0..BYTES {
            res.pack[i] = self.pack[i] & other.pack[i];
        }
        res
    }
}
