use std::convert::{AsMut, AsRef};
use std::mem::MaybeUninit;
use std::ops::{Add, Mul, Sub};

use num_traits::identities::Zero;

use crate::algebra::*;
use crate::crypto::prg::PRG;

pub const NSHARES: usize = 128;

#[derive(Debug, Copy, Clone)]
pub struct BatchZ64 {
    pub(crate) pack: [u64; NSHARES],
}

impl Default for BatchZ64 {
    fn default() -> Self {
        BatchZ64 {
            pack: [0u64; NSHARES],
        }
    }
}

impl Batch for BatchZ64 {
    fn random(&mut self, prg: &mut PRG) {
        let (_prefix, aligned, _suffix) = unsafe { self.pack.align_to_mut::<u8>() };
        prg.gen(aligned);
    }
}

impl Zero for BatchZ64 {
    #[inline(always)]
    fn zero() -> Self {
        BatchZ64 { pack: [0; NSHARES] }
    }

    fn is_zero(&self) -> bool {
        self.pack.iter().all(|x| *x == 0)
    }
}

impl AsMut<[u8]> for BatchZ64 {
    fn as_mut(&mut self) -> &mut [u8] {
        let (_prefix, aligned, _suffix) = unsafe { self.pack.align_to_mut::<u8>() };
        aligned
    }
}

impl AsRef<[u8]> for BatchZ64 {
    fn as_ref(&self) -> &[u8] {
        let (_prefix, aligned, _suffix) = unsafe { self.pack.align_to::<u8>() };
        aligned
    }
}

impl Add for BatchZ64 {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        let mut res = Self {
            pack: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        for i in 0..NSHARES {
            res.pack[i] = self.pack[i].wrapping_add(other.pack[i]);
        }
        res
    }
}

impl Sub for BatchZ64 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self {
        let mut res = Self {
            pack: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        for i in 0..NSHARES {
            res.pack[i] = self.pack[i].wrapping_sub(other.pack[i]);
        }
        res
    }
}

impl Mul for BatchZ64 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        let mut res = Self {
            pack: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        for i in 0..NSHARES {
            res.pack[i] = self.pack[i].wrapping_mul(other.pack[i]);
        }
        res
    }
}
