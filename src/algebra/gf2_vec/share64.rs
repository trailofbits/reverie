use super::batch::Batch;
use super::scalar::Scalar;
use super::{RingElement, RingModule};

use std::mem::{self, MaybeUninit};
use std::ops::{Add, Mul, Sub};

const PLAYERS: usize = 64;

// vector element
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sharing64([Batch; PLAYERS]);

impl Add for Sharing64 {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for i in 0..PLAYERS {
            res[i] = MaybeUninit::new(self.0[i] + other.0[i]);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Sub for Sharing64 {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for i in 0..PLAYERS {
            res[i] = MaybeUninit::new(self.0[i] - other.0[i]);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Mul for Sharing64 {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for i in 0..PLAYERS {
            res[i] = MaybeUninit::new(self.0[i] * other.0[i]);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl RingElement for Sharing64 {
    const ONE: Self = Sharing64([Batch::ONE; PLAYERS]);

    const ZERO: Self = Sharing64([Batch::ZERO; PLAYERS]);
}

/*
impl RingModule<Scalar> for Sharing64 {
    const DIMENSION: usize = PLAYERS;
}
*/
