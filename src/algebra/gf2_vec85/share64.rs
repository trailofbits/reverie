use super::batch::Batch;
use super::scalar::Scalar;
use super::{LocalOperation, RingElement, RingModule, Serializable, Sharing};

use std::io;
use std::mem::{self, MaybeUninit};
use std::ops::{Add, Mul, Sub};

const PLAYERS: usize = 64;

// vector element
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sharing64(pub(super) [Batch; PLAYERS]);

impl Serializable for Sharing64 {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        for i in 0..PLAYERS {
            self.0[i].serialize(w)?;
        }
        Ok(())
    }
}

impl LocalOperation for Sharing64 {
    #[inline(always)]
    fn operation(&self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (i, res_i) in res.iter_mut().enumerate() {
            *res_i = MaybeUninit::new(self.0[i].rotate());
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Add for Sharing64 {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (i, res_i) in res.iter_mut().enumerate() {
            *res_i = MaybeUninit::new(self.0[i] + other.0[i]);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Sub for Sharing64 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (i, res_i) in res.iter_mut().enumerate() {
            *res_i = MaybeUninit::new(self.0[i] - other.0[i]);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Mul for Sharing64 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (i, res_i) in res.iter_mut().enumerate() {
            *res_i = MaybeUninit::new(self.0[i] * other.0[i]);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl RingElement for Sharing64 {
    const ONE: Self = Sharing64([Batch::ONE; PLAYERS]);

    const ZERO: Self = Sharing64([Batch::ZERO; PLAYERS]);
}

impl RingModule<Scalar> for Sharing64 {
    const DIMENSION: usize = PLAYERS;

    // action of the scalar ring upon the module:
    // s * (r_1, r_2, ..., r_dimension) = (s * r_1, s * r_2, ..., s * r_dimension)
    fn action(&self, s: Scalar) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for i in 0..PLAYERS {
            res[i] = MaybeUninit::new(s.0 * self.0[i]);
        }
        Self(unsafe { mem::transmute(res) })
    }

    fn set(&mut self, i: usize, s: Scalar) {
        self.0[i] = s.0;
    }

    fn get(&self, i: usize) -> Scalar {
        Scalar(self.0[i])
    }
}

impl Sharing<Scalar> for Sharing64 {
    fn reconstruct(&self) -> Scalar {
        let mut batch = Batch::ZERO;
        for i in 0..PLAYERS {
            batch = batch + self.0[i];
        }
        Scalar(batch)
    }
}
