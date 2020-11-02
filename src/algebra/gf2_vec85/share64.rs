use super::batch::Batch;
use super::scalar::Scalar;
use super::{LocalOperation, RingElement, RingModule, Serializable, Sharing};

use std::io;
use std::mem::{self, MaybeUninit};
use std::ops::{Add, Mul, Sub};

use itertools::izip;

const PLAYERS: usize = 64;

// vector element
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sharing64(pub(super) [Batch; PLAYERS]);

impl Serializable for Sharing64 {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        for batch in &self.0 {
            batch.serialize(w)?;
        }
        Ok(())
    }
}

impl LocalOperation for Sharing64 {
    #[inline(always)]
    fn operation(&self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_batch, self_batch) in res.iter_mut().zip(&self.0) {
            *res_batch = MaybeUninit::new(self_batch.rotate());
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Add for Sharing64 {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_batch, self_batch, other_batch) in izip!(&mut res, &self.0, &other.0) {
            *res_batch = MaybeUninit::new(*self_batch + *other_batch);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Sub for Sharing64 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_batch, self_batch, other_batch) in izip!(&mut res, &self.0, &other.0) {
            *res_batch = MaybeUninit::new(*self_batch - *other_batch);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Mul for Sharing64 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        let mut res: [MaybeUninit<Batch>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_batch, self_batch, other_batch) in izip!(&mut res, &self.0, &other.0) {
            *res_batch = MaybeUninit::new(*self_batch * *other_batch);
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
        for (res_batch, self_batch) in res.iter_mut().zip(&self.0) {
            *res_batch = MaybeUninit::new(s.0 * *self_batch);
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
        for self_batch in &self.0 {
            batch = batch + *self_batch;
        }
        Scalar(batch)
    }
}
