use super::*;

use itertools::izip;
use std::mem::{self, MaybeUninit};

const PLAYERS: usize = 8;
const PRIME: u64 = 17;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Sharing8(pub(super) [u64; PLAYERS]);

impl LocalOperation for Sharing8 {}

impl Add for Sharing8 {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        let mut res: [MaybeUninit<u64>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_share, self_share, other_share) in izip!(&mut res, &self.0, &other.0) {
            *res_share = MaybeUninit::new((*self_share + *other_share) % PRIME);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Sub for Sharing8 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        let mut res: [MaybeUninit<u64>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_share, self_share, other_share) in izip!(&mut res, &self.0, &other.0) {
            *res_share = MaybeUninit::new((*self_share - *other_share) % PRIME);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl Mul for Sharing8 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        let mut res: [MaybeUninit<u64>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_share, self_share, other_share) in izip!(&mut res, &self.0, &other.0) {
            *res_share = MaybeUninit::new((*self_share * *other_share) % PRIME);
        }
        Self(unsafe { mem::transmute(res) })
    }
}

impl RingElement for Sharing8 {
    const ONE: Self = Sharing8([1; PLAYERS]);
    const ZERO: Self = Sharing8([0; PLAYERS]);
}

impl RingModule<Scalar> for Sharing8 {
    const DIMENSION: usize = 8;

    #[inline(always)]
    fn action(&self, s: Scalar) -> Self {
        let mut res: [MaybeUninit<u64>; PLAYERS] = [MaybeUninit::uninit(); PLAYERS];
        for (res_share, self_share) in res.iter_mut().zip(&self.0) {
            *res_share = MaybeUninit::new((s.0 * *self_share) % PRIME);
        }
        Self(unsafe { mem::transmute(res) })
    }

    fn get(&self, i: usize) -> Scalar {
        debug_assert!(i < 8);
        Scalar(self.0[i])
    }

    fn set(&mut self, i: usize, s: Scalar) {
        debug_assert!(i < 8);
        self.0[i] = s.0;
    }
}

impl Serializable for Sharing8 {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        for elem in self.0.iter() {
            w.write_all(&elem.to_le_bytes())?;
        }
        Ok(())
    }
}

impl Sharing<Scalar> for Sharing8 {
    // Reconstruction for the share module is the sum of the ring elements
    fn reconstruct(&self) -> Scalar {
        let mut res = 0;
        for scalar in &self.0 {
            res = (res + *scalar) % PRIME;
        }
        Scalar(res)
    }
}