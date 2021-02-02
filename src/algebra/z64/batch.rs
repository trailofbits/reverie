use super::*;

use crate::util::Writer;

use itertools::izip;
use serde::{Deserialize, Serialize};

use std::convert::TryInto;
use std::io;

pub(super) const BATCH_SIZE: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch(pub(super) [u64; BATCH_SIZE]);

impl Add for Batch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        let mut res: [u64; BATCH_SIZE] = [0; BATCH_SIZE];
        for (res_scalar, self_scalar, other_scalar) in izip!(&mut res, &self.0, &other.0) {
            *res_scalar = self_scalar + other_scalar;
        }
        Self(res)
    }
}

impl Sub for Batch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        let mut res: [u64; BATCH_SIZE] = [0; BATCH_SIZE];
        for (res_scalar, self_scalar, other_scalar) in izip!(&mut res, &self.0, &other.0) {
            *res_scalar = self_scalar - other_scalar;
        }
        Self(res)
    }
}

impl Mul for Batch {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        let mut res: [u64; BATCH_SIZE] = [0; BATCH_SIZE];
        for (res_scalar, self_scalar, other_scalar) in izip!(&mut res, &self.0, &other.0) {
            *res_scalar = self_scalar * other_scalar;
        }
        Self(res)
    }
}

impl RingElement for Batch {
    const ONE: Batch = Batch([1; BATCH_SIZE]);
    const ZERO: Batch = Batch([0; BATCH_SIZE]);
}

impl RingModule<Scalar> for Batch {
    const DIMENSION: usize = BATCH_SIZE;

    #[inline(always)]
    fn action(&self, s: Scalar) -> Self {
        let mut res: [u64; BATCH_SIZE] = [0; BATCH_SIZE];
        for (res_scalar, self_scalar) in res.iter_mut().zip(&self.0) {
            *res_scalar = s.0 * self_scalar;
        }
        Self(res)
    }

    fn get(&self, i: usize) -> Scalar {
        debug_assert!(i < BATCH_SIZE);
        Scalar(self.0[i])
    }
    
    fn set(&mut self, i: usize, s: Scalar) {
        debug_assert!(i < BATCH_SIZE);
        self.0[i] = s.0;
    }
}

impl Serializable for Batch {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        for elem in self.0.iter() {
            w.write_all(&elem.to_le_bytes());
        }
        Ok(())
    }
}

impl Samplable for Batch {
    fn gen<R: RngCore>(rng: &mut R) -> Batch {
        let mut res: [u64; BATCH_SIZE] = [0; BATCH_SIZE];
        for i in 0..BATCH_SIZE {
            res[i] = rng.gen::<u64>();
        }
        return Batch(res);
    }
}

impl Packable for Batch {
    type Error = ();

    fn pack<'a, W: io::Write, I: Iterator<Item = &'a Batch>>(
        mut dst: W,
        elems: I,
    ) -> io::Result<()> {
        for batch in elems {
            for elem in batch.0.iter() {
                dst.write_all(&elem.to_le_bytes());
            }
        }
        Ok(())
    }

    fn unpack<W: Writer<Batch>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() % (8*BATCH_SIZE) != 0 {
            return Err(());
        }
        
        let mut i: usize = 0;
        let mut batch: Batch = Batch([0; BATCH_SIZE]);
        for chunk in bytes.chunks(8) {
            batch.0[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            
            if i % BATCH_SIZE == 0 {
                dst.write(batch);
                i = 0;
            }
        }

        Ok(())
    }
}