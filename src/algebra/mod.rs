use std::io;
use std::ops::{Add, Mul, Sub};

use rand::distributions::{Distribution, Standard};
use rand::{Rng, RngCore};

mod ring;

pub mod gf2;

pub use ring::{RingElement, RingModule};

pub trait Serializable {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()>;
}

pub trait Samplable {
    fn gen<R: RngCore>(rng: &mut R) -> Self;
}

impl<T> Samplable for T
where
    Standard: Distribution<T>,
{
    fn gen<R: RngCore>(rng: &mut R) -> T {
        rng.gen()
    }
}

/// A sharing is a serializable ring module with a reconstruction homomorphism:
///
/// (v1 + v2).reconstruct() = v1.reconstruct() + v2.reconstruct()
///
/// For additive sharings (used here) this corresponds to the sum of the coordinates.
/// The dimension of the sharing is equal to the number of players in the MPC protocol.
pub trait Sharing: RingModule + Serializable {
    fn reconstruct(&self) -> <Self as RingModule>::Scalar;
}

/// Represents a ring and player count instance of the protocol
pub trait Domain {
    /// a batch of ring elements belonging to a single player
    type Batch: RingModule + Samplable + Serializable;

    /// a sharing of a value across all players
    type Sharing: Sharing;

    /// See documentation for Domain::convert
    const SHARINGS_PER_BATCH: usize;

    /// Map from:
    ///
    /// Self::Batch ^ Self::Sharing::DIMENSION -> Self::Sharing ^ Self::SHARINGS_PER_BATCH
    ///
    /// This corresponds to a transpose of the following matrix:
    ///
    /// The destination is always holds at least SHARINGS_PER_BATCH bytes.
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]);
}
