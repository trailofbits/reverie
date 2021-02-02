use std::fmt::Debug;
use std::io;
use std::io::Write;
use std::ops::{Add, Mul, Sub};

use crate::util::Writer;

use rand::distributions::{Distribution, Standard};
use rand::{Rng, RngCore};

use serde::{Deserialize, Serialize};

mod ring;

/// General purpose "bit-by-bit" domain
pub mod gf2;

// Ring of integers mod 64
pub mod z64;

/// These two domains are primarily used for bit-slicing LowMC inside the circuit
pub mod gf2_vec;
pub mod gf2_vec85;

pub use ring::{RingElement, RingModule};

pub trait Serializable {
    fn serialize<W: io::Write>(&self, w: &mut W) -> io::Result<()>;
}

pub trait Samplable {
    fn gen<R: RngCore>(rng: &mut R) -> Self;
}

pub trait Packable: Sized + 'static {
    type Error: Debug;

    fn pack<'a, W: Write, I: Iterator<Item = &'a Self>>(dst: W, elems: I) -> io::Result<()>;

    fn unpack<W: Writer<Self>>(dst: W, bytes: &[u8]) -> Result<(), Self::Error>;
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
pub trait Sharing<R: RingElement>: RingModule<R> + Serializable + LocalOperation {
    fn reconstruct(&self) -> R;
}

/// Apply a deterministic operation to the type, default implementation is a noop.
///
/// Used for cyclic shifts in the [F]^n domain (vector space over fields)
pub trait LocalOperation: Sized + Copy {
    fn operation(&self) -> Self {
        *self
    }
}

/// Represents a ring and player count instance of the protocol
pub trait Domain: Debug + Copy + Send + Sync + 'static {
    const PLAYERS: usize;
    const PREPROCESSING_REPETITIONS: usize;
    const ONLINE_REPETITIONS: usize;

    type Scalar: LocalOperation + RingElement + Packable + Sized;

    /// a batch of ring elements belonging to a single player
    type Batch: RingModule<Self::Scalar> + Samplable + Serializable + Debug + Packable;

    /// a sharing of a value across all players
    type Sharing: Sharing<Self::Scalar> + Debug;

    /// Map from:
    ///
    /// Self::Batch ^ Self::Sharing::DIMENSION -> Self::Sharing ^ Self::Batch::DIMENSION
    ///
    /// This corresponds to a transpose of the following matrix:
    ///
    /// The destination is always holds at least SHARINGS_PER_BATCH bytes.
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]);

    /// Map from:
    ///
    /// Self::Sharing ^ Self::Batch::DIMENSION -> Self::Batch ^ Self::Sharing::DIMENSION
    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]);
}

/// Derived property-based test for any domain
#[cfg(test)]
fn test_domain<D: Domain>() {
    use rand::thread_rng;

    let mut rng = thread_rng();

    fn rnd_batches<D: Domain, R: RngCore>(rng: &mut R) -> Vec<D::Batch> {
        let mut batches: Vec<D::Batch> = Vec::with_capacity(D::Sharing::DIMENSION);
        for _ in 0..D::Sharing::DIMENSION {
            batches.push(D::Batch::gen(rng));
        }
        batches
    }

    fn rnd_sharings<D: Domain, R: RngCore>(rng: &mut R) -> Vec<D::Sharing> {
        let batches = rnd_batches::<D, R>(rng);
        let mut sharings = vec![D::Sharing::ZERO; D::Batch::DIMENSION];
        D::convert(&mut sharings, &batches);
        sharings
    }

    // check serialize of batch
    for _ in 0..1000 {
        // generate a random number of random batches
        let num_batches: usize = 1 + rng.gen::<usize>() % 100;
        let mut batches: Vec<D::Batch> = Vec::with_capacity(num_batches);
        for _ in 0..num_batches {
            batches.push(D::Batch::gen(&mut rng))
        }

        // serialize into a vector
        let mut serialized: Vec<u8> = vec![];
        D::Batch::pack(&mut serialized, batches.iter()).unwrap();

        // deserialize and check equality
        let mut result: Vec<D::Batch> = vec![];
        D::Batch::unpack(&mut result, &serialized).unwrap();
        assert_eq!(batches, result);
    }

    // check that convert_inv is the inverse of convert
    for _ in 0..1000 {
        let batches = rnd_batches::<D, _>(&mut rng);
        let mut sharings: Vec<D::Sharing> = vec![D::Sharing::ZERO; D::Batch::DIMENSION];

        D::convert(&mut sharings, &batches);

        let mut batches_after = rnd_batches::<D, _>(&mut rng);

        D::convert_inv(&mut batches_after, &sharings[..]);

        assert_eq!(
            &batches[..],
            &batches_after[..],
            "convert_inv o convert != id"
        );
    }

    // check that reconstruction is additively homomorphic
    for _ in 0..1000 {
        let sharings_1 = rnd_sharings::<D, _>(&mut rng);
        let sharings_2 = rnd_sharings::<D, _>(&mut rng);

        for i in 0..sharings_1.len() {
            let a: D::Scalar = (sharings_1[i] + sharings_2[i]).reconstruct();
            let b: D::Scalar = sharings_1[i].reconstruct() + sharings_2[i].reconstruct();
            assert_eq!(a, b);
        }
    }
}

#[test]
fn test_gf2_p8() {
    test_domain::<gf2::GF2P8>();
}

#[test]
fn test_gf2_p64() {
    test_domain::<gf2::GF2P64>();
}

#[test]
fn test_gf2_p64_64() {
    test_domain::<gf2_vec::GF2P64_64>();
}

#[test]
fn test_gf2_p64_85() {
    test_domain::<gf2_vec85::GF2P64_85>();
}
