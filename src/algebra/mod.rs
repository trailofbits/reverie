use std::fmt::Debug;
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
    type Batch: RingModule + Samplable + Serializable + Debug;

    /// a sharing of a value across all players
    type Sharing: Sharing + Debug;

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

    // check that convert_inv is the inverse of convert
    {
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

    // check that reconstruction is homomorphic
    {
        let sharings_1 = rnd_sharings::<D, _>(&mut rng);
        let sharings_2 = rnd_sharings::<D, _>(&mut rng);

        for i in 0..sharings_1.len() {
            let a: <D::Sharing as RingModule>::Scalar =
                (sharings_1[i] + sharings_2[i]).reconstruct();
            let b: <D::Sharing as RingModule>::Scalar =
                sharings_1[i].reconstruct() + sharings_2[i].reconstruct();
            assert_eq!(a, b);
        }
    }
}

#[test]
fn test_gf2_p8() {
    test_domain::<gf2::GF2P8>();
}
