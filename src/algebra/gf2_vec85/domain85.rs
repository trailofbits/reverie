use super::batch::Batch;
use super::scalar::Scalar;
use super::share64::Sharing64;
use super::Domain;

use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Gf2P64_85();

impl Domain for Gf2P64_85 {
    const PLAYERS: usize = 64;
    const PREPROCESSING_REPETITIONS: usize = 1662;
    const ONLINE_REPETITIONS: usize = 44;
    const NR_OF_BITS: usize = 1;

    type Scalar = Scalar;
    type Batch = Batch;
    type Sharing = Sharing64;

    /// Conversion for this domain is trivial
    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        debug_assert_eq!(src.len(), Self::PLAYERS);
        let sharing: &mut Self::Sharing = &mut dst[0];
        sharing.0.clone_from_slice(&src)
    }

    /// Conversion for this domain is trivial
    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        let sharing: &Self::Sharing = &src[0];
        dst.clone_from_slice(&sharing.0)
    }
}
