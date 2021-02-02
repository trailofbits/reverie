use super::*;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Z64P8 {}

impl Domain for Z64P8 {
    type Scalar = Scalar;
    type Batch = Batch;
    type Sharing = Sharing8;

    const PLAYERS: usize = 8;
    const PREPROCESSING_REPETITIONS: usize = 252;
    const ONLINE_REPETITIONS: usize = 44;

    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        assert_eq!(src.len(), Self::PLAYERS);
        assert!(dst.len() >= Self::Batch::DIMENSION);

        for i in 0..Self::Batch::DIMENSION { 
            let mut shares: [u64; Self::PLAYERS] = [0; Self::PLAYERS];
            for j in 0..Self::PLAYERS {
                shares[j] = src[j].0[i];
            }
            unsafe { *dst.get_unchecked_mut(i) = Sharing8(shares)};
        }
    }

    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        // there should be enough sharings to fill a batch
        assert_eq!(src.len(), Self::Batch::DIMENSION);

        // there will be one batch per player
        assert_eq!(dst.len(), Self::PLAYERS);

        for i in 0..Self::PLAYERS {
            let mut batch: [u64; Self::Batch::DIMENSION] = [0; Self::Batch::DIMENSION];
            for j in 0..Self::Batch::DIMENSION {
                batch[j] = src[j].0[i];
            }
            unsafe { *dst.get_unchecked_mut(i) = Batch(batch)};
        }
    }
}