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
        assert_eq!(dst.len(), 1);

        let mut shares: [u64; Self::PLAYERS] = [0; Self::PLAYERS];
        for i in 0..Self::PLAYERS {
            shares[i] = src[i].0;
        }
        unsafe { *dst.get_unchecked_mut(0) = Sharing8(shares)};
    }

    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        // there should be enough sharings to fill a batch
        assert_eq!(src.len(), 1);

        // there will be one batch per player
        assert_eq!(dst.len(), Self::PLAYERS);

        let sharing = src[0].0;
        for (i, share) in sharing.iter().enumerate() {
            unsafe { *dst.get_unchecked_mut(i) = Batch(*share)};
        }
    }
}