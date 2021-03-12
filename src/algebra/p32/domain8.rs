use super::*;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct P32P8 {}

impl Domain for P32P8 {
    type Scalar = Scalar;
    type Batch = Batch;
    type Sharing = Sharing8;

    const PLAYERS: usize = 8;
    const PREPROCESSING_REPETITIONS: usize = 252;
    const ONLINE_REPETITIONS: usize = 44;
    const NR_OF_BITS: usize = 64;

    fn convert(dst: &mut [Self::Sharing], src: &[Self::Batch]) {
        assert_eq!(src.len(), Self::PLAYERS);
        assert_eq!(dst.len(), 1);

        let mut shares: [u64; Self::PLAYERS] = [0; Self::PLAYERS];
        for i in 0..Self::PLAYERS {
            shares[i] = src[i].0;
        }
        unsafe { *dst.get_unchecked_mut(0) = Sharing8(shares) };
    }

    fn convert_inv(dst: &mut [Self::Batch], src: &[Self::Sharing]) {
        // there should be enough sharings to fill a batch
        assert_eq!(src.len(), 1);

        // there will be one batch per player
        assert_eq!(dst.len(), Self::PLAYERS);

        let sharing = src[0].0;
        for (i, share) in sharing.iter().enumerate() {
            unsafe { *dst.get_unchecked_mut(i) = Batch(*share) };
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    //make sure round trip conversion is the identity function
    #[test]
    fn test_convert() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let batches: [_; 8] = [
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
            ];

            let mut shares = [Sharing8::ZERO; 1];
            P32P8::convert(&mut shares, &batches);

            let mut result = [Batch::ZERO; 8];
            P32P8::convert_inv(&mut result, &shares);

            assert_eq!(batches, result);
        }
    }

    // test round trip serialization
    #[test]
    fn test_pack_batch() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let batches: [_; 8] = [
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
                Batch::gen(&mut rng),
            ];

            let mut serialized: Vec<u8> = vec![];
            Batch::pack(&mut serialized, batches.iter()).unwrap();

            let mut result: Vec<Batch> = vec![];
            Batch::unpack(&mut result, &serialized).unwrap();
            assert_eq!(result.len(), batches.len());
            for (i, res) in result.iter().enumerate() {
                assert_eq!(batches[i], *res);
            }
        }
    }
}