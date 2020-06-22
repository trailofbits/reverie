mod constants;
mod generator;

pub use generator::{PreprocessingFull, PreprocessingPartial};

use super::algebra::{RingArray, RingBatch, RingPacked, RingVector};
use super::consts::*;
use super::crypto::*;
use super::fs::*;
use super::util::*;

use std::marker::PhantomData;
use std::mem;

use rand_core::RngCore;
use rayon::prelude::*;


/// Represents repeated execution of the pre-processing phase.
/// The pre-precessing phase is executed R times, then fed to a random oracle,
/// which dictates the subset of executions to open.
///
///
/// - P  : number of players
/// - PT : size of PRF tree for players
/// - R  : number of repetitions
/// - RT : size of PRF tree for repetitions
/// - H  : hidden views (repetitions of online phase)
pub struct PreprocessedProof<
    B: RingBatch,
    const P: usize,
    const PT: usize,
    const R: usize,
    const RT: usize,
    const H: usize,
> {
    hidden: Box<[Hash; H]>,
    random: TreePRF<{ RT }>,
    ph: PhantomData<B>,
}


/// Executes the preprocessing (in-the-head) phase once.
///
/// Returns a commitment to the view of all players.
fn preprocess<B: RingBatch, const P: usize, const PT: usize>(
    beaver: u64,               // number of Beaver multiplication triples
    seed: &[u8; KEY_SIZE], // random tape used for phase
) -> Hash {
    // the root PRF from which each players random tape is derived using a PRF tree
    let root: TreePRF<PT> = TreePRF::new(*seed);
    let keys: Box<[_; P]> = root.expand();

    // create a view for every player
    let mut views: Box<[View; P]> = arr_map!(&keys, |key: &Option<[u8; KEY_SIZE]>| View::new_keyed(key.as_ref().unwrap()));

    // generate the beaver triples and write the corrected shares to the transcript
    let player0_correction_hash = PreprocessingFull::<B, _, P, false>::new(
        arr_map!(&views, |view: &View| view.rng(LABEL_RNG_BEAVER)), // derive RNG for every
    )
    .hash(beaver);

    // append the corrections to the view of player0
    views[0]
        .scope(LABEL_SCOPE_CORRECTION)
        .join(&player0_correction_hash);

    // aggregate every view commitment into a single commitment to the entire pre-processing
    let mut global: View = View::new();
    for view in views.iter() {
        global
            .scope(LABEL_SCOPE_AGGREGATE_COMMIT)
            .join(&view.hash())
    }
    global.hash()
}


impl<
        B: RingBatch,
        const P: usize,
        const PT: usize,
        const R: usize,
        const RT: usize,
        const H: usize,
    > PreprocessedProof<B, P, PT, R, RT, H>
{
    pub fn verify(&self, beaver: u64) -> Option<&[Hash; H]> {
        let batches = (beaver + (B::BATCH_SIZE as u64) - 1) / (B::BATCH_SIZE as u64);
        debug_assert!(batches * (B::BATCH_SIZE as u64) >= beaver);
        debug_assert!(beaver == 0 || (batches - 1) * (B::BATCH_SIZE as u64) <= beaver);

        // derive keys and hidden execution indexes
        let keys: Box<[_; R]> = self.random.expand();
        let mut hidden: Vec<usize> = Vec::with_capacity(R);
        let mut opened: Vec<usize> = Vec::with_capacity(R - H);
        for (i, key) in keys.iter().enumerate() {
            if key.is_none() {
                hidden.push(i)
            } else {
                opened.push(i)
            }
        }

        // prover must open exactly R-H repetitions
        if hidden.len() != H {
            return None;
        }
        assert_eq!(hidden.len() + opened.len(), R);

        // recompute the opened views
        let mut hashes: Vec<Option<Hash>> = keys
            .par_iter()
            .map(|seed| seed.map(|seed| preprocess::<B, P, PT>(batches, &seed)))
            .collect();

        // copy over the provided hashes from the hidden views
        for (&i, hash) in hidden.iter().zip(self.hidden.iter()) {
            assert!(hashes[i].is_none());
            hashes[i] = Some(*hash);
        }

        // interleave the proved hashes with the recomputed ones
        let mut global: View = View::new();
        {
            let mut scope: Scope = global.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in &hashes {
                scope.join(&hash.unwrap());
            }
        }

        // accept if the hidden indexes where computed correctly (Fiat-Shamir transform)
        if &hidden[..]
            == &random_subset::<_, R, H>(&mut global.rng(LABEL_RNG_OPEN_PREPROCESSING))[..]
        {
            Some(&self.hidden)
        } else {
            None
        }
    }

    pub fn new(beaver: u64, seed: [u8; KEY_SIZE]) -> Self {
        // define PRF tree and obtain key material for every pre-processing execution
        let root: TreePRF<RT> = TreePRF::new(seed);
        let keys: Box<[_; R]> = root.expand();

        // batches = ceil(beaver / BATCH_SIZE)
        let batches = (beaver + (B::BATCH_SIZE as u64) - 1) / (B::BATCH_SIZE as u64);
        debug_assert!(batches * (B::BATCH_SIZE as u64) >= beaver);

        // generate hashes of every pre-processing execution
        let hashes: Vec<Hash> = keys
            .par_iter()
            .map(|seed| preprocess::<B, P, PT>(batches, seed.as_ref().unwrap()))
            .collect();

        // add every pre-processing execution to a global view
        let mut global: View = View::new();
        {
            let mut scope: Scope = global.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in &hashes {
                scope.join(&hash);
            }
        }

        // extract random indexes not to open (rejection sampling)
        let hide: [usize; H] =
            random_subset::<_, R, H>(&mut global.rng(LABEL_RNG_OPEN_PREPROCESSING));

        // puncture the root prf
        let mut random = root.clone();
        for i in hide.iter() {
            random = random.puncture(*i);
        }

        // extract hashes for the hidden evaluations
        let hidden: Box<[Hash; H]> = arr_from_iter!(&mut hide.iter().map(|i| hashes[*i].clone()));

        // combine into the proof
        PreprocessedProof {
            hidden,
            random,
            ph: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::algebra::gf2::BitBatch;
    use super::*;

    use rand::Rng;
    const BEAVER: u64 = 1000;

    #[test]
    fn test_preprocessing_n8() {
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let proof = PreprocessedProof::<BitBatch, 8, 8, 252, 256, 44>::new(BEAVER, seed);
        assert!(proof.verify(BEAVER).is_some());
    }

    #[test]
    fn test_preprocessing_n64() {
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let proof = PreprocessedProof::<BitBatch, 64, 64, 631, 1024, 23>::new(BEAVER, seed);
        assert!(proof.verify(BEAVER).is_some());
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::super::algebra::gf2::BitBatch;
    use super::*;

    use test::Bencher;

    const BEAVER: u64 = 100_000;

    /// Benchmark proof generation of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =  64 (simulated players)
    /// M =  23 (number of pre-processing executions)
    /// t =  23 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_gen_n64(b: &mut Bencher) {
        b.iter(|| {
            PreprocessedProof::<BitBatch, 64, 64, 631, 1024, 23>::new(BEAVER, [0u8; KEY_SIZE])
        });
    }

    /// Benchmark proof generation of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =   8 (simulated players)
    /// M = 252 (number of pre-processing executions)
    /// t =  44 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_gen_n8(b: &mut Bencher) {
        b.iter(|| PreprocessedProof::<BitBatch, 8, 8, 252, 256, 44>::new(BEAVER, [0u8; KEY_SIZE]));
    }

    /// Benchmark proof verification of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =  64 (simulated players)
    /// M =  23 (number of pre-processing executions)
    /// t =  23 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_verify_n64(b: &mut Bencher) {
        let proof =
            PreprocessedProof::<BitBatch, 64, 64, 631, 1024, 23>::new(BEAVER, [0u8; KEY_SIZE]);
        b.iter(|| proof.verify(BEAVER));
    }

    /// Benchmark proof verification of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =   8 (simulated players)
    /// M = 252 (number of pre-processing executions)
    /// t =  44 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_verify_n8(b: &mut Bencher) {
        let proof = PreprocessedProof::<BitBatch, 8, 8, 252, 256, 44>::new(BEAVER, [0u8; KEY_SIZE]);
        b.iter(|| proof.verify(BEAVER));
    }
}