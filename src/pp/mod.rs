mod constants;
pub mod prover;
pub mod verifier;

use crate::algebra::*;
use crate::consts::*;
use crate::crypto::*;
use crate::fs::*;
use crate::util::*;
use crate::Instruction;

use std::marker::PhantomData;
use std::mem;

use rand_core::RngCore;
use rayon::prelude::*;

pub trait Preprocessing<D: Domain> {
    fn mask(&self, idx: usize) -> D::Sharing;

    fn next_ab_gamma(&mut self) -> D::Sharing;
}

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
    D: Domain,
    const P: usize,
    const PT: usize,
    const R: usize,
    const RT: usize,
    const H: usize,
> {
    hidden: Box<[Hash; H]>,
    random: TreePRF<{ RT }>,
    ph: PhantomData<D>,
}

/// Executes the preprocessing (in-the-head) phase once.
///
/// Returns a commitment to the view of all players.
fn preprocess<D: Domain, const P: usize, const PT: usize>(
    seed: &[u8; KEY_SIZE], // random tape used for phase
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    inputs: usize,
) -> Hash {
    // the root PRF from which each players random tape is derived using a PRF tree
    let root: TreePRF<PT> = TreePRF::new(*seed);
    let keys: Box<[_; P]> = root.expand();

    // create a view for every player
    let views: Box<[View; P]> = arr_map!(&keys, |key: &Option<[u8; KEY_SIZE]>| View::new_keyed(
        key.as_ref().unwrap()
    ));

    // generate the beaver triples and write the corrected shares to the transcript
    let mut rngs: Box<[ViewRNG; P]> = arr_map!(&views, |view: &View| view.rng(LABEL_RNG_BEAVER));
    let mut hasher = RingHasher::new();
    let mut exec: prover::PreprocessingExecution<D, _, _, P, false> =
        prover::PreprocessingExecution::new(&mut rngs, &mut hasher, inputs, program);

    // process entire program
    exec.finish();

    // return the transcript hash for the corrections
    hasher.finalize()
}

impl<
        D: Domain,
        const P: usize,
        const PT: usize,
        const R: usize,
        const RT: usize,
        const H: usize,
    > PreprocessedProof<D, P, PT, R, RT, H>
{
    pub fn verify(
        &self,
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: usize,
    ) -> Option<&[Hash; H]> {
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

        let mut hashes: Vec<Option<Hash>> = Vec::with_capacity(keys.len());
        keys.par_iter()
            .map(|seed| seed.map(|seed| preprocess::<D, P, PT>(&seed, program, inputs)))
            .collect_into_vec(&mut hashes);

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

    pub fn new(
        seed: [u8; KEY_SIZE],
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: usize,
    ) -> Self {
        // define PRF tree and obtain key material for every pre-processing execution
        let root: TreePRF<RT> = TreePRF::new(seed);
        let keys: Box<[_; R]> = root.expand();

        // generate hashes of every pre-processing execution

        let mut hashes: Vec<Hash> = Vec::with_capacity(keys.len());
        keys.par_iter()
            .map(|seed| preprocess::<D, P, PT>(seed.as_ref().unwrap(), program, inputs))
            .collect_into_vec(&mut hashes);

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
    use super::super::algebra::gf2::GF2P8;
    use super::*;

    use rand::Rng;

    #[test]
    fn test_preprocessing_n8() {
        let program = vec![Instruction::Mul(0, 1, 2); 1024]; // maybe generate random program?
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let proof = PreprocessedProof::<GF2P8, 8, 8, 252, 256, 44>::new(seed, &program, 1024);
        assert!(proof.verify(&program, 1024).is_some());
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::super::algebra::gf2::GF2P8;
    use super::*;

    use test::Bencher;

    const MULT: usize = 100_000;

    /*
    /// Benchmark proof generation of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =  64 (simulated players)
    /// M =  23 (number of pre-processing executions)
    /// t =  23 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_gen_n64(b: &mut Bencher) {
        b.iter(|| PreprocessedProof::<GF2P8, 64, 64, 631, 1024, 23>::new(BEAVER, [0u8; KEY_SIZE]));
    }
    */

    /// Benchmark proof generation of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =   8 (simulated players)
    /// M = 252 (number of pre-processing executions)
    /// t =  44 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_gen_n8(b: &mut Bencher) {
        let program = vec![Instruction::Mul(0, 1, 2); MULT];
        b.iter(|| {
            PreprocessedProof::<GF2P8, 8, 8, 252, 256, 44>::new([0u8; KEY_SIZE], &program, 64)
        });
    }

    /*
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
    */

    /// Benchmark proof verification of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =   8 (simulated players)
    /// M = 252 (number of pre-processing executions)
    /// t =  44 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_verify_n8(b: &mut Bencher) {
        let program = vec![Instruction::Mul(0, 1, 2); MULT];
        let proof =
            PreprocessedProof::<GF2P8, 8, 8, 252, 256, 44>::new([0u8; KEY_SIZE], &program, 64);
        b.iter(|| proof.verify(&program, 64));
    }
}
