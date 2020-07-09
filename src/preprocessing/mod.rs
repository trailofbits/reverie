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

use rayon::prelude::*;

pub(crate) trait Preprocessing<D: Domain> {
    fn mask(&self, idx: usize) -> D::Sharing;

    fn next_ab_gamma(&mut self) -> D::Sharing;
}

/// Represents repeated execution of the preprocessing phase.
/// The preprocessing phase is executed R times, then fed to a random oracle,
/// which dictates the subset of executions to open.
///
/// - N  : number of players
/// - NT : size of PRF tree for players
/// - R  : number of repetitions
/// - RT : size of PRF tree for repetitions
/// - H  : hidden views (repetitions of online phase)
pub struct Proof<
    D: Domain,
    const P: usize,
    const PT: usize,
    const R: usize,
    const RT: usize,
    const H: usize,
> {
    hidden: Box<[Hash; H]>,  // commitments to the hidden pre-processing executions
    random: TreePRF<{ RT }>, // punctured PRF used to derive the randomness for the opened pre-processing executions
    ph: PhantomData<D>,
}

/// Represents the randomness for the preprocessing executions used during the online execution.
///
/// Reusing a PreprocessingOutput for multiple proofs violates zero-knowledge:
/// leaking the witness / input to the program.
///
/// For this reason PreprocessingOutput does not implement Copy/Clone
/// and the online phase takes ownership of the struct, nor does it expose any fields.
pub struct PreprocessingOutput<D: Domain, const H: usize, const N: usize> {
    pub(crate) seeds: [[u8; KEY_SIZE]; H],
    ph: PhantomData<D>,
}

impl<D: Domain, const H: usize, const N: usize> PreprocessingOutput<D, H, N> {
    // used during testing
    #[cfg(test)]
    pub(crate) fn dummy() -> Self {
        PreprocessingOutput {
            seeds: [[0u8; KEY_SIZE]; H],
            ph: PhantomData,
        }
    }
}

// Executes the preprocessing (in-the-head) phase once.
//
// Returns a commitment to the view of all players.
fn preprocess<D: Domain, const N: usize, const NT: usize>(
    seed: &[u8; KEY_SIZE], // random tape used for phase
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    inputs: usize,
) -> Hash {
    // the root PRF from which each players random tape is derived using a PRF tree
    let root: TreePRF<NT> = TreePRF::new(*seed);
    let keys: Box<[_; N]> = root.expand();

    // create a view for every player
    let mut views: Box<[View; N]> = arr_map!(
        &keys,
        |key: &Option<[u8; KEY_SIZE]>| View::new_keyed(key.as_ref().unwrap())
    );

    // generate the beaver triples and write the corrected shares to player0 transcript
    {
        let mut rngs: Box<[ViewRNG; N]> =
            arr_map!(&views, |view: &View| view.rng(LABEL_RNG_PREPROCESSING));
        let mut corr: Scope = views[0].scope(LABEL_SCOPE_CORRECTION);
        let mut exec: prover::PreprocessingExecution<D, _, _, N, false> =
            prover::PreprocessingExecution::new(&mut rngs, &mut corr, inputs, program);

        // process entire program
        exec.finish();
    }

    // return the hash of the commitments to player state
    let mut hasher = Hasher::new();
    for view in views.iter() {
        hasher.update(
            view.hash().as_bytes(), // if the view is keyed, the hash serves as a commitment
        );
    }
    hasher.finalize()
}

impl<
        D: Domain,
        const N: usize,
        const NT: usize,
        const R: usize,
        const RT: usize,
        const H: usize,
    > Proof<D, N, NT, R, RT, H>
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
            .map(|seed| seed.map(|seed| preprocess::<D, N, NT>(&seed, program, inputs)))
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

    /// Create a new pre-processing proof.
    ///
    ///
    pub fn new(
        seed: [u8; KEY_SIZE],
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: usize,
    ) -> (Self, PreprocessingOutput<D, H, N>) {
        // define PRF tree and obtain key material for every pre-processing execution
        let root: TreePRF<RT> = TreePRF::new(seed);
        let keys: Box<[_; R]> = root.expand();

        // generate transcript hashes of every pre-processing execution
        let mut hashes: Vec<Hash> = Vec::with_capacity(keys.len());
        keys.par_iter()
            .map(|seed| preprocess::<D, N, NT>(seed.as_ref().unwrap(), program, inputs))
            .collect_into_vec(&mut hashes);

        // send the pre-processing commitments to the random oracle, receive challenges
        let mut challenge_rng = {
            let mut oracle: View = View::new();
            let mut scope: Scope = oracle.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in &hashes {
                scope.join(&hash);
            }
            mem::drop(scope);
            oracle.rng(LABEL_RNG_OPEN_PREPROCESSING)
        };

        // interpret the oracle response as a subset of indexes to hide
        // (implicitly: which executions to open)
        let hide: [usize; H] = random_subset::<_, R, H>(&mut challenge_rng);

        // puncture the prf at the hidden indexes
        // (implicitly: pass the randomness for all other executions to the verifier)
        let mut random = root.clone();
        for i in hide.iter() {
            random = random.puncture(*i);
        }

        // extract hashes for the hidden evaluations
        let hidden: Box<[Hash; H]> = arr_from_iter!(&mut hide.iter().map(|i| hashes[*i].clone()));

        // extract pre-processing key material for the hidden views
        // (returned to the prover for use in the online phase)
        let mut seeds: [[u8; KEY_SIZE]; H] = [[0u8; KEY_SIZE]; H];
        for (to, from) in hide.iter().enumerate() {
            seeds[to] = keys[*from].unwrap();
        }

        (
            // proof (used by the verifier)
            Proof {
                hidden,
                random,
                ph: PhantomData,
            },
            // randomness used to re-executed the hidden views (used by the prover)
            PreprocessingOutput {
                seeds,
                ph: PhantomData,
            },
        )
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
        let proof = Proof::<GF2P8, 8, 8, 252, 256, 44>::new(seed, &program, 1024);
        assert!(proof.0.verify(&program, 1024).is_some());
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
