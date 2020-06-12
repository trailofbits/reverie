use super::crypto::*;
use super::fs::*;
use super::RingElement;

mod constants;

use constants::*;

use std::marker::PhantomData;
use std::mem;

use rand_core::RngCore;

use generic_array::{ArrayLength, GenericArray};
use rayon::prelude::*;
use typenum::{PowerOfTwo, Unsigned};

/// Represents repeated execution of the pre-processing phase.
/// The pre-precessing phase is executed R times, then fed to a random oracle,
/// which dictates the subset of executions to open.
///
/// The proof is generic over:
///
/// - N : Number of players in the simulated protocol.
/// - NT: Size of the PRF tree (should be greater/equal N)
/// - R : The number of repetitions for soundness.
/// - RT: Size of the PRF tree (should be greater/equal R)
/// - H : The number of repetitions not to open (repetitions of online phase)
///
/// The proof is verified by re-executing the pre-processing phase executions
/// for which the punctured PRF can be evaluated.
pub struct PreprocessedProof<
    E: RingElement,
    N: Unsigned,
    NT: Unsigned + PowerOfTwo,
    R: Unsigned,
    RT: Unsigned + PowerOfTwo,
    H: ArrayLength<Hash>,
> {
    hashes: GenericArray<Hash, H>, // commitments to the un-opened views in the commitment phase
    prf: TreePRF<RT>,              // punctured PRF used for verification of selected views

    // consume type parameters
    _phantom1: PhantomData<N>,
    _phantom2: PhantomData<NT>,
    _phantom3: PhantomData<R>,
    _phantom4: PhantomData<E>,
}

fn random_subset<Mod: Unsigned, Samples: Unsigned, R: RngCore>(rng: &mut R) -> Vec<usize> {
    let mut member: Vec<bool> = vec![false; Mod::to_usize()];
    let mut set: Vec<usize> = Vec::with_capacity(Samples::to_usize());
    while set.len() < Samples::to_usize() {
        // generate a 128-bit integer (to minimize statistical bias)
        let mut le_bytes: [u8; 16] = [0u8; 16];
        rng.fill_bytes(&mut le_bytes);

        // reduce mod the number of repetitions
        let n: u128 = u128::from_le_bytes(le_bytes) % (Mod::to_u64() as u128);
        let n: usize = n as usize;

        // if not in set, add to the vector
        if !mem::replace(&mut member[n as usize], true) {
            set.push(n);
        }
    }

    // ensure a canonical ordering (for comparisons)
    debug_assert_eq!(set.len(), Samples::to_usize());
    set.sort();
    set
}

/// Executes the preprocessing (in-the-head) phase once.
///
/// Returns a commitment to the view of all players.
fn preprocess<E: RingElement, N: Unsigned, NT: Unsigned + PowerOfTwo>(
    beaver: u64,          // number of Beaver multiplication triples
    seed: [u8; KEY_SIZE], // random tape used for phase
) -> Hash {
    assert!(
        NT::to_usize() >= N::to_usize(),
        "tree-prf too small for player count"
    );
    assert!(
        NT::to_usize() / 2 <= N::to_usize(),
        "sub-optimal parameters for tree-prf"
    );

    // the root PRF from which each players random tape is derived using a PRF tree
    let root: TreePRF<NT> = TreePRF::new(seed);
    let keys = root.expand(N::to_usize());

    // create a view for every player
    let mut views: Vec<View> = Vec::with_capacity(N::to_usize());
    for key in keys {
        views.push(View::new_keyed(key.unwrap()));
    }

    // derive PRNG for every player
    let mut prngs: Vec<ViewRNG> = views.iter().map(|v| v.rng(LABEL_RNG_BEAVER)).collect();

    // obtain a scope for correction bits (0th player)
    {
        let mut scope: Scope = views[0].scope(LABEL_SCOPE_CORRECTION);

        // generate correction bits for Beaver triples
        for _ in 0..beaver {
            let mut left_mask = E::zero();
            let mut right_mask = E::zero();
            let mut product_mask = E::zero();

            for j in 0..N::to_usize() {
                let rng: &mut ViewRNG = &mut prngs[j];
                let left = E::gen(rng);
                let right = E::gen(rng);
                let product = E::gen(rng);

                left_mask = left_mask + left;
                right_mask = right_mask + right;
                product_mask = product_mask + product;
            }

            // product correction element:
            // product_mask = correction + left_mask * right_mask
            let correction = product_mask - left_mask * right_mask;

            // add to player 0 view
            scope.update(&correction.pack().to_le_bytes());
        }
    }

    // aggregate every view commitment into a single commitment to the entire pre-processing
    let mut global: View = View::new();
    {
        let mut scope: Scope = global.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
        for j in 0..N::to_usize() {
            scope.update(views[j].hash().as_bytes())
        }
    }
    global.hash()
}

impl<
        E: RingElement,
        N: Unsigned,
        NT: Unsigned + PowerOfTwo,
        R: Unsigned,
        RT: Unsigned + PowerOfTwo,
        H: ArrayLength<Hash>,
    > PreprocessedProof<E, N, NT, R, RT, H>
{
    pub fn verify(&self, beaver: u64) -> Option<&GenericArray<Hash, H>> {
        debug_assert!(R::to_usize() >= H::to_usize());

        // derive keys and hidden execution indexes
        let keys = self.prf.expand(R::to_usize());
        let mut hidden: Vec<usize> = Vec::with_capacity(H::to_usize());
        let mut opened: Vec<usize> = Vec::with_capacity(R::to_usize() - H::to_usize());
        for (i, key) in keys.iter().enumerate() {
            if key.is_none() {
                hidden.push(i)
            } else {
                opened.push(i)
            }
        }

        // prover must open exactly R-H repetitions
        if hidden.len() != H::to_usize() {
            return None;
        }
        debug_assert_eq!(hidden.len() + opened.len(), R::to_usize());

        // recompute the opened views
        let mut hashes: Vec<Option<Hash>> = keys
            .par_iter()
            .map(|seed| seed.map(|seed| preprocess::<E, N, NT>(beaver, seed)))
            .collect();

        // copy over the provided hashes from the hidden views
        for (&i, hash) in hidden.iter().zip(self.hashes.iter()) {
            assert!(hashes[i].is_none());
            hashes[i] = Some(*hash);
        }

        // interleave the proved hashes with the recomputed ones
        let mut global: View = View::new();
        {
            let mut scope: Scope = global.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in &hashes {
                scope.update(hash.unwrap().as_bytes());
            }
        }

        // accept if the hidden indexes where computed correctly (Fiat-Shamir transform)
        if hidden == random_subset::<R, H, _>(&mut global.rng(LABEL_RNG_OPEN_PREPROCESSING)) {
            Some(&self.hashes)
        } else {
            None
        }
    }

    pub fn new(beaver: u64, seed: [u8; KEY_SIZE]) -> Self {
        debug_assert!(R::to_usize() >= H::to_usize());

        // define PRF tree and obtain key material for every pre-processing execution
        let root: TreePRF<RT> = TreePRF::new(seed);
        let keys = root.expand(R::to_usize());

        // generate hashes of every pre-processing execution
        let hashes: Vec<Hash> = keys
            .par_iter()
            .map(|seed| preprocess::<E, N, NT>(beaver, seed.unwrap()))
            .collect();

        // add every pre-processing execution to a global view
        let mut global: View = View::new();
        {
            let mut scope: Scope = global.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in &hashes {
                scope.update(hash.as_bytes())
            }
        }

        // extract random indexes not to open (rejection sampling)
        let hide = random_subset::<R, H, _>(&mut global.rng(LABEL_RNG_OPEN_PREPROCESSING));
        debug_assert_eq!(hide.len(), H::to_usize());

        // puncture the root prf
        let mut punctured = root.clone();
        for i in &hide {
            punctured = punctured.puncture(*i);
        }

        // sanity check
        debug_assert_eq!(
            punctured
                .expand(R::to_usize())
                .into_iter()
                .map(|x| x.is_some() as usize)
                .sum::<usize>(),
            R::to_usize() - H::to_usize()
        );

        // extract hashes for the hidden evaluations
        let mut hidden_hashes: Vec<Hash> = Vec::with_capacity(H::to_usize());
        for i in &hide {
            hidden_hashes.push(hashes[*i].clone());
        }

        // combine into the proof
        PreprocessedProof {
            hashes: GenericArray::clone_from_slice(&hidden_hashes[..]),
            prf: punctured,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
            _phantom3: PhantomData,
            _phantom4: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::BitField;
    use super::*;

    use rand::Rng;
    use typenum::consts::*;

    const BEAVER: u64 = 1000 / 64;

    #[test]
    fn test_preprocessing_n8() {
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let proof = PreprocessedProof::<BitField, U8, U8, U252, U256, U44>::new(BEAVER, seed);
        assert!(proof.verify(BEAVER).is_some());
    }

    #[test]
    fn test_preprocessing_n64() {
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let proof = PreprocessedProof::<BitField, U64, U64, U631, U1024, U23>::new(BEAVER, seed);
        assert!(proof.verify(BEAVER).is_some());
    }
}

#[cfg(test)]
#[cfg(feature = "unstable")]
mod benchmark {
    use super::super::BitField;
    use super::*;

    use test::Bencher;
    use typenum::consts::*;

    const BEAVER: u64 = 100_000 / 64;

    /// Benchmark proof generation of pre-processing using parameters from the paper
    /// (Table 1. p. 10, https://eprint.iacr.org/2018/475/20190311:173838)
    ///
    /// n =  64 (simulated players)
    /// M =  23 (number of pre-processing executions)
    /// t =  23 (online phase executions (hidden pre-processing executions))
    #[bench]
    fn bench_preprocessing_proof_gen_n64(b: &mut Bencher) {
        b.iter(|| {
            PreprocessedProof::<BitField, U64, U64, U631, U1024, U23>::new(BEAVER, [0u8; KEY_SIZE])
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
        b.iter(|| {
            PreprocessedProof::<BitField, U8, U8, U252, U256, U44>::new(BEAVER, [0u8; KEY_SIZE])
        });
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
            PreprocessedProof::<BitField, U64, U64, U631, U1024, U23>::new(BEAVER, [0u8; KEY_SIZE]);
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
        let proof =
            PreprocessedProof::<BitField, U8, U8, U252, U256, U44>::new(BEAVER, [0u8; KEY_SIZE]);
        b.iter(|| proof.verify(BEAVER));
    }
}
