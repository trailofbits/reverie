use super::crypto::*;
use super::fs::*;
use super::RingElement;

mod constants;

use constants::*;

use std::collections::HashSet;
use std::marker::PhantomData;

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
/// - O : The number of repetitions not to open (repetitions of online phase)
///
/// The proof is verified by re-executing the pre-processing phase executions
/// for which the punctured PRF can be evaluated.
pub struct PreprocessedProof<
    E: RingElement,
    N: Unsigned,
    NT: Unsigned + PowerOfTwo,
    R: Unsigned,
    RT: Unsigned + PowerOfTwo,
    O: ArrayLength<Hash>,
> {
    hashes: GenericArray<Hash, O>, // commitments to the un-opened views in the commitment phase
    prf: TreePRF<RT>,              // punctured PRF used for verification of selected views

    // consume type parameters
    _phantom1: PhantomData<N>,
    _phantom2: PhantomData<NT>,
    _phantom3: PhantomData<R>,
    _phantom4: PhantomData<E>,
}

fn random_subset<Mod: Unsigned, Samples: Unsigned, R: RngCore>(rng: &mut R) -> HashSet<usize> {
    let mut set: HashSet<usize> = HashSet::new();
    {
        while set.len() < Samples::to_usize() {
            // generate a 128-bit integer (to minimize statistical bias)
            let mut le_bytes: [u8; 16] = [0u8; 16];
            rng.fill_bytes(&mut le_bytes);

            // reduce mod the number of repetitions
            let n: u128 = u128::from_le_bytes(le_bytes) % (Mod::to_u64() as u128);
            set.insert(n as usize);
        }
    }
    debug_assert_eq!(set.len(), Samples::to_usize());
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
        O: ArrayLength<Hash>,
    > PreprocessedProof<E, N, NT, R, RT, O>
{
    pub fn verify(&self, beaver: u64) -> bool {
        debug_assert!(R::to_usize() >= O::to_usize());

        // derive keys and hidden execution indexes
        let keys = self.prf.expand(R::to_usize());
        let mut hide: Vec<usize> = Vec::with_capacity(O::to_usize());
        let mut open: Vec<usize> = Vec::with_capacity(R::to_usize() - O::to_usize());
        for (i, key) in keys.iter().enumerate() {
            if key.is_none() {
                hide.push(i)
            } else {
                open.push(i)
            }
        }

        // prover must open exactly n-t views
        if hide.len() != O::to_usize() {
            return false;
        }

        // recompute the opened views
        let mut hashes: Vec<Option<Hash>> = keys
            .par_iter()
            .map(|seed| seed.map(|seed| preprocess::<E, N, NT>(beaver, seed)))
            .collect();

        // copy over the provided hashes from the hidden views
        for (i, hash) in hide.iter().zip(self.hashes.iter()) {
            assert!(hashes[*i].is_none());
            hashes[*i] = Some(*hash);
        }

        // interleave the proved hashes with the recomputed ones
        let mut global: View = View::new();
        {
            let mut scope: Scope = global.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in hashes {
                match hash {
                    None => return false,
                    Some(hash) => {
                        scope.update(hash.as_bytes());
                    }
                }
            }
        }

        // recompute the hidden indexes
        let hide: HashSet<usize> =
            random_subset::<R, O, _>(&mut global.rng(LABEL_RNG_OPEN_PREPROCESSING));

        // check that every hidden pre-processed phase is included in the hidden set computed
        for i in &hide {
            if !hide.contains(&i) {
                return false;
            }
        }
        true
    }

    pub fn new(beaver: u64, seed: [u8; KEY_SIZE]) -> Self {
        debug_assert!(R::to_usize() >= O::to_usize());

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
        let hide: HashSet<usize> =
            random_subset::<R, O, _>(&mut global.rng(LABEL_RNG_OPEN_PREPROCESSING));

        // puncture the root prf
        let mut punctured = root.clone();
        for i in &hide {
            punctured = punctured.puncture(*i);
        }

        // sort the hidden evaluations
        let mut hide_ordered: Vec<usize> = hide.into_iter().collect();
        hide_ordered.sort();

        // extract hashes for the hidden evaluations
        let mut hide_hashes: Vec<Hash> = Vec::with_capacity(O::to_usize());
        for i in hide_ordered {
            hide_hashes.push(hashes[i].clone());
        }

        // combine into the proof
        PreprocessedProof {
            hashes: GenericArray::clone_from_slice(&hide_hashes[..]),
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
        assert!(proof.verify(BEAVER));
    }

    #[test]
    fn test_preprocessing_n64() {
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let proof = PreprocessedProof::<BitField, U64, U64, U631, U1024, U23>::new(BEAVER, seed);
        assert!(proof.verify(BEAVER));
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

    /// Benchmark of pre-processing using parameters from the paper
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

    /// Benchmark of pre-processing using parameters from the paper
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
}
