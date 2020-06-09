use super::crypto::*;
use super::fs::*;
use super::RingElement;

mod constants;

use constants::*;

use std::marker::PhantomData;

use generic_array::{ArrayLength, GenericArray};
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
pub struct PreprocessedProof<N, R: Unsigned, O: ArrayLength<Hash>, M: Unsigned + PowerOfTwo> {
    // seed: [u8; KEY_SIZE],               // seed used to generate pre-processing phase
    commitments: GenericArray<Hash, O>, // commitments to the un-opened views in the commitment phase
    prf: TreePRF<M>,                    // punctured PRF used for verification of selected views

    // consume type parameters
    _phantom1: PhantomData<N>,
    _phantom2: PhantomData<R>,
}

/// Executes the preprocessing (in-the-head) phase once.
///
/// Returns a commitment to the view of all players.
pub fn preprocess<E: RingElement, N: Unsigned, M: Unsigned + PowerOfTwo>(
    beaver: u64,          // number of Beaver multiplication triples
    seed: [u8; KEY_SIZE], // random tape used for phase
) -> Hash {
    assert!(
        M::to_usize() >= N::to_usize(),
        "tree-prf too small for player count"
    );
    assert!(
        M::to_usize() / 2 <= N::to_usize(),
        "sub-optimal parameters for tree-prf"
    );

    // the root PRF from which each players random tape is derived using a PRF tree
    let root: TreePRF<M> = TreePRF::new(seed);
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
    let mut agg: View = View::new();
    {
        let mut scope: Scope = agg.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
        for j in 0..N::to_usize() {
            scope.update(views[j].hash().as_bytes())
        }
    }

    agg.hash()
}

pub fn preprocessing_batch<R: ArrayLength<Hash>>(
    beaver: u64,          // number of Beaver multiplication triples,
    seed: [u8; KEY_SIZE], // random tape used for phase
) {
}
