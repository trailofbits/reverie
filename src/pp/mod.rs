use super::crypto::*;
use super::fs::*;
use super::RingElement;

use std::marker::PhantomData;

use typenum::{PowerOfTwo, Unsigned};

struct Preprocessed<N> {
    seed: [u8; KEY_SIZE], // seed used to generate pre-processing randomness
    commitment: Hash,     // resulting hash of commitments to pre-processing views
    _phantom: PhantomData<N>,
}

fn preprocess<E: RingElement, N: Unsigned, M: Unsigned + PowerOfTwo>(
    inputs: u64, // number of input/output sharings
    beaver: u64, // number of Beaver multiplication triples
    seed: [u8; 16],
) -> Preprocessed<N> {
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
    let mut prngs: Vec<ViewRNG> = views.iter().map(|v| v.rng()).collect();

    // obtain a scope for correction bits (0th player)
    {
        let mut scope: Scope = views[0].scope("correction".as_bytes());

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

            // product correction element
            let correction = product_mask - left_mask * right_mask;

            // add to player 0 view
            scope.update(&correction.pack().to_le_bytes());
        }
    }

    // aggregate every view commitment into a single commitment to the entire pre-processing
    let mut agg: View = View::new();
    {
        let mut scope: Scope = agg.scope("view_commitment".as_bytes());
        for j in 0..N::to_usize() {
            scope.update(views[j].hash().as_bytes())
        }
    }

    Preprocessed {
        seed,
        commitment: agg.hash(),
        _phantom: PhantomData,
    }
}
