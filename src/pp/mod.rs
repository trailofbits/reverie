use super::crypto::*;
use super::fs::*;
use super::RingElement;

use std::marker::PhantomData;

use typenum::Unsigned;

struct Preprocessed<N> {
    seed: [u8; KEY_SIZE], // seed used to generate pre-processing randomness
    commitment: Hash,     // resulting hash of commitments to pre-processing views
    _phantom: PhantomData<N>,
}

fn preprocess<E: RingElement, N: Unsigned>(elements: u64, seed: [u8; 16]) -> Preprocessed<N> {
    // the root PRF from which each players random tape is derived
    let root = PRF::new(seed);

    // create a view for every player
    let mut views: Vec<View> = Vec::with_capacity(N::to_usize());
    for i in 0..N::to_usize() {
        views.push(View::new(root.eval_u64(i as u64)));
    }

    // derive PRNG for every player
    let prngs: Vec<ViewRNG> = views.iter().map(|v| v.rng()).collect();

    // obtain a scope for correction bits (0th player)
    let scope: Scope = views[0].scope("correction".as_bytes());

    // generate correction bits for Beaver triples
    for i in 0..elements {}

    unimplemented!()
}
