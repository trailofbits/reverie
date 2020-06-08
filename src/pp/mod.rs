use super::crypto::*;
use super::RingElement;

use std::marker::PhantomData;

use typenum::Unsigned;

struct Preprocessed<N> {
    seed: [u8; KEY_SIZE], // seed used to generate pre-processing randomness
    commitment: Hash,     // resulting hash of commitments to pre-processing views
    _phantom: PhantomData<N>,
}

fn preprocess<E: RingElement, N: Unsigned>(elements: u64, seed: [u8; 16]) -> Preprocessed<E, N> {
    // the root PRF from which each players random tape is derived
    let root = PRF::new(seed);

    // derive player PRFs
    let prfs: Vec<PRF> = Vec::with_capacity(N::to_usize());
    for i in 0..N::to_usize() {
        prfs.push(PRF::new(root.eval_u64(i as u64)));
    }

    // init players view commitments
    let hashers: Vec<Hasher> = Vec::with_capacity(N::to_usize());
    for i in 0..N::to_usize() {
        hashers.push(commit())
    }

    // generate Beaver triples
    for i in 0..elements {}

    Preprocessed {
        seed,
        _phantom: PhantomData,
    }
}
