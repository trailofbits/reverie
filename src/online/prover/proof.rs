use super::*;

use crate::algebra::{Domain, RingModule, Serializable, Sharing};
use crate::consts::{LABEL_RNG_OPEN_ONLINE, LABEL_SCOPE_ONLINE_TRANSCRIPT};
use crate::crypto::TreePRF;
use crate::util::*;

use std::io::{sink, Sink};
use std::marker::PhantomData;

use blake3::Hash;
use rayon::prelude::*;

pub struct Proof<D: Domain, const N: usize, const NT: usize> {
    _ph: PhantomData<D>,
}

impl<D: Domain, const N: usize, const NT: usize> Proof<D, N, NT> {
    pub fn new(
        seeds: &[[u8; KEY_SIZE]],
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: &[<D::Sharing as RingModule>::Scalar],
    ) -> Proof<D, N, NT> {
        // expand keys for every player
        let keys: Vec<Box<[[u8; KEY_SIZE]; N]>> = seeds
            .par_iter()
            .map(|seed| {
                let tree: TreePRF<NT> = TreePRF::new(*seed);
                arr_map!(&tree.expand(), |x: &Option<[u8; KEY_SIZE]>| x.unwrap())
            })
            .collect();

        // first execution to obtain challenges
        let hashes: Vec<Hash> = keys
            .par_iter()
            .map(|keys| {
                let mut transcript = RingHasher::<D::Sharing>::new();

                let mut exec =
                    Execution::<D, Sink, _, N, NT>::new(keys, sink(), inputs, &mut transcript);
                for ins in program {
                    exec.step(ins);
                }
                transcript.finalize()
            })
            .collect();

        // extract which players to open
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for hash in hashes.iter() {
                scope.join(hash);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        let mut hidden: Vec<usize> = Vec::with_capacity(seeds.len());
        for _ in 0..seeds.len() {
            hidden.push(random_usize::<_, N>(&mut rng));
        }

        Proof { _ph: PhantomData }
    }
}

/*
impl<B: RingBatch, const N: usize, const NT: usize> Proof<B, N, NT> {
    ///
    /// - seeds: A list of PRNG seeds used for every execution (of both pre-processing an online).
    pub fn new(
        seeds: &[[u8; KEY_SIZE]],
        program: &[Instruction<B::Element>],
        inputs: &RingVector<B>,
    ) -> Proof<B, N, NT> {
        // expand keys for every player
        let keys: Vec<Box<[[u8; KEY_SIZE]; N]>> = seeds
            .par_iter()
            .map(|seed| {
                let tree: TreePRF<NT> = TreePRF::new(*seed);
                arr_map!(&tree.expand(), |x: &Option<[u8; KEY_SIZE]>| x.unwrap())
            })
            .collect();

        // first execution to obtain challenges
        let hashes: Vec<Hash> = keys
            .par_iter()
            .map(|keys| {
                let mut transcript = ElementHasher::<B>::new();
                let mut exec = Execution::<B, ElementHasher<B>, N, NT>::new(
                    keys,
                    &mut transcript,
                    inputs,
                    1024,
                );
                for ins in program {
                    exec.step(ins);
                }
                transcript.finalize()
            })
            .collect();

        // extract which players to open
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for hash in hashes.iter() {
                scope.join(hash);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        let mut hidden: Vec<usize> = Vec::with_capacity(seeds.len());
        for _ in 0..seeds.len() {
            hidden.push(random_usize::<_, N>(&mut rng));
        }

        // second execution to obtain proof
        let jobs: Vec<(&usize, &Box<[[u8; KEY_SIZE]; N]>)> =
            hidden.iter().zip(keys.iter()).collect();
        let transcripts: Vec<RingVector<B>> = jobs
            .par_iter()
            .map(|(hide, keys)| {
                let mut transcript = SavedTranscript::new(**hide);
                let mut exec = Execution::<B, SavedTranscript<B, N>, N, NT>::new(
                    keys,
                    &mut transcript,
                    inputs,
                    1024,
                );
                for ins in program {
                    exec.step(ins);
                }
                transcript.inner()
            })
            .collect();

        Proof {
            _ph: PhantomData,
            transcripts,
        }
    }
}
*/
