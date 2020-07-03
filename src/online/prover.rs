use super::*;
use super::{Instruction, Proof, RingHasher, Run, View, ViewRNG, KEY_SIZE};

use crate::algebra::{Domain, RingElement, RingModule, Serializable, Sharing};
use crate::consts::{LABEL_RNG_BEAVER, LABEL_RNG_MASKS};
use crate::consts::{LABEL_RNG_OPEN_ONLINE, LABEL_SCOPE_ONLINE_TRANSCRIPT};
use crate::crypto::TreePRF;
use crate::pp::prover::PreprocessingExecution;
use crate::pp::Preprocessing;
use crate::util::*;

use blake3::Hash;
use rayon::prelude::*;

pub(super) struct StoredTranscript<T: Serializable> {
    msgs: Vec<T>,
    hasher: RingHasher<T>,
}

impl<T: Serializable> StoredTranscript<T> {
    pub fn new() -> Self {
        StoredTranscript {
            msgs: Vec::new(),
            hasher: RingHasher::new(),
        }
    }

    pub fn end(self) -> (Hash, Vec<T>) {
        (self.hasher.finalize(), self.msgs)
    }
}

impl<T: Serializable + Copy> Writer<T> for StoredTranscript<T> {
    fn write(&mut self, message: &T) {
        self.hasher.update(&message);
        self.msgs.push(*message);
    }
}

impl<T: Serializable + Copy> Writer<T> for Vec<T> {
    fn write(&mut self, message: &T) {
        self.push(*message);
    }
}

impl<D: Domain, const N: usize, const NT: usize, const R: usize> Proof<D, N, NT, R> {
    pub fn new(
        seeds: &[[u8; KEY_SIZE]; R],
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: &[<D::Sharing as RingModule>::Scalar],
    ) -> Proof<D, N, NT, R> {
        // execute the online phase R times
        let mut execs: Vec<(
            (Hash, Vec<D::Sharing>),
            TreePRF<NT>,
            Option<Vec<D::Batch>>,
            Option<Vec<<D::Sharing as RingModule>::Scalar>>,
            usize,
        )> = Vec::with_capacity(R);

        #[cfg(test)]
        let runs = seeds.iter();

        #[cfg(not(test))]
        let runs = seeds.par_iter();

        let runs = runs.map(|seed| {
            // expand seed into RNG keys for players
            let tree: TreePRF<NT> = TreePRF::new(*seed);
            let keys: Box<[[u8; KEY_SIZE]; N]> =
                arr_map!(&tree.expand(), |x: &Option<[u8; KEY_SIZE]>| x.unwrap());

            // create pre-processing instance
            let views: Box<[View; N]> = arr_map!(&keys, |key| View::new_keyed(key));

            let mut rngs: Box<[ViewRNG; N]> =
                arr_map!(&views, |view| { view.rng(LABEL_RNG_BEAVER) });

            let mut corrections = Vec::<D::Batch>::new();

            let preprocessing: PreprocessingExecution<D, ViewRNG, _, N, true> =
                PreprocessingExecution::new(&mut *rngs, &mut corrections, inputs.len(), program);

            // mask the inputs
            let mut wires: Vec<<D::Sharing as RingModule>::Scalar> =
                Vec::with_capacity(inputs.len());

            for (i, input) in inputs.iter().enumerate() {
                let mask: D::Sharing = preprocessing.mask(i);
                wires.push(*input - mask.reconstruct());
            }

            // execute program one instruction at a time
            let mut transcript = StoredTranscript::<D::Sharing>::new();

            execute::<D, StoredTranscript<D::Sharing>, _, N>(
                &mut transcript,
                wires.clone(),
                preprocessing,
                program,
            );
            (
                transcript.end(),  // transcript for the broadcast channel
                tree,              // PRF for deriving all random tapes
                Some(corrections), // player zero corrections extracted from pre-processing
                Some(wires),       // the initial wire values (masked witness)
                0,                 // player to omit (unfilled)
            )
        });

        #[cfg(test)]
        execs.extend(runs);

        #[cfg(not(test))]
        runs.collect_into_vec(&mut execs);

        // extract which players to omit in every run (Fiat-Shamir)
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for run in execs.iter() {
                scope.join(&(run.0).0);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        for i in 0..R {
            execs[i].4 = random_usize::<_, N>(&mut rng);

            #[cfg(test)]
            println!("omitted: {}", execs[i].4);
        }

        // compile views of opened players
        let mut runs: Vec<Run<D, N, NT>> = Vec::with_capacity(R);
        execs
            .par_iter_mut()
            .map(|run| {
                let omitted = run.4;

                // clear the player 0 corrections if not opened
                let mut corrections = run.2.take().unwrap();
                if omitted == 0 {
                    corrections.clear();
                }

                // pad transcript to batch multiple
                // (not added to the transcript hash)
                let transcript = &mut (run.0).1;
                let num_batches =
                    (transcript.len() + D::Batch::DIMENSION - 1) / D::Batch::DIMENSION;
                transcript.resize(num_batches * D::Batch::DIMENSION, D::Sharing::ZERO);

                // extract broadcast messages from omitted player
                // NOTE: Done by transposing groups of sharings back into per-player-batches then saving the appropriate batch
                let mut broadcast = Vec::with_capacity(num_batches);
                let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
                for i in 0..num_batches {
                    D::convert_inv(
                        &mut batches,
                        &transcript[i * D::Batch::DIMENSION..(i + 1) * D::Batch::DIMENSION],
                    );
                    broadcast.push(batches[omitted]);
                }

                // puncture the PRF to hide the random tape of the hidden player
                Run {
                    corrections,
                    broadcast,
                    inputs: run.3.take().unwrap(),
                    open: run.1.clone().puncture(omitted),
                }
            })
            .collect_into_vec(&mut runs);

        Proof { runs }
    }
}
