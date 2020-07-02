use super::*;

use crate::algebra::{Domain, RingElement, RingModule, Serializable, Sharing};
use crate::consts::{LABEL_RNG_OPEN_ONLINE, LABEL_SCOPE_ONLINE_TRANSCRIPT};
use crate::crypto::TreePRF;
use crate::util::*;

use blake3::Hash;
use rayon::prelude::*;

pub struct Run<D: Domain, const N: usize, const NT: usize> {
    zero: Vec<D::Batch>, // sharings for
    msgs: Vec<D::Batch>, // messages broadcast by hidden player
    open: TreePRF<NT>,
}

pub struct Proof<D: Domain, const N: usize, const NT: usize, const R: usize> {
    runs: Vec<Run<D, N, NT>>,
}

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
            Option<(Hash, Vec<D::Batch>)>,
            usize,
        )> = Vec::with_capacity(R);

        seeds
            .par_iter()
            .map(|seed| {
                // expand seed into RNG keys for players
                let tree: TreePRF<NT> = TreePRF::new(*seed);
                let keys: Box<[[u8; KEY_SIZE]; N]> =
                    arr_map!(&tree.expand(), |x: &Option<[u8; KEY_SIZE]>| x.unwrap());

                // prepare execution environment
                let mut transcript = StoredTranscript::<D::Sharing>::new();
                let mut zero = StoredTranscript::<D::Batch>::new();
                // execute program one instruction at a time
                execute::<D, StoredTranscript<D::Batch>, StoredTranscript<D::Sharing>, N, NT>(
                    &keys,
                    &mut zero,
                    inputs,
                    &mut transcript,
                    program,
                );
                (transcript.end(), tree, Some(zero.end()), 0)
            })
            .collect_into_vec(&mut execs);

        // extract which players to open
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for run in execs.iter() {
                scope.join(&(run.0).0);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        for i in 0..R {
            execs[i].3 = random_usize::<_, N>(&mut rng);
        }

        // compile views of opened players
        let mut runs: Vec<Run<D, N, NT>> = Vec::with_capacity(R);
        execs
            .par_iter_mut()
            .map(|run| {
                let omit = run.3;

                // clear the player 0 corrections if not opened
                let mut zero = run.2.take().unwrap().1;
                if omit != 0 {
                    zero.clear();
                }

                // pad transcript to batch multiple
                // (not added to the transcript hash)
                let transcript = &mut (run.0).1;
                let num_batches =
                    (transcript.len() + D::Batch::DIMENSION - 1) / D::Batch::DIMENSION;
                transcript.resize(num_batches * D::Batch::DIMENSION, D::Sharing::ZERO);

                // extract broadcast messages from omitted player
                // done by transposing groups of sharings back into per-player-batches then saving the appropriate batch
                let mut msgs = Vec::with_capacity(num_batches);
                let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
                for i in 0..num_batches {
                    D::convert_inv(
                        &mut batches,
                        &transcript[i * D::Batch::DIMENSION..(i + 1) * D::Batch::DIMENSION],
                    );
                    msgs.push(batches[omit]);
                }

                // puncture the PRF to hide the random tape of the hidden player
                Run {
                    zero,
                    msgs,
                    open: run.1.clone().puncture(omit),
                }
            })
            .collect_into_vec(&mut runs);

        Proof { runs }
    }
}
