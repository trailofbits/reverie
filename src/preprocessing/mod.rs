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

use async_channel::{Receiver, SendError, Sender};
use async_std::task;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

async fn feed<D: Domain, PI: Iterator<Item = Instruction<D::Scalar>>>(
    chunk: usize,
    senders: &mut [Sender<Arc<Vec<Instruction<D::Scalar>>>>],
    program: &mut PI,
) -> bool {
    // next slice of program
    let ps = Arc::new(read_n(program, chunk));
    if ps.len() == 0 {
        return false;
    }

    // feed to workers
    for sender in senders {
        sender.send(ps.clone()).await.unwrap();
    }
    true
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
#[derive(Deserialize, Serialize)]
pub struct Proof<D: Domain, const N: usize, const R: usize, const H: usize> {
    hidden: Array<[u8; 32], H>, // commitments to the hidden pre-processing executions
    random: TreePRF<{ R }>, // punctured PRF used to derive the randomness for the opened pre-processing executions
    chunk_size: usize,
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
    pub(crate) seeds: Array<[u8; KEY_SIZE], H>,
    pub(crate) chunk_size: usize,
    ph: PhantomData<D>,
}

pub struct Output<const H: usize> {
    pub(crate) hidden: [Hash; H],
}

impl<D: Domain, const H: usize, const N: usize> PreprocessingOutput<D, H, N> {
    // used during testing
    #[cfg(test)]
    pub(crate) fn dummy() -> Self {
        PreprocessingOutput {
            chunk_size: 1024,
            seeds: Array::new([0u8; KEY_SIZE]),
            ph: PhantomData,
        }
    }
}

impl<D: Domain, const N: usize, const R: usize, const H: usize> Proof<D, N, R, H> {
    async fn preprocess<PI: Iterator<Item = Instruction<D::Scalar>>>(
        chunk_size: usize,
        seeds: &[[u8; KEY_SIZE]],
        mut program: PI,
    ) -> Vec<Hash> {
        async fn process<D: Domain, const N: usize>(
            root: [u8; KEY_SIZE],
            outputs: Sender<()>,
            inputs: Receiver<
                Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
            >,
        ) -> Result<Hash, SendError<()>> {
            // expand repetition seed into per-player seeds
            let mut seeds: [[u8; KEY_SIZE]; N] = [[0u8; KEY_SIZE]; N];
            TreePRF::<N>::expand_full(&mut seeds, &root);

            // create keyed views for every player
            let mut views: Array<View, N> =
                Array::from_iter(seeds.iter().map(|seed| View::new_keyed(seed)));

            // prepare pre-processing state
            let mut preprocessing: Box<prover::PreprocessingExecution<D, N, false>> =
                Box::new(prover::PreprocessingExecution::new(&views));

            loop {
                match inputs.recv().await {
                    Ok(program) => {
                        // pre-process next chunk of program and add corrections to player 0 view
                        preprocessing
                            .prove(&program[..], &mut views[0].scope(LABEL_SCOPE_CORRECTION));
                        outputs.send(()).await?;
                    }
                    Err(_) => {
                        // return a hash of all the committed views
                        return Ok(union_views(views.iter()));
                    }
                }
            }
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(R);
        let mut inputs: Vec<Sender<Arc<Vec<Instruction<D::Scalar>>>>> = Vec::with_capacity(R);
        let mut outputs = Vec::with_capacity(R);

        for seed in seeds.iter().cloned() {
            let (send_inputs, recv_inputs) = async_channel::bounded(5);
            let (send_outputs, recv_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D, N>(
                seed,
                send_outputs,
                recv_inputs,
            )));
            inputs.push(send_inputs);
            outputs.push(recv_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        scheduled += feed::<D, _>(chunk_size, &mut inputs[..], &mut program).await as usize;
        scheduled += feed::<D, _>(chunk_size, &mut inputs[..], &mut program).await as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }
            scheduled -= 1;
            scheduled += feed::<D, _>(chunk_size, &mut inputs[..], &mut program).await as usize;
        }

        // close inputs channels
        inputs.clear();

        // collect final commitments
        let mut hashes: Vec<Hash> = Vec::with_capacity(R);
        for t in tasks.into_iter() {
            hashes.push(t.await.unwrap());
        }
        hashes
    }

    pub fn verify<PI: Iterator<Item = Instruction<D::Scalar>>>(
        &self,
        program: PI,
    ) -> Option<Output<H>> {
        // derive keys and hidden execution indexes
        let mut roots: Array<Option<[u8; KEY_SIZE]>, R> = Array::new(None);
        self.random.expand(&mut roots);

        let mut opened: Vec<bool> = Vec::with_capacity(R);
        let mut hidden: Vec<usize> = Vec::with_capacity(H);
        for (i, key) in roots.iter().enumerate() {
            opened.push(key.is_some());
            if key.is_none() {
                hidden.push(i)
            }
        }

        // prover must open exactly R-H repetitions
        if hidden.len() != H {
            return None;
        }

        // recompute the opened views
        let seeds: Vec<[u8; KEY_SIZE]> = roots
            .iter()
            .filter(|v| v.is_some())
            .map(|v| v.unwrap())
            .collect();

        let opened_hashes = task::block_on(Self::preprocess(self.chunk_size, &seeds[..], program));

        // interleave the proved hashes with the recomputed ones
        let mut hashes = Vec::with_capacity(R);
        {
            let mut open_hsh = opened_hashes.iter();
            let mut hide_hsh = self.hidden.iter();
            for open in opened {
                if open {
                    hashes.push(*open_hsh.next().unwrap())
                } else {
                    hashes.push(Hash::from(*hide_hsh.next().unwrap()))
                }
            }
        }

        // feed to the Random-Oracle
        let mut challenge_prg = {
            let mut oracle: View = View::new();
            let mut scope: Scope = oracle.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in hashes.iter() {
                scope.join(hash);
            }
            mem::drop(scope);
            oracle.prg(LABEL_RNG_OPEN_PREPROCESSING)
        };

        // accept if the hidden indexes where computed correctly (Fiat-Shamir transform)
        if &hidden[..] == &random_subset::<_, R, H>(&mut challenge_prg)[..] {
            Some(Output {
                hidden: self.hidden.map(|h| Hash::from(*h)).unbox(),
            })
        } else {
            None
        }
    }

    /// Create a new pre-processing proof.
    ///
    ///
    pub fn new<PI: Iterator<Item = Instruction<D::Scalar>>>(
        global: [u8; KEY_SIZE],
        program: PI,
        chunk_size: usize,
    ) -> (Self, PreprocessingOutput<D, H, N>) {
        // expand the global seed into per-repetition roots
        let mut roots: Array<[u8; KEY_SIZE], R> = Array::new([0; KEY_SIZE]);
        TreePRF::<R>::expand_full(&mut roots, &global);

        // block and wait for hashes to compute
        let hashes = task::block_on(Self::preprocess(chunk_size, &roots[..], program));

        // send the pre-processing commitments to the random oracle, receive challenges
        let mut challenge_prg = {
            let mut oracle: View = View::new();
            let mut scope: Scope = oracle.scope(LABEL_SCOPE_AGGREGATE_COMMIT);
            for hash in hashes.iter() {
                scope.join(hash);
            }
            mem::drop(scope);
            oracle.prg(LABEL_RNG_OPEN_PREPROCESSING)
        };

        // interpret the oracle response as a subset of indexes to hide
        // (implicitly: which executions to open)
        let hide: [usize; H] = random_subset::<_, R, H>(&mut challenge_prg);

        // puncture the prf at the hidden indexes
        // (implicitly: pass the randomness for all other executions to the verifier)
        let mut tree: TreePRF<R> = TreePRF::new(global);
        for i in hide.iter().cloned() {
            tree = tree.puncture(i);
        }

        // extract hashes for the hidden evaluations
        let hidden_hashes: Array<[u8; HASH_SIZE], H> =
            Array::from_iter(hide.iter().cloned().map(|i| *hashes[i].as_bytes()));

        // extract pre-processing key material for the hidden views
        // (returned to the prover for use in the online phase)
        let mut hidden_seeds: Array<[u8; KEY_SIZE], H> = Array::new([0u8; KEY_SIZE]);
        for (to, from) in hide.iter().cloned().enumerate() {
            hidden_seeds[to] = roots[from];
        }

        (
            // proof (used by the verifier)
            Proof {
                hidden: hidden_hashes,
                random: tree,
                chunk_size,
                ph: PhantomData,
            },
            // randomness used to re-executed the hidden views (used by the prover)
            PreprocessingOutput {
                chunk_size,
                seeds: hidden_seeds,
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
        let program = vec![
            Instruction::Input(1),
            Instruction::Input(2),
            Instruction::Mul(0, 1, 2),
        ]; // maybe generate random program?
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let proof = Proof::<GF2P8, 8, 252, 44>::new(seed, program.iter().cloned(), 1000);
        assert!(proof.0.verify(program.into_iter()).is_some());
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::super::algebra::gf2::GF2P8;
    use super::*;

    use test::Bencher;

    const MULT: usize = 1_000_000;
    const CHUNK_SIZE: usize = MULT;

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
        let mut program = vec![Instruction::Input(1), Instruction::Input(2)];
        program.resize(MULT + 2, Instruction::Mul(0, 1, 2));
        b.iter(|| {
            Proof::<GF2P8, 8, 8, 252, 256, 44>::new(
                [0u8; KEY_SIZE],
                program.iter().cloned(),
                CHUNK_SIZE,
            )
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
        let mut program = vec![Instruction::Input(1), Instruction::Input(2)];
        program.resize(MULT + 2, Instruction::Mul(0, 1, 2));
        let (proof, _) = Proof::<GF2P8, 8, 8, 252, 256, 44>::new(
            [0u8; KEY_SIZE],
            program.iter().cloned(),
            CHUNK_SIZE,
        );
        b.iter(|| proof.verify(program.iter().cloned()));
    }
}
