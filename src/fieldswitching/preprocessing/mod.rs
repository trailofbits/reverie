use std::marker::PhantomData;
use std::sync::Arc;

use async_channel::{Receiver, Sender, SendError};
use async_std::task;
use serde::{Deserialize, Serialize};

use crate::{ConnectionInstruction, Instruction};
use crate::algebra::*;
use crate::consts::*;
use crate::crypto::*;
use crate::oracle::RandomOracle;
use crate::util::*;

mod util;

#[allow(clippy::module_inception)]
pub mod preprocessing;
pub mod prover;
pub mod verifier;

async fn feed<PI: Iterator<Item = ConnectionInstruction>>(
    senders: &mut [Sender<Arc<Vec<ConnectionInstruction>>>],
    connection_program: &mut PI,
) -> bool {
    // next slice of program
    let ps = Arc::new(read_n(connection_program, BATCH_SIZE));
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
/// The preprocessing phase is executed D::ONLINE_REPETITIONS times, then fed to a random oracle,
/// which dictates the subset of executions to open.
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof<D: Domain, D2: Domain> {
    hidden: Vec<Hash>, // commitments to the hidden pre-processing executions
    random: TreePRF, // punctured PRF used to derive the randomness for the opened pre-processing executions
    proof1: super::super::preprocessing::Proof<D>,
    proof2: super::super::preprocessing::Proof<D2>,
    _ph: PhantomData<D>,
    _ph2: PhantomData<D2>,
}

pub struct Run {
    pub(crate) seed: [u8; KEY_SIZE], // root seed
    pub(crate) union: Hash,
    pub(crate) commitments: Vec<Hash>, // preprocessing commitment for every player
}

/// Represents the randomness for the preprocessing executions used during the online execution.
///
/// Reusing a PreprocessingOutput for multiple proofs violates zero-knowledge:
/// leaking the witness / input to the program.
///
/// For this reason PreprocessingOutput does not implement Copy/Clone
/// and the online phase takes ownership of the struct, nor does it expose any fields.
pub struct PreprocessingOutput<D: Domain, D2: Domain> {
    pub(crate) hidden: Vec<Run>,
    pub(crate) preprocessing1: super::super::preprocessing::PreprocessingOutput<D>,
    pub(crate) preprocessing2: super::super::preprocessing::PreprocessingOutput<D2>,
}

pub struct Output<D: Domain, D2: Domain> {
    pub(crate) hidden: Vec<Hash>,
    pub(crate) output1: super::super::preprocessing::Output<D>,
    pub(crate) output2: super::super::preprocessing::Output<D2>,
    _ph: PhantomData<D>,
}

pub fn pack_branch<D: Domain>(branch: &[D::Scalar]) -> Vec<D::Batch> {
    let mut res: Vec<D::Batch> = Vec::with_capacity(branch.len() / D::Batch::DIMENSION + 1);
    for chunk in branch.chunks(D::Batch::DIMENSION) {
        let mut batch = D::Batch::ZERO;
        for (i, s) in chunk.iter().cloned().enumerate() {
            batch.set(i, s);
        }
        res.push(batch)
    }
    res
}

pub fn pack_branches<D: Domain>(branches: &[&[D::Scalar]]) -> Vec<Vec<D::Batch>> {
    let mut batches: Vec<Vec<D::Batch>> = Vec::with_capacity(branches.len());
    for branch in branches {
        batches.push(pack_branch::<D>(branch));
    }
    batches
}

impl<D: Domain, D2: Domain> Proof<D, D2> {
    async fn preprocess<PI: Iterator<Item = ConnectionInstruction>>(
        seeds: &[[u8; KEY_SIZE]],
        mut connection_program: PI,
    ) -> Vec<(Hash, Vec<Hash>)> {

        async fn process<D: Domain, D2: Domain>(
            root: [u8; KEY_SIZE],
            outputs: Sender<()>,
            inputs: Receiver<Arc<Vec<ConnectionInstruction>>>,
        ) -> Result<(Hash, Vec<Hash>), SendError<()>> {
            let mut preprocessing: preprocessing::PreprocessingExecution<D, D2> =
                preprocessing::PreprocessingExecution::new(root);

            loop {
                match inputs.recv().await {
                    Ok(program) => {
                        preprocessing.prove(&program[..]);
                        outputs.send(()).await?;
                    }
                    Err(_) => {
                        return Ok(preprocessing.done());
                    }
                }
            }
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut inputs: Vec<Sender<Arc<Vec<ConnectionInstruction>>>> =
            Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);

        for seed in seeds.iter().cloned() {
            let (send_inputs, recv_inputs) = async_channel::bounded(5);
            let (send_outputs, recv_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D, D2>(
                seed,
                send_outputs,
                recv_inputs,
            )));
            inputs.push(send_inputs);
            outputs.push(recv_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        scheduled += feed::<_>(&mut inputs[..], &mut connection_program).await as usize;
        scheduled += feed::<_>(&mut inputs[..], &mut connection_program).await as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }
            scheduled -= 1;
            scheduled += feed::<_>(&mut inputs[..], &mut connection_program).await as usize;
        }

        // close inputs channels
        inputs.clear();

        // collect final commitments
        let mut results: Vec<(Hash, Vec<Hash>)> = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        for t in tasks.into_iter() {
            results.push(t.await.unwrap());
        }
        results
    }

    pub async fn verify<PI: Iterator<Item = ConnectionInstruction>, PI1: Iterator<Item = Instruction<D::Scalar>>, PI2: Iterator<Item = Instruction<D2::Scalar>>>(
        &self,
        branches1: &[&[D::Scalar]],
        branches2: &[&[D2::Scalar]],
        connection_program: PI,
        program1: PI1,
        program2: PI2,
    ) -> Option<Output<D, D2>> {
        //TODO: spawn asynchronously
        let option_output1 = self.proof1.verify(branches1, program1, vec![], vec![]).await;
        assert!(option_output1.is_some());
        let output1 = option_output1.unwrap();
        let option_output2 = self.proof2.verify(branches2, program2, vec![], vec![]).await;
        assert!(option_output2.is_some());
        let output2 = option_output2.unwrap();

        // derive keys and hidden execution indexes
        let mut roots: Vec<Option<[u8; KEY_SIZE]>> = vec![None; D::PREPROCESSING_REPETITIONS];
        self.random.expand(&mut roots);

        // derive the hidden indexes
        let mut opened: Vec<bool> = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut hidden: Vec<usize> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for (i, key) in roots.iter().enumerate() {
            opened.push(key.is_some());
            if key.is_none() {
                hidden.push(i)
            }
        }

        // prover must open exactly R-H repetitions
        if hidden.len() != D::ONLINE_REPETITIONS {
            return None;
        }

        // recompute the opened repetitions
        let opened_roots: Vec<[u8; KEY_SIZE]> = roots
            .iter()
            .filter(|v| v.is_some())
            .map(|v| v.unwrap())
            .collect();

        debug_assert_eq!(
            opened_roots.len(),
            D::PREPROCESSING_REPETITIONS - D::ONLINE_REPETITIONS
        );

        let opened_results = Self::preprocess(&opened_roots[..], connection_program).await;

        debug_assert_eq!(
            opened_results.len(),
            D::PREPROCESSING_REPETITIONS - D::ONLINE_REPETITIONS
        );

        // interleave the proved hashes with the recomputed ones
        let mut hashes = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        {
            let mut open_hsh = opened_results.iter().map(|(comm, _)| comm);
            let mut hide_hsh = self.hidden.iter();
            for open in opened {
                if open {
                    hashes.push(open_hsh.next().unwrap())
                } else {
                    hashes.push(hide_hsh.next().unwrap())
                }
            }
        }

        debug_assert_eq!(hashes.len(), D::PREPROCESSING_REPETITIONS);

        // feed to the Random-Oracle
        let mut challenge_prg = {
            let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);
            for hash in hashes.iter() {
                oracle.feed(hash.as_bytes());
            }
            oracle.query()
        };

        // accept if the hidden indexes where computed correctly (Fiat-Shamir transform)
        let subset: Vec<usize> = random_subset(
            &mut challenge_prg,
            D::PREPROCESSING_REPETITIONS,
            D::ONLINE_REPETITIONS,
        );
        if hidden[..] == subset[..] {
            Some(Output {
                hidden: self.hidden.to_vec(),
                output1,
                output2,
                _ph: PhantomData,
            })
        } else {
            None
        }
    }

    /// Create a new pre-processing proof.
    ///
    ///
    pub fn new<PI: Iterator<Item = ConnectionInstruction>, PI1: Iterator<Item = Instruction<D::Scalar>>, PI2: Iterator<Item = Instruction<D2::Scalar>>>(
        global: [u8; KEY_SIZE],
        branches1: &[&[D::Scalar]],
        branches2: &[&[D2::Scalar]],
        connection_program: PI,
        program1: PI1,
        program2: PI2,
    ) -> (Self, PreprocessingOutput<D, D2>) {
        let (proof1, preprocessing1) = super::super::preprocessing::Proof::new(global, branches1, program1, vec![], vec![]);
        let (proof2, preprocessing2) = super::super::preprocessing::Proof::new(global, branches2, program2, vec![], vec![]);

        // expand the global seed into per-repetition roots
        let mut roots: Vec<[u8; KEY_SIZE]> = vec![[0; KEY_SIZE]; D::PREPROCESSING_REPETITIONS];
        TreePRF::expand_full(&mut roots, global);

        // block and wait for hashes to compute
        let results = task::block_on(Self::preprocess(&roots[..], connection_program));

        // send the pre-processing commitments to the random oracle, receive challenges
        let mut challenge_prg = {
            let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);
            for (hash, _) in results.iter() {
                oracle.feed(hash.as_bytes());
            }
            oracle.query()
        };

        // interpret the oracle response as a subset of indexes to hide
        // (implicitly: which executions to open)
        let hidden: Vec<usize> = random_subset(
            &mut challenge_prg,
            D::PREPROCESSING_REPETITIONS,
            D::ONLINE_REPETITIONS,
        );

        // puncture the prf at the hidden indexes
        // (implicitly: pass the randomness for all other executions to the verifier)
        let mut tree: TreePRF = TreePRF::new(D::PREPROCESSING_REPETITIONS, global);
        for i in hidden.iter().cloned() {
            tree = tree.puncture(i);
        }

        // extract pre-processing key material for the hidden views
        // (returned to the prover for use in the online phase)
        let mut hidden_runs: Vec<Run> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut hidden_hashes: Vec<Hash> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut results = results.into_iter().enumerate();

        for i in hidden.iter().cloned() {
            // find the matching result
            let result = loop {
                let (j, elem) = results.next().unwrap();
                if i == j {
                    break elem;
                }
            };

            // add to the preprocessing output
            hidden_runs.push(Run {
                seed: roots[i],
                union: result.0.clone(),
                commitments: result.1,
            });

            // add to the preprocessing proof
            hidden_hashes.push(result.0.clone());
        }

        (
            // proof (used by the verifier)
            Proof {
                hidden: hidden_hashes,
                random: tree,
                proof1,
                proof2,
                _ph: PhantomData,
                _ph2: PhantomData,
            },
            // randomness used to re-executed the hidden views (used by the prover)
            PreprocessingOutput {
                hidden: hidden_runs,
                preprocessing1,
                preprocessing2,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng};
    use rand_core::{OsRng, RngCore};

    use crate::algebra::gf2::{BitScalar, GF2P8};
    use crate::tests::{connection_program, mini_program, random_scalars};

    use super::*;

    #[test]
    pub fn test_integration() {
        let mut rng = thread_rng();

        let program = mini_program::<GF2P8>();
        let program2 = mini_program::<GF2P8>();
        let connection_program = connection_program();
        let input = random_scalars::<GF2P8, _>(&mut rng, 4);

        let branch: Vec<BitScalar> = vec![];
        let branches: Vec<Vec<BitScalar>> = vec![branch];

        // prove preprocessing
        // pick global random seed
        let mut seed: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut seed);

        let branches2: Vec<&[BitScalar]> = branches.iter().map(|b| &b[..]).collect();

        let proof = Proof::<GF2P8, GF2P8>::new(seed, &branches2[..], &branches2[..],connection_program.iter().cloned(), program.iter().cloned(), program2.iter().cloned());
        assert!(task::block_on(proof.0.verify(&branches2[..],&branches2[..], connection_program.iter().cloned(), program.iter().cloned(), program2.iter().cloned())).is_some());
        assert!(task::block_on(proof.0.proof1.verify(&branches2[..], program.iter().cloned(), vec![], vec![])).is_some());
        assert!(task::block_on(proof.0.proof2.verify(&branches2[..], program2.iter().cloned(), vec![], vec![])).is_some());
    }
}

