pub(crate) mod util;

#[allow(clippy::module_inception)]
pub mod preprocessing;
pub mod prover;
pub mod verifier;

use crate::algebra::*;
use crate::consts::*;
use crate::crypto::*;
use crate::oracle::RandomOracle;
use crate::util::*;
use crate::{Instruction, Instructions};

use std::marker::PhantomData;
use std::sync::Arc;

use async_channel::{Receiver, SendError, Sender};
use async_std::task;

use crate::fieldswitching::util::FieldSwitchingIo;
use serde::{Deserialize, Serialize};

type Round1Output<D> = (
    Arc<Vec<Vec<<D as Domain>::Batch>>>,
    Vec<[u8; 32]>,
    Vec<(Hash, Vec<Hash>)>,
);

/// Represents repeated execution of the preprocessing phase.
/// The preprocessing phase is executed D::ONLINE_REPETITIONS times, then fed to a random oracle,
/// which dictates the subset of executions to open.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Proof<D: Domain> {
    hidden: Vec<Hash>, // commitments to the hidden pre-processing executions
    random: TreePrf, // punctured PRF used to derive the randomness for the opened pre-processing executions
    _ph: PhantomData<D>,
}

impl<D: Domain> Proof<D> {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn deserialize(encoded: &[u8]) -> Option<Self> {
        bincode::deserialize(encoded).ok()
    }
}

#[derive(Clone)] //TODO(gvl): remove Clone
pub struct PreprocessingRun {
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
#[derive(Clone)] //TODO(gvl): remove clone
pub struct PreprocessingOutput<D: Domain> {
    pub(crate) branches: Arc<Vec<Vec<D::Batch>>>,
    pub(crate) hidden: Vec<PreprocessingRun>,
}

pub struct Output<D: Domain> {
    pub(crate) hidden: Vec<Hash>,
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

impl<D: Domain> Proof<D> {
    async fn preprocess(
        seeds: &[[u8; KEY_SIZE]],
        branches: Arc<Vec<Vec<D::Batch>>>,
        program: Arc<Vec<Instruction<D::Scalar>>>,
        fieldswitching_io: FieldSwitchingIo,
    ) -> Vec<(Hash, Vec<Hash>)> {
        assert!(
            branches.len() > 0,
            "even when the branch feature is not used, the branch should still be provided and should be a singleton list with an empty element"
        );

        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            branches: Arc<Vec<Vec<D::Batch>>>,
            outputs: Sender<()>,
            inputs: Receiver<Arc<Instructions<D>>>,
            fieldswitching_io: FieldSwitchingIo,
        ) -> Result<(Hash, Vec<Hash>), SendError<()>> {
            let mut preprocessing: preprocessing::PreprocessingExecution<D> =
                preprocessing::PreprocessingExecution::new(root, &branches[..]);
            let mut nr_of_wires = 0;

            loop {
                match inputs.recv().await {
                    Ok(program) => {
                        nr_of_wires = preprocessing.prove(
                            &program[..],
                            fieldswitching_io.0.clone(),
                            fieldswitching_io.1.clone(),
                            nr_of_wires,
                        );
                        outputs.send(()).await?;
                    }
                    Err(_) => {
                        return Ok(preprocessing.done());
                    }
                }
            }
        }

        type TaskHandle = task::JoinHandle<Result<(Hash, Vec<Hash>), SendError<()>>>;
        async fn collect_commitments<D: Domain>(
            mut tasks: Vec<TaskHandle>,
        ) -> Vec<(Hash, Vec<Hash>)> {
            let mut results: Vec<(Hash, Vec<Hash>)> = Vec::new();
            for t in tasks.drain(..) {
                results.push(t.await.unwrap());
            }
            results
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut inputs: Vec<Sender<Arc<Instructions<D>>>> =
            Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);

        for seed in seeds.iter().cloned() {
            let (send_inputs, recv_inputs) = async_channel::bounded(5);
            let (send_outputs, recv_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D>(
                seed,
                branches.clone(),
                send_outputs,
                recv_inputs,
                fieldswitching_io.clone(),
            )));
            inputs.push(send_inputs);
            outputs.push(recv_outputs);
        }
        let commitments = task::spawn(collect_commitments::<D>(tasks));

        let chunk_size = chunk_size(program.len(), inputs.len());

        while !inputs.is_empty() {
            for sender in inputs.drain(..chunk_size) {
                sender.send(program.clone()).await.unwrap();
            }
            for rx in outputs.drain(..chunk_size) {
                let _ = rx.recv().await;
            }
        }

        // collect final commitments
        commitments.await
    }

    pub async fn verify(
        &self,
        branches: &[&[D::Scalar]],
        program: Arc<Vec<Instruction<D::Scalar>>>,
        fieldswitching_io: FieldSwitchingIo,
    ) -> Option<Output<D>> {
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);

        let (hidden, output) = match self
            .verify_round_1(branches, program, fieldswitching_io, &mut oracle)
            .await
        {
            Some(out) => out,
            None => return None,
        };

        if !<Proof<D>>::verify_challenge(&mut oracle, hidden) {
            return None;
        }

        Some(output)
    }

    pub async fn verify_round_1(
        &self,
        branches: &[&[<D as Domain>::Scalar]],
        program: Arc<Vec<Instruction<D::Scalar>>>,
        fieldswitching_io: FieldSwitchingIo,
        oracle: &mut RandomOracle,
    ) -> Option<(Vec<usize>, Output<D>)> {
        // pack branch scalars into batches for efficiency
        let branches = Arc::new(pack_branches::<D>(branches));

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

        let opened_results =
            Self::preprocess(&opened_roots[..], branches, program, fieldswitching_io).await;

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
        for hash in hashes.iter() {
            oracle.feed(hash.as_bytes());
        }
        Some((
            hidden,
            Output {
                hidden: self.hidden.to_vec(),
                _ph: PhantomData,
            },
        ))
    }

    pub fn verify_challenge(oracle: &mut RandomOracle, hidden: Vec<usize>) -> bool {
        // feed to the Random-Oracle
        let mut challenge_prg = oracle.clone().query();

        // accept if the hidden indexes where computed correctly (Fiat-Shamir transform)
        let subset: Vec<usize> = random_subset(
            &mut challenge_prg,
            D::PREPROCESSING_REPETITIONS,
            D::ONLINE_REPETITIONS,
        );
        hidden[..] == subset[..]
    }

    /// Create a new pre-processing proof.
    ///
    ///
    pub fn new(
        global: [u8; KEY_SIZE],
        branches: &[&[D::Scalar]],
        program: Arc<Vec<Instruction<D::Scalar>>>,
        fieldswitching_io: FieldSwitchingIo,
    ) -> (Self, PreprocessingOutput<D>) {
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);

        let (branches, roots, results) =
            <Proof<D>>::new_round_1(global, branches, program, fieldswitching_io, &mut oracle);

        let hidden = <Proof<D>>::get_challenge(&mut oracle);

        <Proof<D>>::new_round_3(global, branches, roots, results, hidden)
    }

    pub fn new_round_3(
        global: [u8; 32],
        branches: Arc<Vec<Vec<<D as Domain>::Batch>>>,
        roots: Vec<[u8; 32]>,
        results: Vec<(Hash, Vec<Hash>)>,
        hidden: Vec<usize>,
    ) -> (Proof<D>, PreprocessingOutput<D>) {
        // puncture the prf at the hidden indexes
        // (implicitly: pass the randomness for all other executions to the verifier)
        let mut tree: TreePrf = TreePrf::new(D::PREPROCESSING_REPETITIONS, global);
        for i in hidden.iter().cloned() {
            tree = tree.puncture(i);
        }

        // extract pre-processing key material for the hidden views
        // (returned to the prover for use in the online phase)
        let mut hidden_runs: Vec<PreprocessingRun> = Vec::with_capacity(D::ONLINE_REPETITIONS);
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
            hidden_runs.push(PreprocessingRun {
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
                _ph: PhantomData,
            },
            // randomness used to re-executed the hidden views (used by the prover)
            PreprocessingOutput {
                branches,
                hidden: hidden_runs,
            },
        )
    }

    pub(crate) fn get_challenge(oracle: &mut RandomOracle) -> Vec<usize> {
        // interpret the oracle response as a subset of indexes to hide
        // (implicitly: which executions to open)
        let hidden: Vec<usize> = random_subset(
            &mut oracle.clone().query(),
            D::PREPROCESSING_REPETITIONS,
            D::ONLINE_REPETITIONS,
        );
        hidden
    }

    pub fn new_round_1(
        global: [u8; 32],
        branches: &[&[<D as Domain>::Scalar]],
        program: Arc<Vec<Instruction<D::Scalar>>>,
        fieldswitching_io: FieldSwitchingIo,
        oracle: &mut RandomOracle,
    ) -> Round1Output<D> {
        // pack branch scalars into batches for efficiency
        let branches = Arc::new(pack_branches::<D>(branches));

        // expand the global seed into per-repetition roots
        let mut roots: Vec<[u8; KEY_SIZE]> = vec![[0; KEY_SIZE]; D::PREPROCESSING_REPETITIONS];
        TreePrf::expand_full(&mut roots, global);

        // block and wait for hashes to compute
        let results = task::block_on(Self::preprocess(
            &roots[..],
            branches.clone(),
            program,
            fieldswitching_io,
        ));

        // send the pre-processing commitments to the random oracle, receive challenges
        for (hash, _) in results.iter() {
            oracle.feed(hash.as_bytes());
        }
        (branches, roots, results)
    }
}

#[cfg(test)]
mod tests {
    use super::super::algebra::gf2::{BitScalar, Gf2P8};
    use super::*;

    use crate::fieldswitching::util::DedupMap;
    use rand::Rng;
    use std::collections::HashSet;

    #[test]
    fn test_preprocessing_n8() {
        let program = Arc::new(vec![
            Instruction::NrOfWires(3),
            Instruction::Input(1),
            Instruction::Input(2),
            Instruction::Mul(0, 1, 2),
        ]); // maybe generate random program?
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let branch: Vec<BitScalar> = vec![];
        let branches: Vec<&[BitScalar]> = vec![&branch];
        let proof = Proof::<Gf2P8>::new(
            seed,
            &branches[..],
            program.clone(),
            (HashSet::new(), DedupMap::new()),
        );
        assert!(task::block_on(proof.0.verify(
            &branches[..],
            program,
            (HashSet::new(), DedupMap::new())
        ))
        .is_some());
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::super::algebra::gf2::{BitScalar, Gf2P8};
    use super::*;

    use test::Bencher;

    const MULT: usize = 1_000_000;

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
        let branch: Vec<BitScalar> = vec![];
        let branches: Vec<&[BitScalar]> = vec![&branch];
        b.iter(|| Proof::<Gf2P8>::new([0u8; KEY_SIZE], &branches, program.iter().cloned()));
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
        let branch: Vec<BitScalar> = vec![];
        let branches: Vec<&[BitScalar]> = vec![&branch];
        let (proof, _) = Proof::<Gf2P8>::new([0u8; KEY_SIZE], &branches, program.iter().cloned());
        b.iter(|| task::block_on(proof.verify(&branches, program.iter().cloned())));
    }
}
