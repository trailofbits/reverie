mod util;

pub mod preprocessing;
pub mod prover;
pub mod verifier;

use crate::algebra::*;
use crate::consts::*;
use crate::crypto::*;
use crate::oracle::RandomOracle;
use crate::util::*;
use crate::Instruction;

use std::iter;
use std::marker::PhantomData;
use std::sync::Arc;

use async_channel::{Receiver, SendError, Sender};
use async_std::task;

use serde::{Deserialize, Serialize};

fn challenge<D: Domain>(hash: &Hash) -> Vec<(usize, usize)> {
    let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);
    oracle.feed(hash.as_bytes());
    let mut prg = oracle.query();

    // subset of indexes to open online phase
    let online: Vec<usize> = random_subset(
        &mut prg,
        D::PREPROCESSING_REPETITIONS,
        D::ONLINE_REPETITIONS,
    );

    // players to hide
    let players: Vec<usize> = random_vector(&mut prg, D::PLAYERS, D::ONLINE_REPETITIONS);

    online.into_iter().zip(players.into_iter()).collect()
}

struct Player0 {
    corrections: Vec<u8>,
}
struct Online {
    branch: Vec<u8>,    // encrypted branch bits
    witness: Vec<u8>,   // encrypted witness bit
    broadcast: Vec<u8>, // broadcast messages (omitted player)
    branch_membership: MerkleSetProof,
    player0: Option<Player0>,
}

// rather than supplying the online hash for all unopened online executions, prove membership of the
#[derive(Clone, Serialize, Deserialize)]
pub struct Opening<D: Domain> {
    online: MerkleProof,
    preprocessing: Hash,
    open: TreePRF,
    _ph: PhantomData<D>,
}

pub struct Challenge<'a> {
    online: MerkleTree,
    executions: &'a [ExecutionCommitment],
}

impl<'a> Challenge<'a> {
    fn new(executions: &'a [ExecutionCommitment]) -> Self {
        // calculate preprocessing hashes
        let online: Vec<Hash> = {
            let mut hs: Vec<Hash> = Vec::with_capacity(executions.len());
            for exec in executions.iter() {
                hs.push(exec.online.clone())
            }
            hs
        };

        Self {
            executions,
            online: MerkleTree::new(&online[..]),
        }
    }

    fn open_online(&self, indexes: &[(usize, usize)]) -> Vec<Opening> {
        let mut opened: Vec<Opening> = Vec::with_capacity(indexes.len());
        for (i, p) in indexes.iter().cloned() {
            opened.push(Opening {
                online: self.online.prove(i), // membership proof for online commitment
                preprocessing: self.executions[i].preprocessing[p], // commitment from omitted player
                player0: None,
            })
        }
        opened
    }

    fn commit(&self) -> Hash {
        // aggregate the views of the players in the preprocessing
        let preprocessing: Hash = {
            let mut sum = Hasher::new();
            for exec in self.executions.iter() {
                let mut hasher = Hasher::new();
                for state in exec.preprocessing.iter() {
                    hasher.update(state.as_bytes());
                }
                sum.update(hasher.finalize().as_bytes());
            }
            sum.finalize()
        };

        let mut joined = Hasher::new();
        joined.update(preprocessing.as_bytes());
        joined.update(self.online.root().as_bytes());
        joined.finalize()
    }
}

pub struct Execution<D: Domain> {
    corrections: Vec<D::Batch>, // player0 corrections
    messages: Vec<D::Sharing>,  // broadcast messages
    preprocessing: Vec<Hash>,   // commitment to the preprocessing states of each player
    online: Hash,               // commitment to the online communication
}

impl Execution {
    fn new(
        mut states: Vec<Hash>, // commitments to per-player PRG seeds (not full player 0 state)
        corrections: Hash,     // correction bits (part of player 0 state)
        root: Hash,            // root of branch Merkle tree (part of player 0 state)
        messages: Hash,        // messages exchanged during online phase
    ) -> Self {
        // add corrections and to player 0 commitment
        states[0] = {
            let mut comm = Hasher::new();
            comm.update(states[0].as_bytes());
            comm.update(corrections.as_bytes());
            comm.update(root.as_bytes());
            comm.finalize()
        };

        Self {
            preprocessing: states,
            online: messages,
        }
    }

    /// Update the online commitment (broadcast channel transcript)
    ///
    /// This is used to supply the online transcript when the preprocessing is opened in cut-and-choose.
    pub fn set_online(&mut self, new: Hash) {
        self.online = new
    }

    /// Update the preprocessing commitment of one of the players
    ///
    /// This is used to set the preprocessing commitment of the omitted player
    /// as supplied by the prover.
    pub fn set_preprocessing(&mut self, idx: usize, new: Hash) {
        self.preprocessing[idx] = new;
    }
}

async fn feed<D: Domain, PI: Iterator<Item = Instruction<D::Scalar>>>(
    senders: &mut [Sender<Arc<Vec<Instruction<D::Scalar>>>>],
    program: &mut PI,
) -> bool {
    // next slice of program
    let ps = Arc::new(read_n(program, BATCH_SIZE));
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
pub struct Proof<D: Domain> {
    hash: Hash,
    online: Vec<Opening<D>>,
    random: TreePRF, // punctured PRF: randomness for the opened pre-processing executions
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
pub struct PreprocessingOutput<D: Domain> {
    pub(crate) branches: Arc<Vec<Vec<D::Batch>>>,
    pub(crate) hidden: Vec<Run>,
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
    async fn preprocess<PI: Iterator<Item = Instruction<D::Scalar>>>(
        seeds: &[[u8; KEY_SIZE]],
        witness: Option<(
            Arc<Vec<D::Scalar>>, // part of witness: active branch programming
            Arc<Vec<D::Scalar>>, // part of witness: unconstrained inputs
        )>,
        branches: Arc<Vec<Vec<D::Batch>>>, // set of permissible branches (packed for efficiency)
        mut program: PI,
    ) -> Vec<ExecutionCommitment> {
        assert!(
            branches.len() > 0,
            "even when the branch feature is not used, the branch should still be provided and should be a singleton list with an empty element"
        );

        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            witness: Option<(
                Arc<Vec<D::Scalar>>, // part of witness: active branch programming
                Arc<Vec<D::Scalar>>, // part of witness: unconstrained inputs
            )>,
            branches: Arc<Vec<Vec<D::Batch>>>,
            outputs: Sender<()>,
            inputs: Receiver<Arc<Vec<Instruction<D::Scalar>>>>,
        ) -> Result<ExecutionCommitment, SendError<()>> {
            async fn drive<
                D: Domain,
                WI: Iterator<Item = D::Scalar>,
                BI: Iterator<Item = D::Scalar>,
            >(
                outputs: Sender<()>,
                inputs: Receiver<Arc<Vec<Instruction<D::Scalar>>>>,
                mut pp: preprocessing::PreprocessingExecution<D, WI, BI>,
            ) -> Result<ExecutionCommitment, SendError<()>> {
                loop {
                    match inputs.recv().await {
                        Ok(program) => {
                            pp.process(&program[..]);
                            outputs.send(()).await?;
                        }
                        Err(_) => {
                            return Ok(pp.done());
                        }
                    }
                }
            };

            match witness {
                // prover processing
                Some((branch, free)) => {
                    drive::<D, _, _>(
                        outputs,
                        inputs,
                        preprocessing::PreprocessingExecution::new(
                            root,
                            &branches[..],
                            free.iter().cloned(),
                            branch.iter().cloned(),
                        ),
                    )
                    .await
                }
                // verifier cut-and-choose preprocessing
                None => {
                    drive::<D, _, _>(
                        outputs,
                        inputs,
                        preprocessing::PreprocessingExecution::new(
                            root,
                            &branches[..],
                            iter::repeat(D::Scalar::ZERO), // execute with infinite dummy inputs
                            iter::repeat(D::Scalar::ZERO), // execute with infinite dummy inputs
                        ),
                    )
                    .await
                }
            }
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut inputs: Vec<Sender<Arc<Vec<Instruction<D::Scalar>>>>> =
            Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);

        for seed in seeds.iter().cloned() {
            let (send_inputs, recv_inputs) = async_channel::bounded(5);
            let (send_outputs, recv_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D>(
                seed,
                witness.clone(),
                branches.clone(),
                send_outputs,
                recv_inputs,
            )));
            inputs.push(send_inputs);
            outputs.push(recv_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        scheduled += feed::<D, _>(&mut inputs[..], &mut program).await as usize;
        scheduled += feed::<D, _>(&mut inputs[..], &mut program).await as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }
            scheduled -= 1;
            scheduled += feed::<D, _>(&mut inputs[..], &mut program).await as usize;
        }

        // close inputs channels
        inputs.clear();

        // collect final commitments
        let mut results: Vec<ExecutionCommitment> =
            Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        for t in tasks.into_iter() {
            results.push(t.await.unwrap());
        }
        results
    }

    pub async fn verify<PI: Iterator<Item = Instruction<D::Scalar>>>(
        &self,
        branches: &[&[D::Scalar]],
        program: PI,
    ) -> Option<Output<D>> {
        if self.online.len() != D::ONLINE_REPETITIONS {
            return None;
        }

        // pack branch scalars into batches for efficiency
        let branches = Arc::new(pack_branches::<D>(branches));

        // derive keys and hidden execution indexes
        let mut roots: Vec<Option<[u8; KEY_SIZE]>> = vec![None; D::PREPROCESSING_REPETITIONS];
        self.random.expand(&mut roots);

        // recompute the opened repetitions
        let preprocessing_roots: Vec<[u8; KEY_SIZE]> =
            roots.iter().map(|v| v.unwrap_or([0u8; KEY_SIZE])).collect();

        // recover online and preprocessing indexes from proof
        let mut online_indexes = challenge::<D>(&self.hash);

        let preprocessing_results =
            Self::preprocess(&preprocessing_roots[..], None, branches, program).await;

        debug_assert_eq!(
            opened_results.len(),
            D::PREPROCESSING_REPETITIONS - D::ONLINE_REPETITIONS
        );

        unimplemented!()
    }

    /// Creates a new proof.
    pub fn new<PI: Iterator<Item = Instruction<D::Scalar>>>(
        global: [u8; KEY_SIZE],
        active: usize,         // active branch programming
        witness: &[D::Scalar], // free witness wires
        branches: &[&[D::Scalar]],
        program: PI,
    ) -> Self {
        let witness = Arc::new(witness.to_owned());
        let branch = Arc::new(branches[active].to_owned());

        // pack branch scalars into batches for efficiency
        let branches = Arc::new(pack_branches::<D>(branches));

        // expand the global seed into per-repetition roots
        let mut roots: Vec<[u8; KEY_SIZE]> = vec![[0; KEY_SIZE]; D::PREPROCESSING_REPETITIONS];
        TreePRF::expand_full(&mut roots, global);

        // block and wait for hashes to compute
        let results = task::block_on(Self::preprocess(
            &roots[..],
            Some((branch, witness)),
            branches.clone(),
            program,
        ));

        let opener = Challenge::new(&results[..]);
        let commitment = opener.commit();
        let online_indexes = challenge::<D>(&commitment);

        // puncture the prf at the hidden indexes
        // (implicitly: pass the randomness for all other executions to the verifier)
        let mut tree: TreePRF = TreePRF::new(D::PREPROCESSING_REPETITIONS, global);
        for (i, _) in online_indexes.iter().cloned() {
            tree = tree.puncture(i);
        }
        Proof {
            online: opener.open_online(online_indexes),
            random: tree,
            _ph: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::algebra::gf2::{BitScalar, GF2P8};
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
        let branch: Vec<BitScalar> = vec![];
        let branches: Vec<&[BitScalar]> = vec![&branch];
        let proof = Proof::<GF2P8>::new(seed, &branches[..], program.iter().cloned());
        assert!(task::block_on(proof.0.verify(&branches[..], program.into_iter())).is_some());
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::super::algebra::gf2::GF2P8;
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
        b.iter(|| Proof::<GF2P8>::new([0u8; KEY_SIZE], program.iter().cloned()));
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
        let (proof, _) = Proof::<GF2P8>::new([0u8; KEY_SIZE], program.iter().cloned());
        b.iter(|| task::block_on(proof.verify(program.iter().cloned())));
    }
}
