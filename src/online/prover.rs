use super::*;

use crate::algebra::Packable;
use crate::algebra::{Domain, LocalOperation, RingModule, Sharing};
use crate::consts::*;
use crate::crypto::{Hash, TreePRF};
use crate::oracle::RandomOracle;
use crate::preprocessing::prover::PreprocessingExecution;
use crate::preprocessing::PreprocessingOutput;
use crate::util::*;
use crate::Instructions;

use std::sync::Arc;

use async_channel::{Receiver, SendError, Sender};
use async_std::task;

/// A type alias for a tuple of a program slice and its witness slice.
type ProgWitSlice<D> = (Arc<Instructions<D>>, Arc<Vec<<D as Domain>::Scalar>>);

const DEFAULT_CAPACITY: usize = BATCH_SIZE;

async fn feed<
    D: Domain,
    PI: Iterator<Item = Instruction<D::Scalar>>,
    WI: Iterator<Item = D::Scalar>,
>(
    chunk: usize,
    senders: &mut [Sender<ProgWitSlice<D>>],
    program: &mut PI,
    witness: &mut WI,
) -> bool {
    // next slice of program
    let ps = Arc::new(read_n(program, chunk));
    if ps.len() == 0 {
        return false;
    }

    // slice of the witness consumed by the program slice
    let ni = count_inputs::<D>(&ps[..]);
    let ws = Arc::new(read_n(witness, ni));
    if ws.len() != ni {
        return false;
    }

    // feed to workers
    debug_assert_eq!(senders.len(), D::ONLINE_REPETITIONS);
    for tx in senders.iter_mut() {
        tx.send((ps.clone(), ws.clone())).await.unwrap();
    }
    true
}

fn count_inputs<D: Domain>(program: &[Instruction<D::Scalar>]) -> usize {
    let mut inputs = 0;
    for step in program {
        if let Instruction::Input(_) = step {
            inputs += 1;
        }
    }
    inputs
}

pub struct StreamingProver<D: Domain> {
    branch: Arc<Vec<D::Scalar>>,
    preprocessing: PreprocessingOutput<D>,
    omitted: Vec<usize>,
}

struct BatchExtractor<D: Domain, W: Writer<D::Batch>> {
    idx: usize,
    shares: Vec<D::Sharing>,
    writer: W,
}

impl<D: Domain, W: Writer<D::Batch>> BatchExtractor<D, W> {
    fn new(idx: usize, writer: W) -> Self {
        debug_assert!(idx < D::PLAYERS);
        BatchExtractor {
            idx,
            shares: Vec::with_capacity(D::Batch::DIMENSION),
            writer,
        }
    }
}

impl<D: Domain, W: Writer<D::Batch>> Writer<D::Sharing> for BatchExtractor<D, W> {
    fn write(&mut self, elem: D::Sharing) {
        self.shares.push(elem);
        if self.shares.len() == D::Batch::DIMENSION {
            let mut batches = vec![D::Batch::ZERO; D::PLAYERS];
            D::convert_inv(&mut batches[..], &self.shares[..]);
            self.writer.write(batches[self.idx]);
            self.shares.clear();
        }
    }
}

impl<D: Domain, W: Writer<D::Batch>> Drop for BatchExtractor<D, W> {
    fn drop(&mut self) {
        if self.shares.is_empty() {
            return;
        }

        let mut batches = vec![D::Batch::ZERO; D::PLAYERS];
        self.shares.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
        D::convert_inv(&mut batches[..], &self.shares[..]);
        self.writer.write(batches[self.idx]);
        self.shares.clear();
    }
}

struct Prover<D: Domain, I: Iterator<Item = D::Scalar>> {
    #[cfg(test)]
    #[cfg(debug_assertions)]
    plain: VecMap<Option<D::Scalar>>,
    wires: VecMap<D::Scalar>,
    branch: I,
}

impl<D: Domain, I: Iterator<Item = D::Scalar>> Prover<D, I> {
    fn new(branch: I) -> Self {
        Prover {
            #[cfg(test)]
            #[cfg(debug_assertions)]
            plain: VecMap::new(),
            wires: VecMap::new(),
            branch,
        }
    }

    // execute the next chunk of program
    fn run<WW: Writer<D::Scalar>, BW: Writer<D::Sharing>>(
        &mut self,
        program: &[Instruction<D::Scalar>],
        witness: &[D::Scalar], // witness for input gates from next chunk of program
        preprocessing_masks: &[D::Sharing],
        preprocessing_ab_gamma: &[D::Sharing],
        masked_witness: &mut WW,
        broadcast: &mut BW,
    ) {
        let mut witness = witness.iter().cloned();
        let mut ab_gamma = preprocessing_ab_gamma.iter().cloned();
        let mut masks = preprocessing_masks.iter().cloned();

        for step in program {
            match *step {
                Instruction::LocalOp(dst, src) => {
                    self.wires.set(dst, self.wires.get(src).operation());

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        let correct = self.plain.get(src).unwrap().operation();
                        self.plain.set(dst, Some(correct));
                    }
                }
                Instruction::Input(dst) => {
                    let value: D::Scalar = witness.next().unwrap();
                    let mask: D::Sharing = masks.next().unwrap();
                    let wire = value + D::Sharing::reconstruct(&mask);
                    self.wires.set(dst, wire);
                    masked_witness.write(wire);

                    #[cfg(feature = "trace")]
                    {
                        println!(
                            "prover-input    : Input({}) ; wire = {:?}, mask = {:?}, value = {:?}",
                            dst, wire, mask, value
                        );
                    }

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        assert_eq!(self.wires.get(dst) + mask.reconstruct(), value);
                        #[cfg(feature = "trace")]
                        println!("  mask = {:?}, value = {:?}", mask, value);
                        self.plain.set(dst, Some(value));
                    }
                }
                Instruction::Branch(dst) => {
                    let value: D::Scalar = self.branch.next().unwrap();
                    let mask: D::Sharing = masks.next().unwrap();
                    let wire = value + D::Sharing::reconstruct(&mask);
                    self.wires.set(dst, wire);

                    #[cfg(feature = "trace")]
                    {
                        println!(
                            "prover-branch   : Branch({}) ; wire = {:?}, mask = {:?}, value = {:?}",
                            dst, wire, mask, value
                        );
                    }

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        assert_eq!(self.wires.get(dst) + mask.reconstruct(), value);
                        #[cfg(feature = "trace")]
                        println!("  mask = {:?}, value = {:?}", mask, value);
                        self.plain.set(dst, Some(value));
                    }
                }
                Instruction::AddConst(dst, src, c) => {
                    let a_w = self.wires.get(src);
                    self.wires.set(dst, a_w + c);

                    #[cfg(feature = "trace")]
                    {
                        println!(
                            "prover-addconst : AddConst({}, {}, {:?}) ; wire = {:?}",
                            dst,
                            src,
                            c,
                            self.wires.get(dst),
                        );
                    }

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        // calculate the real result
                        let correct = self.plain.get(src).unwrap() + c;
                        self.plain.set(dst, Some(correct));

                        // reconstruct masked wire and check computation
                        #[cfg(feature = "debug_eval")]
                        {
                            let mask = masks.next().unwrap();
                            #[cfg(feature = "trace")]
                            println!("  mask = {:?}, value = {:?}", mask, correct);
                            assert_eq!(correct, mask.reconstruct() + self.wires.get(dst));
                        }
                    }
                }
                Instruction::MulConst(dst, src, c) => {
                    let sw = self.wires.get(src);
                    self.wires.set(dst, sw * c);

                    #[cfg(feature = "trace")]
                    {
                        println!(
                            "prover-mulconst : MulConst({}, {}, {:?}) ; wire = {:?}",
                            dst,
                            src,
                            c,
                            self.wires.get(dst),
                        );
                    }

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        // calculate the real result
                        let correct = self.plain.get(src).unwrap() * c;
                        self.plain.set(dst, Some(correct));

                        // reconstruct masked wire and check computation
                        #[cfg(feature = "debug_eval")]
                        {
                            let mask = masks.next().unwrap();
                            #[cfg(feature = "trace")]
                            println!("  mask = {:?}, value = {:?}", mask, correct);
                            assert_eq!(correct, mask.reconstruct() + self.wires.get(dst));
                        }
                    }
                }
                Instruction::Add(dst, src1, src2) => {
                    let a_w = self.wires.get(src1);
                    let b_w = self.wires.get(src2);
                    self.wires.set(dst, a_w + b_w);

                    #[cfg(feature = "trace")]
                    {
                        println!(
                            "prover-add      : Add({}, {}, {}) ; wire = {:?}",
                            dst,
                            src1,
                            src2,
                            self.wires.get(dst),
                        );
                    }

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        let correct = self.plain.get(src1).unwrap() + self.plain.get(src2).unwrap();
                        self.plain.set(dst, Some(correct));

                        // reconstruct masked wire and check computation
                        #[cfg(feature = "debug_eval")]
                        {
                            let mask = masks.next().unwrap();
                            #[cfg(feature = "trace")]
                            println!("  mask = {:?}, value = {:?}", mask, correct);
                            assert_eq!(correct, mask.reconstruct() + self.wires.get(dst));
                        }
                    }
                }
                Instruction::Mul(dst, src1, src2) => {
                    // calculate reconstruction shares for every player
                    let a_w = self.wires.get(src1);
                    let b_w = self.wires.get(src2);
                    let a_m: D::Sharing = masks.next().unwrap();
                    let b_m: D::Sharing = masks.next().unwrap();
                    let ab_gamma: D::Sharing = ab_gamma.next().unwrap();
                    let recon = a_m.action(b_w) + b_m.action(a_w) + ab_gamma;

                    // reconstruct
                    broadcast.write(recon);

                    // corrected wire
                    let c_w = recon.reconstruct() + a_w * b_w;

                    // reconstruct and correct share
                    self.wires.set(dst, c_w);

                    #[cfg(feature = "trace")]
                    {
                        println!(
                            "prover-mul      : Mul({}, {}, {}) ; wire = {:?}",
                            dst,
                            src1,
                            src2,
                            self.wires.get(dst),
                        );
                    }

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        let correct = self.plain.get(src1).unwrap() * self.plain.get(src2).unwrap();
                        self.plain.set(dst, Some(correct));

                        // reconstruct masked wire and check computation
                        #[cfg(feature = "debug_eval")]
                        {
                            let mask = masks.next().unwrap();
                            #[cfg(feature = "trace")]
                            println!("  mask = {:?}, value = {:?}", mask, correct);
                            assert_eq!(correct, mask.reconstruct() + self.wires.get(dst));
                        }
                    }
                }
                Instruction::Output(_src) => {
                    let recon: D::Sharing = masks.next().unwrap();
                    broadcast.write(recon);

                    #[cfg(feature = "trace")]
                    {
                        println!(
                            "prover-output   : Output({}) ; recon = {:?}, wire = {:?}",
                            _src,
                            recon,
                            self.wires.get(_src),
                        );
                    }

                    // check result correctly reconstructed
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        let value: D::Scalar = self.plain.get(_src).unwrap();
                        assert_eq!(
                            self.wires.get(_src) + recon.reconstruct(),
                            value,
                            "wire-index: {}, wire-value: {:?} recon: {:?}",
                            _src,
                            self.wires.get(_src),
                            recon
                        );
                    }
                }
            }
        }
        debug_assert!(witness.next().is_none());
        debug_assert!(masks.next().is_none());
    }
}

impl<D: Domain> StreamingProver<D> {
    /// Creates a new proof of program execution on the input provided.
    ///
    /// It is crucial for zero-knowledge that the pre-processing output is not reused!
    /// To help ensure this Proof::new takes ownership of PreprocessedProverOutput,
    /// which prevents the programmer from accidentally re-using the output
    pub async fn new<
        PI: Iterator<Item = Instruction<D::Scalar>>,
        WI: Iterator<Item = D::Scalar>,
    >(
        bind: Option<&[u8]>, // included Fiat-Shamir transform (for signatures of knowledge)
        preprocessing: PreprocessingOutput<D>, // output of preprocessing
        branch_index: usize, // branch index (from preprocessing)
        mut program: PI,
        mut witness: WI,
    ) -> (Proof<D>, Self) {
        assert_eq!(preprocessing.hidden.len(), D::ONLINE_REPETITIONS);

        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            branches: Arc<Vec<Vec<D::Batch>>>,
            branch_index: usize,
            branch: Arc<Vec<D::Scalar>>,
            outputs: Sender<()>,
            inputs: Receiver<ProgWitSlice<D>>,
        ) -> Result<(Vec<u8>, MerkleSetProof, Hash), SendError<Vec<u8>>> {
            // online execution
            let mut online = Prover::<D, _>::new(branch.iter().cloned());

            // public transcript (broadcast channel)
            let mut transcript = RingHasher::new();

            // preprocessing execution
            let mut preprocessing = PreprocessingExecution::<D>::new(root);

            // vectors for values passed between preprocessing and online execution
            let mut masks = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma = Vec::with_capacity(DEFAULT_CAPACITY);

            loop {
                match inputs.recv().await {
                    Ok((program, witness)) => {
                        // execute the next slice of program
                        {
                            // reset preprocessing output buffers
                            masks.clear();
                            ab_gamma.clear();

                            // prepare pre-processing execution (online mode)
                            preprocessing.process(
                                &program[..],
                                &mut VoidWriter::new(),
                                &mut masks,
                                &mut ab_gamma,
                            );

                            // compute public transcript
                            online.run(
                                &program[..],
                                &witness[..],
                                &masks[..],
                                &ab_gamma[..],
                                &mut VoidWriter::new(),
                                &mut transcript,
                            );
                        }

                        // needed for synchronization
                        outputs.send(()).await.unwrap();
                    }
                    Err(_) => {
                        let mut packed: Vec<u8> = Vec::with_capacity(256);
                        let (branch, proof) = preprocessing.prove_branch(&*branches, branch_index);
                        Packable::pack(&mut packed, branch.iter()).unwrap();
                        return Ok((packed, proof, transcript.finalize()));
                    }
                }
            }
        }

        // unpack selected branch into scalars again
        let branch_batches = &preprocessing.branches[branch_index][..];
        let mut branch = Vec::with_capacity(branch_batches.len() * D::Batch::DIMENSION);
        for batch in branch_batches.iter() {
            for j in 0..D::Batch::DIMENSION {
                branch.push(batch.get(j))
            }
        }
        let branch = Arc::new(branch);

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for run in preprocessing.hidden.iter() {
            let (send_inputs, recv_inputs) = async_channel::bounded(2);
            let (send_outputs, recv_outputs) = async_channel::bounded(2);
            tasks.push(task::spawn(process::<D>(
                run.seed,
                preprocessing.branches.clone(),
                branch_index,
                branch.clone(),
                send_outputs,
                recv_inputs,
            )));
            inputs.push(send_inputs);
            outputs.push(recv_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;

        scheduled +=
            feed::<D, _, _>(BATCH_SIZE, &mut inputs[..], &mut program, &mut witness).await as usize;

        scheduled +=
            feed::<D, _, _>(BATCH_SIZE, &mut inputs[..], &mut program, &mut witness).await as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            scheduled -= 1;

            // schedule a new task
            scheduled += feed::<D, _, _>(BATCH_SIZE, &mut inputs[..], &mut program, &mut witness)
                .await as usize;

            // wait for output from every task to avoid one task racing a head
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }
        }

        // close input writers
        inputs.clear();

        // extract which players to omit in every run (Fiat-Shamir)
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind);
        let mut masked_branches = Vec::with_capacity(D::ONLINE_REPETITIONS);

        for (pp, t) in preprocessing.hidden.iter().zip(tasks.into_iter()) {
            let (masked, proof, transcript) = t.await.unwrap();
            masked_branches.push((masked, proof));

            // RO((preprocessing, transcript))
            oracle.feed(pp.union.as_bytes());
            oracle.feed(transcript.as_bytes());
        }

        let omitted: Vec<usize> =
            random_vector(&mut oracle.query(), D::PLAYERS, D::ONLINE_REPETITIONS);

        debug_assert_eq!(omitted.len(), D::ONLINE_REPETITIONS);

        (
            Proof {
                // omit player from TreePRF and provide pre-processing commitment
                runs: omitted
                    .iter()
                    .cloned()
                    .zip(preprocessing.hidden.iter())
                    .zip(masked_branches.into_iter())
                    .map(|((omit, run), (branch, proof))| {
                        let tree = TreePRF::new(D::PLAYERS, run.seed);
                        Run {
                            proof,
                            branch,
                            commitment: run.commitments[omit].clone(),
                            open: tree.puncture(omit),
                            _ph: PhantomData,
                        }
                    })
                    .collect(),
                _ph: PhantomData,
            },
            StreamingProver {
                branch,
                omitted,
                preprocessing,
            },
        )
    }

    pub async fn stream<
        PI: Iterator<Item = Instruction<D::Scalar>>,
        WI: Iterator<Item = D::Scalar>,
    >(
        self,
        dst: Sender<Vec<u8>>,
        mut program: PI,
        mut witness: WI,
    ) -> Result<(), SendError<Vec<u8>>> {
        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            omitted: usize,
            branch: Arc<Vec<D::Scalar>>,
            outputs: Sender<Vec<u8>>,
            inputs: Receiver<ProgWitSlice<D>>,
        ) -> Result<(), SendError<Vec<u8>>> {
            let mut seeds = vec![[0u8; KEY_SIZE]; D::PLAYERS];
            TreePRF::expand_full(&mut seeds, root);

            let mut online = Prover::<D, _>::new(branch.iter().cloned());
            let mut preprocessing = PreprocessingExecution::<D>::new(root);

            // output buffers used during execution
            let mut masks = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut corrections = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut broadcast = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut masked: Vec<D::Scalar> = Vec::with_capacity(DEFAULT_CAPACITY);

            // packed elements to be serialized
            let mut chunk = Chunk {
                witness: Vec::with_capacity(BATCH_SIZE),
                broadcast: Vec::with_capacity(BATCH_SIZE),
                corrections: Vec::with_capacity(BATCH_SIZE),
            };

            loop {
                match inputs.recv().await {
                    Ok((program, witness)) => {
                        broadcast.clear();
                        corrections.clear();
                        masked.clear();
                        masks.clear();
                        ab_gamma.clear();

                        // execute the next slice of program
                        {
                            // prepare pre-processing execution (online mode), save the corrections.
                            preprocessing.process(
                                &program[..],
                                &mut SwitchWriter::new(&mut corrections, omitted != 0),
                                &mut masks,
                                &mut ab_gamma,
                            );

                            // compute public transcript
                            online.run(
                                &program[..],
                                &witness[..],
                                &masks[..],
                                &ab_gamma[..],
                                &mut masked,
                                &mut BatchExtractor::<D, _>::new(omitted, &mut broadcast),
                            );
                        }

                        // serialize the chunk

                        chunk.witness.clear();
                        chunk.broadcast.clear();
                        chunk.corrections.clear();
                        Packable::pack(&mut chunk.witness, masked.iter()).unwrap();
                        Packable::pack(&mut chunk.broadcast, broadcast.iter()).unwrap();
                        Packable::pack(&mut chunk.corrections, corrections.iter()).unwrap();
                        outputs
                            .send(bincode::serialize(&chunk).unwrap())
                            .await
                            .unwrap();
                    }
                    Err(_) => return Ok(()),
                }
            }
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for (run, omit) in self
            .preprocessing
            .hidden
            .iter()
            .zip(self.omitted.iter().cloned())
        {
            let (sender_inputs, reader_inputs) = async_channel::bounded(3);
            let (sender_outputs, reader_outputs) = async_channel::bounded(3);
            tasks.push(task::spawn(process::<D>(
                run.seed,
                omit,
                self.branch.clone(),
                sender_outputs,
                reader_inputs,
            )));
            inputs.push(sender_inputs);
            outputs.push(reader_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        scheduled +=
            feed::<D, _, _>(BATCH_SIZE, &mut inputs[..], &mut program, &mut witness).await as usize;
        scheduled +=
            feed::<D, _, _>(BATCH_SIZE, &mut inputs[..], &mut program, &mut witness).await as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            scheduled -= 1;

            // wait for output from every task in order (to avoid one task racing a head)
            for rx in outputs.iter_mut() {
                let output = rx.recv().await;
                dst.send(output.unwrap()).await?; // can fail
            }

            // schedule a new task and wait for all works to complete one
            scheduled += feed::<D, _, _>(BATCH_SIZE, &mut inputs[..], &mut program, &mut witness)
                .await as usize;
        }

        // wait for tasks to finish
        inputs.clear();
        for t in tasks {
            t.await.unwrap();
        }
        Ok(())
    }
}
