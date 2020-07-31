use super::*;

use crate::algebra::Packable;
use crate::algebra::{Domain, RingModule, Sharing};
use crate::consts::*;
use crate::crypto::TreePRF;
use crate::fs::*;
use crate::preprocessing::prover::PreprocessingExecution;
use crate::preprocessing::PreprocessingOutput;
use crate::util::*;

use std::mem;
use std::sync::Arc;

use async_channel::{Receiver, SendError, Sender};
use async_std::task;

use blake3::Hash;

use bincode;

const DEFAULT_CAPACITY: usize = BATCH_SIZE;

async fn feed<
    D: Domain,
    PI: Iterator<Item = Instruction<D::Scalar>>,
    WI: Iterator<Item = D::Scalar>,
>(
    chunk: usize,
    senders: &mut [Sender<(Arc<Vec<Instruction<D::Scalar>>>, Arc<Vec<D::Scalar>>)>],
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
        if self.shares.len() == 0 {
            return;
        }

        let mut batches = vec![D::Batch::ZERO; D::PLAYERS];
        self.shares.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
        D::convert_inv(&mut batches[..], &self.shares[..]);
        self.writer.write(batches[self.idx]);
        self.shares.clear();
    }
}

struct Prover<D: Domain> {
    wires: VecMap<D::Scalar>,
}

impl<D: Domain> Prover<D> {
    fn new() -> Self {
        Prover {
            wires: VecMap::new(),
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
                Instruction::Input(dst) => {
                    let mask: D::Sharing = masks.next().unwrap();
                    let wire = witness.next().unwrap() + D::Sharing::reconstruct(&mask);
                    self.wires.set(dst, wire);
                    masked_witness.write(wire);
                }
                Instruction::AddConst(dst, src, c) => {
                    let a_w = self.wires.get(src);
                    self.wires.set(dst, a_w + c);
                }
                Instruction::MulConst(dst, src, c) => {
                    let sw = self.wires.get(src);
                    self.wires.set(dst, sw * c);
                }
                Instruction::Add(dst, src1, src2) => {
                    let a_w = self.wires.get(src1);
                    let b_w = self.wires.get(src2);
                    self.wires.set(dst, a_w + b_w);
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
                }
                Instruction::Output(_src) => {
                    let recon: D::Sharing = masks.next().unwrap();
                    broadcast.write(recon);
                }
            }
        }
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
        preprocessing: PreprocessingOutput<D>,
        mut program: PI,
        mut witness: WI,
    ) -> (Proof<D>, Self) {
        assert_eq!(preprocessing.seeds.len(), D::ONLINE_REPETITIONS);

        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            outputs: Sender<()>,
            inputs: Receiver<(
                Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
                Arc<Vec<D::Scalar>>,              // next slice of witness
            )>,
        ) -> Result<(Hash, Vec<View>), SendError<Vec<u8>>> {
            let mut seeds = vec![[0u8; KEY_SIZE]; D::PLAYERS];
            TreePRF::expand_full(&mut seeds, root);

            let mut views: Vec<View> = seeds.iter().map(|seed| View::new_keyed(seed)).collect();
            let mut preprocessing = PreprocessingExecution::<D>::new(&views[..], true);
            let mut transcript = RingHasher::new();
            let mut online = Prover::<D>::new();

            let mut masks = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma = Vec::with_capacity(DEFAULT_CAPACITY);
            loop {
                match inputs.recv().await {
                    Ok((program, witness)) => {
                        // execute the next slice of program
                        {
                            // prepare pre-processing execution (online mode)
                            preprocessing.process(
                                &program[..],
                                &mut views[0].scope(LABEL_SCOPE_CORRECTION),
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
                        return Ok((transcript.finalize(), views));
                    }
                }
            }
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for root in preprocessing.seeds.iter().cloned() {
            let (send_inputs, recv_inputs) = async_channel::bounded(2);
            let (send_outputs, recv_outputs) = async_channel::bounded(2);
            tasks.push(task::spawn(process::<D>(root, send_outputs, recv_inputs)));
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
        let mut views = Vec::new();
        let mut challenge_rng = {
            let mut global: View = View::new();
            let mut scope: Scope = global.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for t in tasks.into_iter() {
                let (public, players) = t.await.unwrap();
                views.push(players);
                scope.join(&public);
            }
            mem::drop(scope);
            global.prg(LABEL_RNG_OPEN_ONLINE)
        };

        let omitted: Vec<usize> =
            random_vector(&mut challenge_rng, D::PLAYERS, D::ONLINE_REPETITIONS);

        debug_assert_eq!(omitted.len(), D::ONLINE_REPETITIONS);

        let runs = omitted
            .iter()
            .cloned()
            .zip(views.iter())
            .zip(preprocessing.seeds.iter().cloned())
            .map(|((omit, views), seed)| {
                let tree = TreePRF::new(D::PLAYERS, seed);
                Run {
                    commitment: *views[omit].hash().as_bytes(),
                    open: tree.puncture(omit),
                    _ph: PhantomData,
                }
            })
            .collect();

        // rewind the program and input iterators and
        // return prover ready to stream out the proof
        (
            Proof {
                runs,
                _ph: PhantomData,
            },
            StreamingProver {
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
            outputs: Sender<Vec<u8>>,
            inputs: Receiver<(
                Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
                Arc<Vec<D::Scalar>>,              // next slice of witness
            )>,
        ) -> Result<(), SendError<Vec<u8>>> {
            let mut seeds = vec![[0u8; KEY_SIZE]; D::PLAYERS];
            TreePRF::expand_full(&mut seeds, root);

            let views: Vec<View> = seeds.iter().map(|seed| View::new_keyed(seed)).collect();
            let mut preprocessing = PreprocessingExecution::<D>::new(&views[..], true);
            let mut online = Prover::<D>::new();

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
                        Packable::pack(&mut chunk.witness, &masked[..]).unwrap();
                        Packable::pack(&mut chunk.broadcast, &broadcast[..]).unwrap();
                        Packable::pack(&mut chunk.corrections, &corrections[..]).unwrap();
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
        for (root, omit) in self.preprocessing.seeds.iter().zip(self.omitted.iter()) {
            let (sender_inputs, reader_inputs) = async_channel::bounded(3);
            let (sender_outputs, reader_outputs) = async_channel::bounded(3);
            tasks.push(task::spawn(process::<D>(
                *root,
                *omit,
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
