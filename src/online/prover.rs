use super::*;

use crate::algebra::Packable;
use crate::algebra::{Domain, RingModule, Sharing};
use crate::consts::*;
use crate::crypto::TreePRF;
use crate::fs::Scope;
use crate::preprocessing::prover::PreprocessingExecution;
use crate::preprocessing::PreprocessingOutput;
use crate::util::*;

use std::sync::Arc;

use async_channel::{Receiver, SendError, Sender};
use async_std::task;

use blake3::Hash;
use rand::RngCore;

use bincode;

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
    for sender in senders {
        sender.send((ps.clone(), ws.clone())).await.unwrap();
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

pub struct StreamingProver<D: Domain, const R: usize, const N: usize, const NT: usize> {
    preprocessing: PreprocessingOutput<D, R, N>,
    chunk_size: usize,
    omitted: [usize; R],
}

struct BatchExtractor<D: Domain, W: Writer<D::Batch>, const N: usize> {
    idx: usize,
    shares: Vec<D::Sharing>,
    writer: W,
}

impl<D: Domain, W: Writer<D::Batch>, const N: usize> BatchExtractor<D, W, N> {
    fn new(idx: usize, writer: W) -> Self {
        debug_assert!(idx < N);
        BatchExtractor {
            idx,
            shares: Vec::with_capacity(D::Batch::DIMENSION),
            writer,
        }
    }
}

impl<D: Domain, W: Writer<D::Batch>, const N: usize> Writer<D::Sharing>
    for BatchExtractor<D, W, N>
{
    fn write(&mut self, elem: D::Sharing) {
        self.shares.push(elem);
        if self.shares.len() == D::Batch::DIMENSION {
            let mut batches = [D::Batch::ZERO; N];
            D::convert_inv(&mut batches[..], &self.shares[..]);
            self.writer.write(batches[self.idx]);
            self.shares.clear();
        }
    }
}

impl<D: Domain, W: Writer<D::Batch>, const N: usize> Drop for BatchExtractor<D, W, N> {
    fn drop(&mut self) {
        if self.shares.len() == 0 {
            return;
        }

        let mut batches = [D::Batch::ZERO; N];
        self.shares.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
        D::convert_inv(&mut batches[..], &self.shares[..]);
        self.writer.write(batches[self.idx]);
        self.shares.clear();
    }
}

struct Prover<D: Domain, const N: usize> {
    wires: VecMap<D::Scalar>,
}

impl<D: Domain, const N: usize> Prover<D, N> {
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
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        println!("prover-broadcast: {:?}", recon);
                    }

                    // reconstruct
                    broadcast.write(recon);

                    // corrected wire
                    let c_w = recon.reconstruct() + a_w * b_w;

                    // reconstruct and correct share
                    self.wires.set(dst, c_w);
                }
                Instruction::Output(_src) => {
                    let recon: D::Sharing = masks.next().unwrap();

                    // reconstruct
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        println!("prover-broadcast: {:?}", recon);
                    }
                    broadcast.write(recon);

                    // output for debugging
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    {
                        let output = self.wires.get(_src) + recon.reconstruct();
                        println!("prover-output: {:?}", output);
                    }
                }
            }
        }
    }
}

impl<D: Domain, const R: usize, const N: usize, const NT: usize> StreamingProver<D, R, N, NT> {
    /// Creates a new proof of program execution on the input provided.
    ///
    /// It is crucial for zero-knowledge that the pre-processing output is not reused!
    /// To help ensure this Proof::new takes ownership of PreprocessedProverOutput,
    /// which prevents the programmer from accidentally re-using the output
    pub fn new<PI: Iterator<Item = Instruction<D::Scalar>>, WI: Iterator<Item = D::Scalar>>(
        preprocessing: PreprocessingOutput<D, R, N>,
        program: PI,
        witness: WI,
    ) -> (Proof<D, R, N, NT>, Self) {
        task::block_on(Self::new_internal(preprocessing, program, witness))
    }

    async fn new_internal<
        PI: Iterator<Item = Instruction<D::Scalar>>,
        WI: Iterator<Item = D::Scalar>,
    >(
        preprocessing: PreprocessingOutput<D, R, N>,
        mut program: PI,
        mut witness: WI,
    ) -> (Proof<D, R, N, NT>, Self) {
        struct State<D: Domain, R: RngCore, const N: usize> {
            views: [View; N], // view transcripts for players
            transcript: RingHasher<D::Sharing>,
            preprocessing: PreprocessingExecution<D, R, N, true>,
            online: Prover<D, N>,
        }

        impl<D: Domain, R: RngCore, const N: usize> State<D, R, N> {
            async fn consume(
                mut self,
                outputs: Sender<()>,
                inputs: Receiver<(
                    Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
                    Arc<Vec<D::Scalar>>,              // next slice of witness
                )>,
            ) -> Result<(Hash, Vec<Hash>), SendError<Vec<u8>>> {
                loop {
                    match inputs.recv().await {
                        Ok((program, witness)) => {
                            // execute the next slice of program
                            {
                                // add corrections to player 0 view
                                let mut corr: Scope = self.views[0].scope(LABEL_SCOPE_CORRECTION);
                                // prepare pre-processing execution (online mode)
                                let mut masks = Vec::with_capacity(1024);
                                let mut ab_gamma = Vec::with_capacity(1024);
                                self.preprocessing.process(
                                    &program[..],
                                    &mut corr,
                                    &mut masks,
                                    &mut ab_gamma,
                                );

                                // compute public transcript
                                self.online.run(
                                    &program[..],
                                    &witness[..],
                                    &masks[..],
                                    &ab_gamma[..],
                                    &mut VoidWriter::new(),
                                    &mut self.transcript,
                                );
                            }

                            // needed for syncronization
                            outputs.send(()).await.unwrap();
                        }
                        Err(_) => {
                            return Ok((
                                self.transcript.finalize(),
                                self.views.iter().map(|view| view.hash()).collect(),
                            ))
                        }
                    }
                }
            }
        }

        let states = preprocessing.seeds.iter().map(|seed| {
            let tree: TreePRF<NT> = TreePRF::new(*seed);
            let keys: Array<_, N> = tree.expand().map(|x: &Option<[u8; KEY_SIZE]>| x.unwrap());
            let views = keys.map(|key| View::new_keyed(key));
            let rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));
            State {
                views: views.unbox(),
                transcript: RingHasher::new(),
                preprocessing: PreprocessingExecution::new(rngs.unbox()),
                online: Prover::<D, N>::new(),
            }
        });

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(R);
        let mut inputs = Vec::with_capacity(R);
        let mut outputs = Vec::with_capacity(R);
        for state in states {
            let (send_inputs, recv_inputs) = async_channel::bounded(5);
            let (send_outputs, recv_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(state.consume(send_outputs, recv_inputs)));
            inputs.push(send_inputs);
            outputs.push(recv_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        scheduled += feed::<D, _, _>(
            preprocessing.chunk_size,
            &mut inputs[..],
            &mut program,
            &mut witness,
        )
        .await as usize;
        scheduled += feed::<D, _, _>(
            preprocessing.chunk_size,
            &mut inputs[..],
            &mut program,
            &mut witness,
        )
        .await as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            scheduled -= 1;

            // wait for output from every task to avoid one task racing a head
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }

            // schedule a new task
            scheduled += feed::<D, _, _>(
                preprocessing.chunk_size,
                &mut inputs[..],
                &mut program,
                &mut witness,
            )
            .await as usize;
        }

        // close input writers
        inputs.clear();

        // extract which players to omit in every run (Fiat-Shamir)
        let mut global: View = View::new();
        let mut commitments = Vec::new();
        {
            let mut scope: Scope = global.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for t in tasks.into_iter() {
                let (public, comm) = t.await.unwrap();
                commitments.push(comm);
                scope.join(&public);
            }
        }
        let mut rng = global.rng(LABEL_RNG_OPEN_ONLINE);
        let mut omitted: [usize; R] = [0; R];
        for i in 0..R {
            omitted[i] = random_usize::<_, N>(&mut rng);
        }

        // puncture prfs at omitted players
        let runs = Array::from_iter(
            omitted
                .iter()
                .cloned()
                .zip(commitments.iter())
                .zip(preprocessing.seeds.iter())
                .map(|((omit, comm), seed)| {
                    let tree = TreePRF::new(*seed);
                    Run {
                        commitment: *comm[omit].as_bytes(),
                        open: tree.puncture(omit),
                    }
                }),
        );

        // rewind the program and input iterators and
        // return prover ready to stream out the proof
        let chunk_size = preprocessing.chunk_size;
        (
            Proof {
                runs,
                chunk_size,
                _ph: PhantomData,
            },
            StreamingProver {
                chunk_size,
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
        struct State<D: Domain, R: RngCore, const N: usize> {
            omitted: usize,
            chunk_size: usize,
            preprocessing: PreprocessingExecution<D, R, N, true>,
            online: Prover<D, N>,
        }

        impl<D: Domain, R: RngCore, const N: usize> State<D, R, N> {
            async fn consume(
                mut self,
                outputs: Sender<Vec<u8>>,
                inputs: Receiver<(
                    Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
                    Arc<Vec<D::Scalar>>,              // next slice of witness
                )>,
            ) -> Result<(), SendError<Vec<u8>>> {
                // output buffers used during execution
                let mut masks = Vec::with_capacity(2 * self.chunk_size);
                let mut ab_gamma = Vec::with_capacity(self.chunk_size);
                let mut corrections = Vec::with_capacity(self.chunk_size);
                let mut broadcast = Vec::with_capacity(self.chunk_size);
                let mut masked = Vec::with_capacity(self.chunk_size);

                // packed elements to be serialized
                let mut chunk = Chunk {
                    witness: Vec::with_capacity(self.chunk_size),
                    broadcast: Vec::with_capacity(self.chunk_size),
                    corrections: Vec::with_capacity(self.chunk_size),
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
                                let mut corrections =
                                    SwitchWriter::new(&mut corrections, self.omitted != 0);
                                self.preprocessing.process(
                                    &program[..],
                                    &mut corrections,
                                    &mut masks,
                                    &mut ab_gamma,
                                );

                                // compute public transcript
                                self.online.run(
                                    &program[..],
                                    &witness[..],
                                    &masks[..],
                                    &ab_gamma[..],
                                    &mut masked,
                                    &mut BatchExtractor::<D, _, N>::new(
                                        self.omitted,
                                        &mut broadcast,
                                    ),
                                );
                            }

                            // serialize the chunk
                            #[cfg(test)]
                            #[cfg(debug_assertions)]
                            {
                                println!("send:masked_witness = {:?}", &masked[..]);
                                println!("send:corrections = {:?}", &corrections[..]);
                                println!("send:broadcast = {:?}", &broadcast[..]);
                            }
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
        }

        // initialize state for every
        let states = self
            .omitted
            .iter()
            .cloned()
            .zip(self.preprocessing.seeds.iter())
            .map(|(omitted, seed)| {
                let tree: TreePRF<NT> = TreePRF::new(*seed);
                let keys: Array<_, N> = tree.expand().map(|x: &Option<[u8; KEY_SIZE]>| x.unwrap());
                let views = keys.map(|key| View::new_keyed(key));
                let rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));
                State {
                    omitted,
                    chunk_size: self.chunk_size,
                    preprocessing: PreprocessingExecution::new(rngs.unbox()),
                    online: Prover::<D, N>::new(),
                }
            });

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(R);
        let mut inputs = Vec::with_capacity(R);
        let mut outputs = Vec::with_capacity(R);
        for state in states {
            let (sender_inputs, reader_inputs) = async_channel::bounded(5);
            let (sender_outputs, reader_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(state.consume(sender_outputs, reader_inputs)));
            inputs.push(sender_inputs);
            outputs.push(reader_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        for _ in 0..2 {
            scheduled +=
                feed::<D, _, _>(self.chunk_size, &mut inputs[..], &mut program, &mut witness).await
                    as usize;
        }

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            scheduled -= 1;

            // wait for output from every task in order (to avoid one task racing a head)
            for rx in outputs.iter_mut() {
                let output = rx.recv().await;
                dst.send(output.unwrap()).await?; // can fail
            }

            // schedule a new task and wait for all works to complete one
            scheduled +=
                feed::<D, _, _>(self.chunk_size, &mut inputs[..], &mut program, &mut witness).await
                    as usize;
        }

        // wait for tasks to finish
        inputs.clear();
        for t in tasks {
            t.await.unwrap();
        }
        Ok(())
    }
}
