use crate::util::Writer;

use super::*;

use crate::algebra::{Domain, Packable, RingElement, RingModule, Sharing};
use crate::consts::*;
use crate::fs::{Scope, View, ViewRNG};
use crate::preprocessing::verifier::PreprocessingExecution;
use crate::util::*;

use std::marker::PhantomData;
use std::sync::Arc;

use async_channel::{Receiver, Sender};
use blake3::{Hash, Hasher};
use rand::RngCore;

use async_std::task;

const DEFAULT_CAPACITY: usize = 1024;

async fn feed<D: Domain, PI: Iterator<Item = Instruction<D::Scalar>>>(
    chunk: usize,
    senders: &mut [Sender<(Arc<Vec<Instruction<D::Scalar>>>, Vec<u8>)>],
    program: &mut PI,
    chunks: &mut Receiver<Vec<u8>>,
) -> Option<bool> {
    // next slice of program
    let ps = Arc::new(read_n(program, chunk));
    if ps.len() == 0 {
        return Some(false);
    }

    // feed to workers
    for sender in senders {
        let chunk = chunks.recv().await.ok()?;
        sender.send((ps.clone(), chunk)).await.unwrap();
    }
    Some(true)
}

pub struct StreamingVerifier<D: Domain, PI: Iterator<Item = Instruction<D::Scalar>>> {
    proof: Proof<D>,
    program: PI,
    _ph: PhantomData<D>,
}

struct ShareIterator<D: Domain, I: Iterator<Item = D::Batch>> {
    idx: usize,
    src: I,
    next: usize,
    shares: Vec<D::Sharing>,
}

impl<D: Domain, I: Iterator<Item = D::Batch>> ShareIterator<D, I> {
    fn new(idx: usize, src: I) -> Self {
        ShareIterator {
            idx,
            src,
            next: D::Batch::DIMENSION,
            shares: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
        }
    }
}

impl<D: Domain, I: Iterator<Item = D::Batch>> Iterator for ShareIterator<D, I> {
    type Item = D::Sharing;

    fn next(&mut self) -> Option<Self::Item> {
        // convert the next batch
        if self.next == D::Batch::DIMENSION {
            self.next = 0;
            let mut batches = vec![D::Batch::ZERO; D::PLAYERS];
            batches[self.idx] = self.src.next()?;
            D::convert(&mut self.shares[..], &batches[..]);
        }

        // return the next partial share
        let share = self.shares[self.next];
        self.next += 1;
        Some(share)
    }
}

impl<D: Domain, PI: Iterator<Item = Instruction<D::Scalar>> + Clone> StreamingVerifier<D, PI> {
    pub fn new(program: PI, proof: Proof<D>) -> Self {
        StreamingVerifier {
            program,
            proof,
            _ph: PhantomData,
        }
    }

    pub async fn verify(mut self, mut proof: Receiver<Vec<u8>>) -> Option<Output<D>> {
        async fn process<D: Domain>(
            random: TreePRF,
            commitment: Hash,
            outputs: Sender<()>,
            inputs: Receiver<(
                Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
                Vec<u8>,                          // next chunk
            )>,
        ) -> Option<(usize, Vec<D::Scalar>, Hash, Hash)> {
            let mut wires = VecMap::new();
            let mut transcript: RingHasher<_> = RingHasher::new();
            let mut output: Vec<D::Scalar> = Vec::with_capacity(5);

            // expand the randomness for the provided players
            let mut seeds = vec![None; D::PLAYERS];
            random.expand(&mut seeds);

            // find omitted player
            let mut omitted = 0;
            for (i, seed) in seeds.iter().enumerate() {
                if seed.is_none() {
                    omitted = i;
                    break;
                }
            }

            // create a new for every player (dummy for omitted player(s))
            let mut views: Vec<View> = seeds
                .iter()
                .map(|seed| View::new_keyed(&seed.unwrap_or([0u8; KEY_SIZE])))
                .collect();

            // pre-processing output
            let mut preprocessing = PreprocessingExecution::<D>::new(&views, omitted);
            let mut masks: Vec<D::Sharing> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma: Vec<D::Sharing> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut broadcast: Vec<D::Batch> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut corrections: Vec<D::Batch> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut masked_witness: Vec<D::Scalar> = Vec::with_capacity(DEFAULT_CAPACITY);
            loop {
                match inputs.recv().await {
                    Err(_) => {
                        let mut hasher: Hasher = Hasher::new();
                        for (i, view) in views.iter().enumerate() {
                            if i == omitted {
                                hasher.update(commitment.as_bytes());
                            } else {
                                hasher.update(view.hash().as_bytes());
                            }
                        }
                        return Some((
                            omitted,
                            output,
                            transcript.finalize(), // public transcript
                            hasher.finalize(),     // player commitments
                        ));
                    }
                    Ok((program, chunk)) => {
                        // deserialize the chunk
                        let chunk: Chunk = bincode::deserialize(&chunk[..]).ok()?;
                        Packable::unpack(&mut masked_witness, &chunk.witness[..]).ok()?;
                        Packable::unpack(&mut corrections, &chunk.corrections[..]).ok()?;
                        Packable::unpack(&mut broadcast, &chunk.broadcast[..]).ok()?;

                        // add corrections to player 0 view
                        if omitted != 0 {
                            let mut corr: Scope = views[0].scope(LABEL_SCOPE_CORRECTION);
                            for elem in corrections.iter() {
                                corr.write(*elem)
                            }
                        }

                        // pre-process next chunk
                        preprocessing.process(
                            &program[..],
                            &corrections[..],
                            &mut masks,
                            &mut ab_gamma,
                        )?;

                        //
                        let mut masks = masks.iter().cloned();
                        let mut witness = masked_witness.iter().cloned();
                        let mut ab_gamma = ab_gamma.iter().cloned();
                        let mut broadcast: ShareIterator<D, _> =
                            ShareIterator::new(omitted, broadcast.iter().cloned());

                        for step in program.iter().cloned() {
                            match step {
                                Instruction::Input(dst) => {
                                    wires.set(dst, witness.next()?);
                                }
                                Instruction::AddConst(dst, src, c) => {
                                    let a_w = wires.get(src);
                                    wires.set(dst, a_w + c);
                                }
                                Instruction::MulConst(dst, src, c) => {
                                    let sw = wires.get(src);
                                    wires.set(dst, sw * c);
                                }
                                Instruction::Add(dst, src1, src2) => {
                                    let a_w = wires.get(src1);
                                    let b_w = wires.get(src2);
                                    wires.set(dst, a_w + b_w);
                                }
                                Instruction::Mul(dst, src1, src2) => {
                                    // calculate reconstruction shares for every player
                                    let a_w = wires.get(src1);
                                    let b_w = wires.get(src2);
                                    let a_m: D::Sharing = masks.next().unwrap();
                                    let b_m: D::Sharing = masks.next().unwrap();
                                    let ab_gamma: D::Sharing = ab_gamma.next().unwrap();
                                    let recon = a_m.action(b_w)
                                                    + b_m.action(a_w)
                                                    + ab_gamma // partial a * b + \gamma
                                                    + broadcast.next()?; // share of omitted player
                                                                         // reconstruct

                                    transcript.write(recon);
                                    // corrected wire
                                    let c_w = recon.reconstruct() + a_w * b_w;
                                    // reconstruct and correct share
                                    wires.set(dst, c_w);
                                    // check if call into pre-processing needed
                                    if masks.len() == 0 {
                                        break;
                                    }
                                }
                                Instruction::Output(src) => {
                                    let recon: D::Sharing =
                                        masks.next().unwrap() + broadcast.next()?;

                                    transcript.write(recon);
                                    output.write(wires.get(src) + recon.reconstruct());
                                    if masks.len() == 0 {
                                        break;
                                    }
                                }
                            }
                        }

                        outputs.send(()).await.unwrap();
                    }
                }
            }
        }

        if self.proof.runs.len() != D::ONLINE_REPETITIONS {
            return None;
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for run in self.proof.runs {
            let (sender_inputs, reader_inputs) = async_channel::bounded(5);
            let (sender_outputs, reader_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D>(
                run.open,
                Hash::from(run.commitment),
                sender_outputs,
                reader_inputs,
            )));
            inputs.push(sender_inputs);
            outputs.push(reader_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        scheduled += feed::<D, _>(BATCH_SIZE, &mut inputs[..], &mut self.program, &mut proof)
            .await? as usize;
        scheduled += feed::<D, _>(BATCH_SIZE, &mut inputs[..], &mut self.program, &mut proof)
            .await? as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            scheduled -= 1;
            // wait for output from every task in order (to avoid one task racing a head)
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }

            // schedule a new task and wait for all works to complete one
            scheduled += feed::<D, _>(BATCH_SIZE, &mut inputs[..], &mut self.program, &mut proof)
                .await? as usize;
        }

        // wait for tasks to finish
        inputs.clear();

        // collect transcript hashes from all executions
        let mut global: View = View::new();
        let mut result: Vec<D::Scalar> = vec![];
        let mut omitted: Vec<usize> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut pp_hashes: Vec<Hash> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        {
            let mut scope: Scope = global.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for (i, t) in tasks.into_iter().enumerate() {
                let (omit, output, online, preprocessing) = t.await?;
                if i == 0 {
                    result = output;
                } else {
                    if &result[..] != &output[..] {
                        return None;
                    }
                }
                omitted.push(omit);
                scope.join(&online);
                pp_hashes.push(preprocessing);
            }
        }

        // verify opening indexes
        let should_omit = random_vector(
            &mut global.prg(LABEL_RNG_OPEN_ONLINE),
            D::PLAYERS,
            D::ONLINE_REPETITIONS,
        );
        if &omitted[..] != should_omit {
            return None;
        }

        // return output to verify against pre-processing
        Some(Output { pp_hashes, result })
    }
}
