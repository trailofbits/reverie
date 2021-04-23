use crate::util::Writer;

use super::*;

use crate::algebra::{Domain, LocalOperation, Packable, RingElement, RingModule, Sharing};
use crate::consts::*;
use crate::oracle::RandomOracle;
use crate::preprocessing::verifier::PreprocessingExecution;
use crate::util::*;
use crate::Instructions;

use std::marker::PhantomData;
use std::sync::Arc;

use async_channel::{Receiver, Sender};

use async_std::task;

const DEFAULT_CAPACITY: usize = 1024;

pub struct StreamingVerifier<D: Domain> {
    proof: Proof<D>,
    program: Arc<Vec<Instruction<D::Scalar>>>,
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

impl<D: Domain> StreamingVerifier<D> {
    pub fn new(program: Arc<Vec<Instruction<D::Scalar>>>, proof: Proof<D>) -> Self {
        StreamingVerifier {
            program,
            proof,
            _ph: PhantomData,
        }
    }

    pub async fn verify(
        self,
        bind: Option<Vec<u8>>,
        proof: Receiver<Vec<u8>>,
    ) -> Result<Output<D>, String> {
        async fn process<D: Domain>(
            run: Run<D>,
            outputs: Sender<()>,
            inputs: Receiver<(
                Arc<Instructions<D>>, // next slice of program
                Vec<u8>,              // next chunk
            )>,
        ) -> Option<(Hash, Hash, usize, Vec<D::Scalar>)> {
            let mut wires = VecMap::new();
            let mut transcript: RingHasher<_> = RingHasher::new();
            let mut output: Vec<D::Scalar> = Vec::with_capacity(5);
            let mut corrections_hash: RingHasher<_> = RingHasher::new();

            // pre-processing output
            let mut preprocessing = PreprocessingExecution::<D>::new(&run.open);
            let mut masks: Vec<D::Sharing> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma: Vec<D::Sharing> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut broadcast_upstream: Vec<D::Batch> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut corrections_upstream: Vec<D::Batch> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut masked_witness_upstream: Vec<D::Scalar> = Vec::with_capacity(DEFAULT_CAPACITY);

            // check branch proof
            let root = {
                // recompute the root from the stored randomness
                run.proof.verify()
            };

            loop {
                match inputs.recv().await {
                    Err(_) => {
                        // return commitment to preprocessing and online transcript
                        let omitted = preprocessing.omitted();
                        return Some((
                            preprocessing.commitment(&root, &run.commitment),
                            transcript.finalize(),
                            omitted,
                            output,
                        ));
                    }
                    Ok((program, chunk)) => {
                        // deserialize the chunk
                        masked_witness_upstream.clear();
                        corrections_upstream.clear();
                        broadcast_upstream.clear();
                        let chunk: Chunk = bincode::deserialize(&chunk[..]).ok()?;
                        Packable::unpack(&mut masked_witness_upstream, &chunk.witness[..]).ok()?;
                        Packable::unpack(&mut corrections_upstream, &chunk.corrections[..]).ok()?;
                        Packable::unpack(&mut broadcast_upstream, &chunk.broadcast[..]).ok()?;

                        // add corrections to player 0 view
                        for elem in corrections_upstream.iter().cloned() {
                            corrections_hash.update(elem);
                        }

                        // reset preprocessing output buffers
                        masks.clear();
                        ab_gamma.clear();

                        // run (partial) preprocessing on next chunk
                        preprocessing.process(
                            &program[..],
                            &corrections_upstream[..],
                            &mut masks,
                            &mut ab_gamma,
                        )?;

                        // consume preprocessing and execute the next chunk
                        {
                            let mut masks = masks.iter().cloned();
                            let mut witness = masked_witness_upstream.iter().cloned();
                            let mut ab_gamma = ab_gamma.iter().cloned();

                            // pad omitted player scalars into sharings (zero shares for all other players)
                            let mut broadcast: ShareIterator<D, _> = ShareIterator::new(
                                preprocessing.omitted(),
                                broadcast_upstream.iter().cloned(),
                            );

                            for step in program.iter().cloned() {
                                match step {
                                    Instruction::LocalOp(dst, src) => {
                                        let w: D::Scalar = wires.get(src);
                                        wires.set(dst, w.operation());
                                        #[cfg(feature = "trace")]
                                        {
                                            println!(
                                                "verifier-perm  : wire = {:?}",
                                                wires.get(dst)
                                            );
                                        }
                                    }
                                    Instruction::Input(dst) => {
                                        wires.set(dst, witness.next()?);
                                        #[cfg(feature = "trace")]
                                        {
                                            println!(
                                                "verifier-input : wire = {:?}",
                                                wires.get(dst)
                                            );
                                        }
                                    }
                                    Instruction::Const(dst, c) => {
                                        wires.set(dst, c);
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
                                        #[cfg(feature = "trace")]
                                        {
                                            println!(
                                                "verifier-add   : a_w = {:?}, b_w = {:?}",
                                                a_w, b_w,
                                            );
                                        }
                                    }
                                    Instruction::Sub(dst, src1, src2) => {
                                        let a_w = wires.get(src1);
                                        let b_w = wires.get(src2);
                                        wires.set(dst, a_w - b_w);
                                        #[cfg(feature = "trace")]
                                        {
                                            println!(
                                                "verifier-sub   : a_w = {:?}, b_w = {:?}",
                                                a_w, b_w,
                                            );
                                        }
                                    }
                                    Instruction::Mul(dst, src1, src2) => {
                                        // calculate reconstruction shares for every player
                                        let a_w = wires.get(src1);
                                        let b_w = wires.get(src2);
                                        let a_m: D::Sharing = masks.next().unwrap();
                                        let b_m: D::Sharing = masks.next().unwrap();
                                        let ab_gamma: D::Sharing = ab_gamma.next().unwrap();
                                        let omit_msg: D::Sharing = broadcast.next()?;
                                        let recon =
                                            a_m.action(b_w) + b_m.action(a_w) + ab_gamma + omit_msg;
                                        transcript.write(recon);

                                        // corrected wire
                                        let c_w = recon.reconstruct() + a_w * b_w;

                                        // reconstruct and correct share
                                        wires.set(dst, c_w);
                                    }
                                    Instruction::Output(src) => {
                                        let recon: D::Sharing =
                                            masks.next().unwrap() + broadcast.next()?;
                                        transcript.write(recon);

                                        output.write(wires.get(src) + recon.reconstruct());
                                    }
                                }
                            }

                            debug_assert!(masks.next().is_none());
                        }

                        outputs.send(()).await.unwrap();
                    }
                }
            }
        }

        type TaskHandle<T> =
            task::JoinHandle<Option<(Hash, Hash, usize, Vec<<T as Domain>::Scalar>)>>;
        async fn collect_transcript_hashes<D: Domain>(
            bind: Option<Vec<u8>>,
            tasks: Vec<TaskHandle<D>>,
        ) -> Result<(Vec<<D as Domain>::Scalar>, Vec<Hash>), String> {
            // collect transcript hashes from all executions
            let mut result: Vec<D::Scalar> = vec![];
            let mut oracle =
                RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind.as_ref().map(|x| &x[..]));
            let mut omitted: Vec<usize> = Vec::with_capacity(D::ONLINE_REPETITIONS);
            let mut pp_hashes: Vec<Hash> = Vec::with_capacity(D::ONLINE_REPETITIONS);
            {
                for (i, t) in tasks.into_iter().enumerate() {
                    let (preprocessing, transcript, omit, output) = t
                        .await
                        .ok_or_else(|| String::from("Circuit evaluation failed"))?;
                    if i == 0 {
                        result = output;
                    } else if result[..] != output[..] {
                        return Err(format!(
                            "Output for task {} was {:?}, should be {:?}",
                            i, output, result
                        ));
                    }
                    omitted.push(omit);
                    oracle.feed(preprocessing.as_bytes());
                    oracle.feed(transcript.as_bytes());
                    pp_hashes.push(preprocessing);
                }
            }

            // verify opening indexes
            let should_omit = random_vector(&mut oracle.query(), D::PLAYERS, D::ONLINE_REPETITIONS);
            if omitted[..] != should_omit {
                return Err(String::from(
                    "Omitted shares did not match expected omissions",
                ));
            }

            debug_assert_eq!(pp_hashes.len(), D::ONLINE_REPETITIONS);
            debug_assert_eq!(should_omit.len(), D::ONLINE_REPETITIONS);
            Ok((result, pp_hashes))
        }

        if self.proof.runs.len() != D::ONLINE_REPETITIONS {
            return Err(String::from("Failed to complete all online repetitions"));
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for run in self.proof.runs {
            let (sender_inputs, reader_inputs) = async_channel::bounded(5);
            let (sender_outputs, reader_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D>(
                run,
                sender_outputs,
                reader_inputs,
            )));
            inputs.push(sender_inputs);
            outputs.push(reader_outputs);
        }

        let collection_task = task::spawn(collect_transcript_hashes::<D>(bind, tasks));

        let chunk_size = chunk_size(self.program.len(), inputs.len());

        while !inputs.is_empty() {
            for sender in inputs.drain(..chunk_size) {
                let chunk = proof.recv().await.unwrap();
                sender.send((self.program.clone(), chunk)).await.unwrap();
            }
            for rx in outputs.drain(..chunk_size) {
                let _ = rx.recv().await;
            }
        }

        // wait for tasks to finish
        let (result, pp_hashes) = collection_task.await?;

        // return output to verify against pre-processing
        Ok(Output { result, pp_hashes })
    }
}
