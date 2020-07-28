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

pub struct StreamingVerifier<
    D: Domain,
    PI: Iterator<Item = Instruction<D::Scalar>>,
    const R: usize,
    const N: usize,
    const NT: usize,
> {
    proof: Proof<D, R, N, NT>,
    program: PI,
    _ph: PhantomData<D>,
}

struct ShareIterator<D: Domain, I: Iterator<Item = D::Batch>, const N: usize> {
    idx: usize,
    src: I,
    next: usize,
    shares: Vec<D::Sharing>,
}

impl<D: Domain, I: Iterator<Item = D::Batch>, const N: usize> ShareIterator<D, I, N> {
    fn new(idx: usize, src: I) -> Self {
        debug_assert!(idx < N);
        ShareIterator {
            idx,
            src,
            next: D::Batch::DIMENSION,
            shares: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
        }
    }
}

impl<D: Domain, I: Iterator<Item = D::Batch>, const N: usize> Iterator for ShareIterator<D, I, N> {
    type Item = D::Sharing;

    fn next(&mut self) -> Option<Self::Item> {
        // convert the next batch
        if self.next == D::Batch::DIMENSION {
            self.next = 0;
            let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
            batches[self.idx] = self.src.next()?;
            D::convert(&mut self.shares[..], &batches[..]);
        }

        // return the next partial share
        let share = self.shares[self.next];
        self.next += 1;
        Some(share)
    }
}

impl<
        D: Domain,
        PI: Iterator<Item = Instruction<D::Scalar>> + Clone,
        const R: usize,
        const N: usize,
        const NT: usize,
    > StreamingVerifier<D, PI, R, N, NT>
{
    pub fn new(program: PI, proof: Proof<D, R, N, NT>) -> Self {
        StreamingVerifier {
            program,
            proof,
            _ph: PhantomData,
        }
    }

    pub async fn verify(mut self, mut proof: Receiver<Vec<u8>>) -> Option<Output<D, R>> {
        struct State<D: Domain, RNG: RngCore, const N: usize> {
            views: Array<View, N>, // view transcripts for players
            omitted: usize,   // index of omitted player
            commitment: Hash, // commitment to the view of the unopened player
            chunk_size: usize,
            preprocessing: PreprocessingExecution<D, RNG, N>,
        }

        impl<D: Domain, RNG: RngCore, const N: usize> State<D, RNG, N> {
            async fn consume(
                mut self,
                outputs: Sender<()>,
                inputs: Receiver<(
                    Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
                    Vec<u8>,                          // next chunk
                )>,
            ) -> Option<(usize, Vec<D::Scalar>, Hash, Hash)> {
                let mut wires = VecMap::new();
                let mut transcript: RingHasher<_> = RingHasher::new();
                let mut output: Vec<D::Scalar> = Vec::with_capacity(5);

                // pre-processing output
                let mut masks: Vec<D::Sharing> = Vec::with_capacity(2 * self.chunk_size);
                let mut ab_gamma: Vec<D::Sharing> = Vec::with_capacity(self.chunk_size);

                // deserialized proof
                let mut broadcast: Vec<D::Batch> = Vec::with_capacity(self.chunk_size);
                let mut corrections: Vec<D::Batch> = Vec::with_capacity(self.chunk_size);
                let mut masked_witness: Vec<D::Scalar> = Vec::with_capacity(self.chunk_size);
                loop {
                    match inputs.recv().await {
                        Err(_) => {
                            let mut hasher: Hasher = Hasher::new();
                            for (i, view) in self.views.iter().enumerate() {
                                if i == self.omitted {
                                    hasher.update(self.commitment.as_bytes());
                                } else {
                                    hasher.update(view.hash().as_bytes());
                                }
                            }
                            return Some((
                                self.omitted,
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
                            if self.omitted != 0 {
                                let mut corr: Scope = self.views[0].scope(LABEL_SCOPE_CORRECTION);
                                for elem in corrections.iter() {
                                    corr.write(*elem)
                                }
                            }

                            // pre-process next chunk
                            self.preprocessing.process(
                                &program[..],
                                &corrections[..],
                                &mut masks,
                                &mut ab_gamma,
                            )?;

                            //
                            let mut masks = masks.iter().cloned();
                            let mut witness = masked_witness.iter().cloned();
                            let mut ab_gamma = ab_gamma.iter().cloned();
                            let mut broadcast: ShareIterator<D, _, N> =
                                ShareIterator::new(self.omitted, broadcast.iter().cloned());

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
        }

        let states = self.proof.runs.iter().map(|run| {
            // expand keys
            let keys: Array<_, N> = run.open.expand();

            // find the punctured position of the PRF (omitted player index)
            let omitted = keys.iter().position(|key| key.is_none()).unwrap_or(0);

            // replace omitted key(s) with dummy
            let keys = keys.map(|v| v.unwrap_or([0u8; KEY_SIZE]));

            //
            let views = keys.map(|key| View::new_keyed(key));
            let rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));
            State::<D, ViewRNG, N> {
                chunk_size: self.proof.chunk_size,
                omitted,
                views: views,
                commitment: Hash::from(run.commitment),
                preprocessing: PreprocessingExecution::new(rngs.unbox(), omitted),
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
            scheduled += feed::<D, _>(
                self.proof.chunk_size,
                &mut inputs[..],
                &mut self.program,
                &mut proof,
            )
            .await? as usize;
        }

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            scheduled -= 1;
            // wait for output from every task in order (to avoid one task racing a head)
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }

            // schedule a new task and wait for all works to complete one
            scheduled += feed::<D, _>(
                self.proof.chunk_size,
                &mut inputs[..],
                &mut self.program,
                &mut proof,
            )
            .await? as usize;
        }

        // wait for tasks to finish
        inputs.clear();

        // collect transcript hashes from all executions
        let mut global: View = View::new();
        let mut result: Vec<D::Scalar> = vec![];
        let mut omitted: [usize; R] = [0; R];
        let mut pp_hashes: Vec<Hash> = Vec::with_capacity(R);
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
                omitted[i] = omit;
                scope.join(&online);
                pp_hashes.push(preprocessing);
            }
        }

        // verify opening indexes
        let mut rng = global.rng(LABEL_RNG_OPEN_ONLINE);
        for i in 0..R {
            if omitted[i] != random_usize::<_, N>(&mut rng) {
                return None;
            }
        }

        // return output to verify against pre-processing
        Some(Output {
            pp_hashes: Array::from_iter(pp_hashes.iter().cloned()),
            result,
        })
    }
}
