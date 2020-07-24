use crate::util::Writer;

use super::*;

use crate::algebra::{Domain, Packable, RingElement, RingModule, Sharing};
use crate::consts::{
    LABEL_RNG_OPEN_ONLINE, LABEL_RNG_PREPROCESSING, LABEL_SCOPE_CORRECTION,
    LABEL_SCOPE_ONLINE_TRANSCRIPT,
};
use crate::fs::{Scope, View};
use crate::preprocessing::verifier::PreprocessingExecution;
use crate::util::*;

use std::marker::PhantomData;
use std::sync::Arc;

use async_channel::{Receiver, RecvError, Sender};
use blake3::{Hash, Hasher};
use rand::RngCore;

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

pub struct StreamingVerifier<
    D: Domain,
    PI: Iterator<Item = Instruction<D::Scalar>> + Clone,
    const R: usize,
    const N: usize,
    const NT: usize,
> {
    runs: [Run<R, N, NT>; R],
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

/// This ensures that the user can only get access to the output
/// by validating the online execution against a correctly validated and matching pre-processing execution.
///
/// Avoiding potential misuse where the user fails to check the pre-processing.
pub struct Output<D: Domain, const R: usize> {
    output: Vec<D::Scalar>,
    pp_hashes: Array<Hash, R>,
}

impl<D: Domain, const R: usize> Output<D, R> {
    pub fn check(&self, pp_hashes: &[Hash; R]) -> Option<&[D::Scalar]> {
        for i in 0..R {
            if pp_hashes[i] != self.pp_hashes[i] {
                return None;
            }
        }
        Some(&self.output[..])
    }

    // provides access to the output without checking the pre-processing
    // ONLY USED IN TESTS
    #[cfg(test)]
    pub(super) fn unsafe_output(&self) -> &[D::Scalar] {
        &self.output[..]
    }
}

struct Verifier<D: Domain, const N: usize> {
    omitted: usize,
    wires: VecMap<D::Scalar>,
}

impl<D: Domain, const N: usize> Verifier<D, N> {
    fn new(omitted: usize) -> Self {
        Verifier {
            omitted,
            wires: VecMap::new(),
        }
    }

    fn run<TW: Writer<D::Sharing>, OW: Writer<D::Scalar>>(
        &mut self,
        output: &mut OW,
        transcript: &mut TW,
        program: &[Instruction<D::Scalar>],
        masked_witness: &[D::Scalar],
        broadcast: &[D::Batch], // broadcast messages from omitted player
        preprocessing_masks: &[D::Sharing], //
        preprocessing_ab_gamma: &[D::Sharing],
    ) -> Option<()> {
        let mut witness = masked_witness.iter().cloned();

        //
        let mut masks = preprocessing_masks.iter().cloned();
        let mut ab_gamma = preprocessing_ab_gamma.iter().cloned();

        //
        let mut broadcast: ShareIterator<D, _, N> =
            ShareIterator::new(self.omitted, broadcast.iter().cloned());

        for step in program {
            match *step {
                Instruction::Input(dst) => {
                    self.wires.set(dst, witness.next()?);
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

                    let recon = a_m.action(b_w)
                                + b_m.action(a_w)
                                + ab_gamma // partial a * b + \gamma
                                + broadcast.next()?; // share of omitted player

                    // reconstruct
                    transcript.write(recon);

                    // corrected wire
                    let c_w = recon.reconstruct() + a_w * b_w;

                    // reconstruct and correct share
                    self.wires.set(dst, c_w);

                    // check if call into pre-processing needed
                    if masks.len() == 0 {
                        break;
                    }
                }
                Instruction::Output(src) => {
                    let recon: D::Sharing = masks.next().unwrap() + broadcast.next()?;

                    // reconstruct
                    transcript.write(recon);

                    // TODO: write the output to
                    output.write(self.wires.get(src) + recon.reconstruct());

                    // check if call into pre-processing needed
                    if masks.len() == 0 {
                        break;
                    }
                }
            }
        }
        Some(())
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
    pub fn new(program: PI, runs: [Run<R, N, NT>; R]) -> Self {
        StreamingVerifier {
            program,
            runs,
            _ph: PhantomData,
        }
    }

    pub async fn verify(self, reader: Receiver<Vec<u8>>) -> Option<Output<D, R>> {
        struct State<D: Domain, RNG: RngCore, const N: usize> {
            views: [View; N],                   // view transcripts for players
            omitted: usize,                     // index of omitted player
            commitment: Hash,                   // commitment to the view of the unopened player
            transcript: RingHasher<D::Sharing>, // broadcast transcript
            preprocessing: PreprocessingExecution<D, RNG, N>,
            online: Verifier<D, N>,
        }

        impl<D: Domain, RNG: RngCore, const N: usize> State<D, RNG, N> {
            async fn consume(
                mut self,
                outputs: Sender<()>,
                inputs: Receiver<(
                    Arc<Vec<Instruction<D::Scalar>>>, // next slice of program
                    Vec<u8>,                          // next chunk
                )>,
            ) -> Option<(Hash, Hash)> {
                let chunk_capacity: usize = 100_000;
                let mut transcript: RingHasher<_> = RingHasher::new();
                let mut output: Vec<D::Scalar> = Vec::with_capacity(5);

                // pre-processing output
                let mut masks: Vec<D::Sharing> = Vec::with_capacity(chunk_capacity);
                let mut ab_gamma: Vec<D::Sharing> = Vec::with_capacity(chunk_capacity);

                // deserialized proof
                let mut broadcast: Vec<D::Batch> = Vec::with_capacity(chunk_capacity);
                let mut corrections: Vec<D::Batch> = Vec::with_capacity(chunk_capacity);
                let mut masked_witness: Vec<D::Scalar> = Vec::with_capacity(chunk_capacity);
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

                            // online
                            self.online.run(
                                &mut output,
                                &mut transcript,
                                &program[..],
                                &masked_witness[..],
                                &broadcast[..],
                                &masks[..],
                                &ab_gamma[..],
                            )?;

                            outputs.send(()).await.unwrap();
                        }
                    }
                }
            }
        }

        /*
        let states = preprocessing.seeds.iter().map(|seed| {
            let tree: TreePRF<NT> = TreePRF::new(*seed);
            let keys: Array<_, N> = tree.expand().map(|x: &Option<[u8; KEY_SIZE]>| x.unwrap());
            let views = keys.map(|key| View::new_keyed(key));
            let rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));
            State {
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
             let (sender_inputs, reader_inputs) = async_channel::bounded(5);
             let (sender_outputs, reader_outputs) = async_channel::bounded(5);
             tasks.push(task::spawn(state.consume(sender_outputs, reader_inputs)));
             inputs.push(sender_inputs);
             outputs.push(reader_outputs);
         }
         // schedule up to 2 tasks immediately (for better performance)
         let mut scheduled = 0;
         for _ in 0..2 {
             scheduled += feed::<D, _, _>(
                 self.chunk_size,
                 &mut inputs[..],
                 &mut self.program,
                 &mut self.inputs,
             )
             .await as usize;
         }
         // wait for all scheduled tasks to complete
         while scheduled > 0 {
             scheduled -= 1;
             // wait for output from every task in order (to avoid one task racing a head)
             for rx in outputs.iter_mut() {
                 let output = rx.recv().await;
                 proof.send(output.unwrap()).await?; // can fail
             }
             // schedule a new task and wait for all works to complete one
             scheduled += feed::<D, _, _>(
                 self.chunk_size,
                 &mut inputs[..],
                 &mut self.program,
                 &mut self.inputs,
             )
             .await as usize;
         }
         // wait for tasks to finish
         inputs.clear();
         for t in tasks {
             t.await.unwrap();
         }
         Ok(())
         */

        /*

        let runs = runs.map(|((corrections, broadcast, masked), run)| {
            // expand keys
            let keys: Array<_, N> = run.open.expand();

            // find the punctured position of the PRF (omitted player index)
            let omitted = keys.iter().position(|key| key.is_none()).unwrap_or(0);

            // replace omitted key(s) with dummy
            let keys = keys.map(|v| v.unwrap_or([0u8; KEY_SIZE]));

            // create pre-processing instance
            let mut views = keys.map(|key| View::new_keyed(key));
            let mut rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));
            let preprocessing: PreprocessingExecution<D, _, _, _, N> =
                PreprocessingExecution::new(&mut rngs, omitted, corrections, self.program.clone());

            //
            let broadcast: ShareIterator<D, _, N> = ShareIterator::new(omitted, broadcast);
            let mut verifier: Verifier<_, _, _, _, _, R, N, NT> =
                Verifier::new(masked, self.program.clone(), broadcast, preprocessing);

            let mut transcript: RingHasher<D::Sharing> = RingHasher::new();
            verifier.run(&mut transcript);

            (omitted, transcript.finalize())
        });

        // execute the online phase R times
        let mut execs: Vec<_> = Vec::with_capacity(R);

        #[cfg(debug_assertions)]
        execs.extend(runs);

        #[cfg(not(debug_assertions))]
        runs.collect_into_vec(&mut execs);

        // extract which players to omit in every run (Fiat-Shamir)
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for (_, hash) in execs.iter() {
                scope.join(&hash);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        for (omit, _) in execs.iter() {
            if *omit != random_usize::<_, N>(&mut rng) {
                return None;
            }
        }
        */

        None
    }
}
