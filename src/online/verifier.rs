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
use std::iter::Cloned;
use std::slice::Iter;

const DEFAULT_CAPACITY: usize = 1024;

// TODO(ww): Figure out a reasonable type alias for `senders` below.
#[allow(clippy::type_complexity)]
async fn feed<D: Domain, PI: Iterator<Item = Instruction<D::Scalar>>>(
    chunk: usize,
    senders: &mut [Sender<(Arc<Instructions<D>>, Vec<u8>)>],
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

impl<D: Domain, PI: Iterator<Item = Instruction<D::Scalar>>> StreamingVerifier<D, PI> {
    pub fn new(program: PI, proof: Proof<D>) -> Self {
        StreamingVerifier {
            program,
            proof,
            _ph: PhantomData,
        }
    }

    pub fn new_fs(program: PI, proof_runs: Vec<OnlineRun<D>>) -> Self {
        StreamingVerifier {
            program,
            proof: Proof {
                runs: proof_runs,
                _ph: PhantomData,
            },
            _ph: PhantomData,
        }
    }

    pub async fn verify(
        self,
        bind: Option<&[u8]>,
        proof: Receiver<Vec<u8>>,
        fieldswitching_input: Vec<usize>,
        fieldswitching_output: Vec<Vec<usize>>,
    ) -> Result<Output<D>, String> {
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind);

        let (omitted, out) = match self
            .verify_round_1(
                proof,
                fieldswitching_input,
                fieldswitching_output,
                &mut oracle,
            )
            .await
        {
            Ok(out) => out,
            Err(e) => return Err(e),
        };

        if !<StreamingVerifier<D, PI>>::verify_omitted(&mut oracle, omitted) {
            return Err(String::from(
                "Omitted shares did not match expected omissions",
            ));
        }

        Ok(out)
    }

    pub async fn verify_round_1(
        mut self,
        mut proof: Receiver<Vec<u8>>,
        fieldswitching_input: Vec<usize>,
        fieldswitching_output: Vec<Vec<usize>>,
        oracle: &mut RandomOracle,
    ) -> Result<(Vec<usize>, Output<D>), String> {
        async fn process<D: Domain>(
            run: OnlineRun<D>,
            outputs: Sender<()>,
            inputs: Receiver<(
                Arc<Instructions<D>>, // next slice of program
                Vec<u8>,              // next chunk
            )>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
        ) -> Option<(Hash, Hash, usize, Vec<D::Scalar>)> {
            let mut wires = VecMap::new();
            let mut transcript: RingHasher<_> = RingHasher::new();
            let mut output: Vec<D::Scalar> = Vec::with_capacity(5);

            // pre-processing output
            let mut preprocessing = PreprocessingExecution::<D>::new(&run.open);
            let mut masks: Vec<D::Sharing> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma: Vec<D::Sharing> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut broadcast_upstream: Vec<D::Batch> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut corrections_upstream: Vec<D::Batch> = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut masked_witness_upstream: Vec<D::Scalar> = Vec::with_capacity(DEFAULT_CAPACITY);

            // check branch proof
            let (root, mut branch) = {
                // unpack bytes
                let mut branch: Vec<D::Batch> = Vec::with_capacity(DEFAULT_CAPACITY);
                Packable::unpack(&mut branch, &run.branch[..]).ok()?;

                // hash the branch
                let mut hasher = RingHasher::new();
                let mut scalars = Vec::with_capacity(branch.len() * D::Batch::DIMENSION);
                for elem in branch.into_iter() {
                    for j in 0..D::Batch::DIMENSION {
                        scalars.push(elem.get(j))
                    }
                    hasher.update(elem)
                }

                // recompute the Merkle root from the leaf and proof
                (run.proof.verify(&hasher.finalize()), scalars.into_iter())
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
                        // println!("masked witness verifier: {:?}", masked_witness_upstream);
                        Packable::unpack(&mut corrections_upstream, &chunk.corrections[..]).ok()?;
                        Packable::unpack(&mut broadcast_upstream, &chunk.broadcast[..]).ok()?;

                        // reset preprocessing output buffers
                        masks.clear();
                        ab_gamma.clear();

                        // run (partial) preprocessing on next chunk
                        preprocessing.process(
                            &program[..],
                            &corrections_upstream[..],
                            &mut masks,
                            &mut ab_gamma,
                            fieldswitching_input.clone(),
                            fieldswitching_output.clone(),
                        )?;

                        // consume preprocessing and execute the next chunk
                        {
                            let mut masks = masks.iter().cloned();
                            let mut witness = masked_witness_upstream.iter().cloned();
                            let mut ab_gamma = ab_gamma.iter().cloned();
                            let mut nr_of_wires = 0;
                            let mut fieldswitching_output_done = Vec::new();

                            // pad omitted player scalars into sharings (zero shares for all other players)
                            let mut broadcast: ShareIterator<D, _> = ShareIterator::new(
                                preprocessing.omitted(),
                                broadcast_upstream.iter().cloned(),
                            );

                            for step in program.iter().cloned() {
                                match step {
                                    Instruction::NrOfWires(nr) => {
                                        nr_of_wires = nr;
                                    }
                                    Instruction::LocalOp(dst, src) => {
                                        assert_ne!(nr_of_wires, 0);
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
                                        assert_ne!(nr_of_wires, 0);
                                        nr_of_wires = process_input::<D>(fieldswitching_input.clone(), &mut wires, &mut witness, nr_of_wires, dst);
                                    }
                                    Instruction::Branch(dst) => {
                                        assert_ne!(nr_of_wires, 0);
                                        wires.set(dst, branch.next()?);
                                    }
                                    Instruction::Const(dst, c) => {
                                        assert_ne!(nr_of_wires, 0);
                                        wires.set(dst, c);
                                    }
                                    Instruction::AddConst(dst, src, c) => {
                                        assert_ne!(nr_of_wires, 0);
                                        process_add_const::<D>(&mut wires, dst, src, c)
                                    }
                                    Instruction::MulConst(dst, src, c) => {
                                        assert_ne!(nr_of_wires, 0);
                                        let sw = wires.get(src);
                                        wires.set(dst, sw * c);
                                    }
                                    Instruction::Add(dst, src1, src2) => {
                                        assert_ne!(nr_of_wires, 0);
                                        process_add::<D>(&mut wires, dst, src1, src2)
                                    }
                                    Instruction::Mul(dst, src1, src2) => {
                                        assert_ne!(nr_of_wires, 0);
                                        process_mul(
                                            &mut wires,
                                            &mut transcript,
                                            &mut masks,
                                            &mut ab_gamma,
                                            &mut broadcast,
                                            dst,
                                            src1,
                                            src2,
                                        )
                                    }
                                    Instruction::Output(src) => {
                                        assert_ne!(nr_of_wires, 0);

                                        let mut found = false;
                                        let mut out_list = Vec::new();
                                        for imp_out in fieldswitching_output.clone() {
                                            if imp_out.contains(&src) {
                                                found = true;
                                                out_list = imp_out;
                                                break;
                                            }
                                        }
                                        if found {
                                            if !fieldswitching_output_done.contains(&src) {
                                                fieldswitching_output_done
                                                    .append(&mut out_list.clone());
                                                let mut zeroes = Vec::new();
                                                for _i in 0..out_list.len() {
                                                    nr_of_wires = process_input::<D>(fieldswitching_input.clone(), &mut wires, &mut witness, nr_of_wires, nr_of_wires);
                                                    zeroes.push(nr_of_wires);
                                                    nr_of_wires += 1;
                                                }
                                                let (outs, carry_out) = full_adder(
                                                    &mut wires,
                                                    &mut transcript,
                                                    &mut masks,
                                                    &mut ab_gamma,
                                                    &mut broadcast,
                                                    out_list,
                                                    zeroes,
                                                    nr_of_wires,
                                                );
                                                nr_of_wires = carry_out;
                                                for out in outs {
                                                    process_output(
                                                        &mut wires,
                                                        &mut transcript,
                                                        &mut output,
                                                        &mut masks,
                                                        &mut broadcast,
                                                        out,
                                                    );
                                                }
                                            }
                                        } else {
                                            process_output(
                                                &mut wires,
                                                &mut transcript,
                                                &mut output,
                                                &mut masks,
                                                &mut broadcast,
                                                src,
                                            );
                                        }
                                    }
                                }
                            }

                            // let mut count = 0;
                            // while (masks.next().is_some()) {
                            //     count +=1;
                            // }
                            // println!("nr of masks left: {:?}", count);
                            debug_assert!(masks.next().is_none());
                        }

                        outputs.send(()).await.unwrap();
                    }
                }
            }
        }

        fn process_input<D: Domain>(fieldswitching_input: Vec<usize>, mut wires: &mut VecMap<D::Scalar>, witness: &mut Cloned<Iter<D::Scalar>>, mut nr_of_wires: usize, dst: usize) -> usize {
            let mut new_dst = dst;
            if fieldswitching_input.contains(&dst) {
                new_dst = nr_of_wires;
            }

            wires.set(new_dst, witness.next().unwrap());
            #[cfg(feature = "trace")]
                {
                    println!(
                        "verifier-input : Input({}) ; wire = {:?}",
                    new_dst, wires.get(new_dst)
                    );
                }

            if fieldswitching_input.contains(&dst) {
                //TODO(gvl) Subtract constant instead of add
                nr_of_wires += 1;
                nr_of_wires = process_input::<D>(fieldswitching_input, wires, witness, nr_of_wires, nr_of_wires);
                process_add::<D>(
                    &mut wires,
                    dst,
                    new_dst,
                    nr_of_wires,
                );
                nr_of_wires += 1;
            }
            nr_of_wires
        }

        fn process_output<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            transcript: &mut RingHasher<D::Sharing>,
            output: &mut Vec<D::Scalar>,
            masks: &mut Cloned<Iter<D::Sharing>>,
            broadcast: &mut ShareIterator<D, Cloned<Iter<D::Batch>>>,
            src: usize,
        ) {
            let recon: D::Sharing = masks.next().unwrap() + broadcast.next().unwrap();
            // println!("broadcast verifier: {:?}", recon);
            transcript.write(recon);

            output.write(wires.get(src) + recon.reconstruct());

            #[cfg(feature = "trace")]
                {
                    println!(
                        "verifier-output   : Output({}) ; recon = {:?}",
                        src,
                        recon,
                    );
                }
        }

        fn process_mul<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            transcript: &mut RingHasher<D::Sharing>,
            masks: &mut Cloned<Iter<D::Sharing>>,
            ab_gamma: &mut Cloned<Iter<D::Sharing>>,
            broadcast: &mut ShareIterator<D, Cloned<Iter<D::Batch>>>,
            dst: usize,
            src1: usize,
            src2: usize,
        ) {
            // calculate reconstruction shares for every player
            let a_w = wires.get(src1);
            let b_w = wires.get(src2);
            let a_m: D::Sharing = masks.next().unwrap();
            let b_m: D::Sharing = masks.next().unwrap();
            let ab_gamma: D::Sharing = ab_gamma.next().unwrap();
            let omit_msg: D::Sharing = broadcast.next().unwrap();
            let recon = a_m.action(b_w) + b_m.action(a_w) + ab_gamma + omit_msg;
            // println!("broadcast verifier: {:?}", recon);
            transcript.write(recon);

            // corrected wire
            let c_w = recon.reconstruct() + a_w * b_w;

            // reconstruct and correct share
            wires.set(dst, c_w);

            #[cfg(feature = "trace")]
                {
                    println!(
                        "verifier-mul      : Mul({}, {}, {}) ; recon = {:?}",
                        dst,
                        src1,
                        src2,
                        recon,
                    );
                }
        }

        fn process_add<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            dst: usize,
            src1: usize,
            src2: usize,
        ) {
            let a_w = wires.get(src1);
            let b_w = wires.get(src2);
            wires.set(dst, a_w + b_w);
            #[cfg(feature = "trace")]
            {
                println!("verifier-add   : Add({:?}, {:?}, {:?}) ; a_w = {:?}, b_w = {:?}", dst, src1, src2, a_w, b_w,);
            }
        }

        fn process_add_const<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            dst: usize,
            src: usize,
            c: D::Scalar,
        ) {
            let a_w = wires.get(src);
            wires.set(dst, a_w + c);
        }

        /// 1 bit adder with carry
        /// Input:
        /// input1: usize               : position of first input
        /// input2: usize               : position of second input
        /// carry_in: usize             : position of carry_in
        /// start_new_wires: usize      : free positions for added wires (start_new_wires, ...)
        ///
        /// Output:
        /// usize                       : position of output bit
        /// usize                       : position of carry out
        /// Vec<Instruction<BitScalar>> : Instruction set for adder with carry based on the given wire values as input.
        fn adder<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            transcript: &mut RingHasher<D::Sharing>,
            masks: &mut Cloned<Iter<D::Sharing>>,
            ab_gamma: &mut Cloned<Iter<D::Sharing>>,
            broadcast: &mut ShareIterator<D, Cloned<Iter<D::Batch>>>,
            input1: usize,
            input2: usize,
            carry_in: usize,
            start_new_wires: usize,
        ) -> (usize, usize) {
            process_add::<D>(wires, start_new_wires, input1, input2);
            process_add::<D>(wires, start_new_wires + 1, carry_in, start_new_wires);
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                start_new_wires + 2,
                carry_in,
                start_new_wires,
            );
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                start_new_wires + 3,
                input1,
                input2,
            );
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                start_new_wires + 4,
                start_new_wires + 2,
                start_new_wires + 3,
            );
            process_add::<D>(
                wires,
                start_new_wires + 5,
                start_new_wires + 2,
                start_new_wires + 3,
            );
            process_add::<D>(
                wires,
                start_new_wires + 6,
                start_new_wires + 4,
                start_new_wires + 5,
            );

            (start_new_wires + 1, start_new_wires + 6)
        }

        fn first_adder<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            transcript: &mut RingHasher<D::Sharing>,
            masks: &mut Cloned<Iter<D::Sharing>>,
            ab_gamma: &mut Cloned<Iter<D::Sharing>>,
            broadcast: &mut ShareIterator<D, Cloned<Iter<D::Batch>>>,
            input1: usize,
            input2: usize,
            start_new_wires: usize,
        ) -> (usize, usize) {
            process_add::<D>(wires, start_new_wires, input1, input2);
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                start_new_wires + 1,
                input1,
                input2,
            );

            (start_new_wires, start_new_wires + 1)
        }

        /// n bit adder with carry
        /// Input:
        /// start_input1: Vec<usize>     : position of the first inputs
        /// start_input2: Vec<usize>     : position of the second inputs (len(start_input1) == len(start_input2))
        /// start_new_wires: usize       : free positions for added wires (start_new_wires, ...)
        ///
        /// Output:
        /// usize                        : position of output bit
        /// usize                        : position of carry out
        /// Vec<Instruction<BitScalar>>  : Instruction set for adder with carry based on the given wire values as input.
        fn full_adder<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            transcript: &mut RingHasher<D::Sharing>,
            masks: &mut Cloned<Iter<D::Sharing>>,
            ab_gamma: &mut Cloned<Iter<D::Sharing>>,
            broadcast: &mut ShareIterator<D, Cloned<Iter<D::Batch>>>,
            start_input1: Vec<usize>,
            start_input2: Vec<usize>,
            start_new_wires: usize,
        ) -> (Vec<usize>, usize) {
            assert_eq!(start_input1.len(), start_input2.len());
            assert!(!start_input1.is_empty());
            let mut output_bits = Vec::new();
            let mut start_new_wires_mut = start_new_wires;

            let (mut output_bit, mut carry_out) = first_adder(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                start_input1[0],
                start_input2[0],
                start_new_wires,
            );
            output_bits.push(output_bit);
            for i in 1..start_input1.len() {
                start_new_wires_mut += carry_out;
                let (output_bit1, carry_out1) = adder(
                    wires,
                    transcript,
                    masks,
                    ab_gamma,
                    broadcast,
                    start_input1[i],
                    start_input2[i],
                    carry_out,
                    start_new_wires_mut,
                );
                output_bit = output_bit1;
                carry_out = carry_out1;
                output_bits.push(output_bit);
            }

            (output_bits, carry_out+1)
        }

        if self.proof.runs.len() != D::ONLINE_REPETITIONS {
            return Err(String::from("Failed to complete all online repetitions"));
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for run in self.proof.runs.iter().cloned() {
            let (sender_inputs, reader_inputs) = async_channel::bounded(5);
            let (sender_outputs, reader_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D>(
                run,
                sender_outputs,
                reader_inputs,
                fieldswitching_input.clone(),
                fieldswitching_output.clone(),
            )));
            inputs.push(sender_inputs);
            outputs.push(reader_outputs);
        }

        // schedule up to 2 tasks immediately (for better performance)
        let mut scheduled = 0;
        scheduled += feed::<D, _>(BATCH_SIZE, &mut inputs[..], &mut self.program, &mut proof)
            .await
            .ok_or_else(|| String::from("Failed to schedule tasks"))? as usize;
        scheduled += feed::<D, _>(BATCH_SIZE, &mut inputs[..], &mut self.program, &mut proof)
            .await
            .ok_or_else(|| String::from("Failed to schedule tasks"))? as usize;

        // wait for all scheduled tasks to complete
        while scheduled > 0 {
            scheduled -= 1;
            // wait for output from every task in order (to avoid one task racing a head)
            for rx in outputs.iter_mut() {
                let _ = rx.recv().await;
            }

            // schedule a new task and wait for all works to complete one
            scheduled += feed::<D, _>(BATCH_SIZE, &mut inputs[..], &mut self.program, &mut proof)
                .await
                .ok_or_else(|| String::from("Failed to schedule tasks"))?
                as usize;
        }

        // wait for tasks to finish
        inputs.clear();

        // collect transcript hashes from all executions
        let mut result: Vec<D::Scalar> = vec![];
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
                // println!("verifier transcript feed: {:?}", transcript);
                // println!("verif preprocessing: {:?}", preprocessing.as_bytes());
                // println!("verif transcript: {:?}", transcript.as_bytes());
                oracle.feed(preprocessing.as_bytes());
                oracle.feed(transcript.as_bytes());
                pp_hashes.push(preprocessing);
            }
        }

        debug_assert_eq!(pp_hashes.len(), D::ONLINE_REPETITIONS);

        // return output to verify against pre-processing
        Ok((omitted, Output { pp_hashes, result }))
    }

    pub fn verify_omitted(oracle: &mut RandomOracle, omitted: Vec<usize>) -> bool {
        // verify opening indexes
        let should_omit = random_vector(
            &mut oracle.clone().query(),
            D::PLAYERS,
            D::ONLINE_REPETITIONS,
        );
        if omitted[..] != should_omit {
            return false;
        }

        debug_assert_eq!(should_omit.len(), D::ONLINE_REPETITIONS);

        true
    }
}
