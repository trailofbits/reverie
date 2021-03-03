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

use crate::fieldswitching::util::FieldSwitchingIo;
use async_std::task;
use std::iter::Cloned;
use std::slice::Iter;

const DEFAULT_CAPACITY: usize = 1024;

pub struct StreamingVerifier<D: Domain> {
    pub(crate) proof: Proof<D>,
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

    pub fn new_fs(
        program: Arc<Vec<Instruction<D::Scalar>>>,
        proof_runs: Vec<OnlineRun<D>>,
    ) -> Self {
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
        mut proof: Receiver<Vec<u8>>,
        fieldswitching_io: FieldSwitchingIo,
    ) -> Result<Output<D>, String> {
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind);

        let (oracle_feed, omitted, out) =
            match self.verify_round_1(&mut proof, fieldswitching_io).await {
                Ok(out) => out,
                Err(e) => return Err(e),
            };

        debug_assert_eq!(out.pp_hashes.len(), D::ONLINE_REPETITIONS);

        for feed in oracle_feed {
            oracle.feed(&feed);
        }

        if !<StreamingVerifier<D>>::verify_omitted(&mut oracle, omitted) {
            return Err(String::from(
                "Omitted shares did not match expected omissions",
            ));
        }

        Ok(out)
    }

    pub async fn verify_round_1(
        self,
        proof: &mut Receiver<Vec<u8>>,
        fieldswitching_io: FieldSwitchingIo,
    ) -> Result<(Vec<[u8; 32]>, Vec<usize>, Output<D>), String> {
        let runs = self.proof.runs.clone();
        if runs.len() != D::ONLINE_REPETITIONS {
            return Err(String::from("Failed to complete all online repetitions"));
        }
        self.do_verify_round_1(proof, fieldswitching_io, runs, None)
            .await
    }

    pub(crate) async fn do_verify_round_1(
        self,
        proof: &mut Receiver<Vec<u8>>,
        fieldswitching_io: FieldSwitchingIo,
        runs: Vec<OnlineRun<D>>,
        challenge: Option<(usize, D::Scalar)>,
    ) -> Result<(Vec<[u8; 32]>, Vec<usize>, Output<D>), String> {
        async fn process<D: Domain>(
            run: OnlineRun<D>,
            outputs: Sender<()>,
            inputs: Receiver<(
                Arc<Instructions<D>>, // next slice of program
                Vec<u8>,              // next chunk
            )>,
            fieldswitching_io: FieldSwitchingIo,
            challenge: Option<(usize, D::Scalar)>,
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
            let fieldswitching_input = fieldswitching_io.0.clone();
            let fieldswitching_output = fieldswitching_io.1.clone();

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
            let mut nr_of_wires = 0;

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
                            (&program[..], nr_of_wires),
                            &corrections_upstream[..],
                            &mut masks,
                            &mut ab_gamma,
                            fieldswitching_io.clone(),
                        )?;

                        // consume preprocessing and execute the next chunk
                        {
                            let mut masks = masks.iter().cloned();
                            let mut witness = masked_witness_upstream.iter().cloned();
                            let mut ab_gamma = ab_gamma.iter().cloned();
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
                                        nr_of_wires = process_input::<D>(
                                            fieldswitching_input.clone(),
                                            &mut wires,
                                            &mut witness,
                                            nr_of_wires,
                                            dst,
                                        );
                                    }
                                    Instruction::Branch(dst) => {
                                        assert_ne!(nr_of_wires, 0);
                                        wires.set(dst, branch.next()?);
                                    }
                                    Instruction::Const(dst, c) => {
                                        assert_ne!(nr_of_wires, 0);
                                        if let Some(cha) = challenge {
                                            if cha.0 == dst {
                                                wires.set(dst, cha.1);
                                            } else {
                                                wires.set(dst, c);
                                            }
                                        } else {
                                            wires.set(dst, c);
                                        }
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
                                            (dst, src1, src2),
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
                                            fieldswitching_output_done.push(src);
                                            let mut contains_all = true;
                                            for item in out_list.clone() {
                                                if !fieldswitching_output_done.contains(&item) {
                                                    contains_all = false;
                                                }
                                            }
                                            if contains_all {
                                                let mut zeroes = Vec::new();
                                                for _i in 0..out_list.len() {
                                                    zeroes.push(nr_of_wires);
                                                    nr_of_wires = process_input::<D>(
                                                        fieldswitching_input.clone(),
                                                        &mut wires,
                                                        &mut witness,
                                                        nr_of_wires,
                                                        nr_of_wires,
                                                    );
                                                    nr_of_wires += 1;
                                                }
                                                let (outs, carry_out) = full_adder(
                                                    &mut wires,
                                                    &mut transcript,
                                                    &mut masks,
                                                    &mut ab_gamma,
                                                    &mut broadcast,
                                                    (out_list, zeroes, nr_of_wires),
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

        type TaskHandle<T> =
            task::JoinHandle<Option<(Hash, Hash, usize, Vec<<T as Domain>::Scalar>)>>;
        async fn collect_transcript_hashes<D: Domain>(
            tasks: Vec<TaskHandle<D>>,
        ) -> Result<(Vec<[u8; 32]>, Vec<usize>, Vec<Hash>, Vec<D::Scalar>), String> {
            // collect transcript hashes from all executions
            let mut result: Vec<D::Scalar> = vec![];
            let mut omitted: Vec<usize> = Vec::with_capacity(D::ONLINE_REPETITIONS);
            let mut pp_hashes: Vec<Hash> = Vec::with_capacity(D::ONLINE_REPETITIONS);
            let mut oracle_feed = Vec::new();
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
                    oracle_feed.push(*preprocessing.as_bytes());
                    oracle_feed.push(*transcript.as_bytes());
                    pp_hashes.push(preprocessing);
                }
            }
            Ok((oracle_feed, omitted, pp_hashes, result))
        }

        if self.proof.runs.len() != D::ONLINE_REPETITIONS {
            return Err(String::from("Failed to complete all online repetitions"));
        }

        fn process_input<D: Domain>(
            fieldswitching_input: Vec<usize>,
            mut wires: &mut VecMap<D::Scalar>,
            witness: &mut Cloned<Iter<D::Scalar>>,
            mut nr_of_wires: usize,
            dst: usize,
        ) -> usize {
            let mut new_dst = dst;
            if fieldswitching_input.contains(&dst) {
                new_dst = nr_of_wires;
            }

            wires.set(new_dst, witness.next().unwrap());
            #[cfg(feature = "trace")]
            {
                println!(
                    "verifier-input : Input({}) ; wire = {:?}",
                    new_dst,
                    wires.get(new_dst)
                );
            }

            if fieldswitching_input.contains(&dst) {
                nr_of_wires += 1;
                nr_of_wires = process_input::<D>(
                    fieldswitching_input,
                    wires,
                    witness,
                    nr_of_wires,
                    nr_of_wires,
                );
                process_add::<D>(&mut wires, dst, new_dst, nr_of_wires);
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

            output.write(wires.get(src) - recon.reconstruct());

            #[cfg(feature = "trace")]
            {
                println!("verifier-output   : Output({}) ; recon = {:?}", src, recon,);
            }
        }

        fn process_mul<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            transcript: &mut RingHasher<D::Sharing>,
            masks: &mut Cloned<Iter<D::Sharing>>,
            ab_gamma: &mut Cloned<Iter<D::Sharing>>,
            broadcast: &mut ShareIterator<D, Cloned<Iter<D::Batch>>>,
            wire_nrs: (usize, usize, usize),
        ) {
            // calculate reconstruction shares for every player
            let a_w = wires.get(wire_nrs.1);
            let b_w = wires.get(wire_nrs.2);
            let a_m: D::Sharing = masks.next().unwrap();
            let b_m: D::Sharing = masks.next().unwrap();
            let ab_gamma: D::Sharing = ab_gamma.next().unwrap();
            let omit_msg: D::Sharing = broadcast.next().unwrap();
            let recon = a_m.action(b_w) + b_m.action(a_w) - ab_gamma + omit_msg;
            // println!("broadcast verifier: {:?}", recon);
            transcript.write(recon);

            // corrected wire
            let min_one = D::Scalar::ZERO - D::Scalar::ONE;
            let c_w = min_one * (recon.reconstruct() - a_w * b_w);

            // reconstruct and correct share
            wires.set(wire_nrs.0, c_w);

            #[cfg(feature = "trace")]
            {
                println!(
                    "verifier-mul      : Mul({}, {}, {}) ; recon = {:?}",
                    wire_nrs.0, wire_nrs.1, wire_nrs.2, recon,
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
                println!(
                    "verifier-add   : Add({:?}, {:?}, {:?}) ; a_w = {:?}, b_w = {:?}",
                    dst, src1, src2, a_w, b_w,
                );
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
            inputs: (usize, usize, usize, usize),
        ) -> (usize, usize) {
            process_add::<D>(wires, inputs.3, inputs.0, inputs.1);
            process_add::<D>(wires, inputs.3 + 1, inputs.2, inputs.3);
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                (inputs.3 + 2, inputs.2, inputs.3),
            );
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                (inputs.3 + 3, inputs.0, inputs.1),
            );
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                (inputs.3 + 4, inputs.3 + 2, inputs.3 + 3),
            );
            process_add::<D>(wires, inputs.3 + 5, inputs.3 + 2, inputs.3 + 3);
            process_add::<D>(wires, inputs.3 + 6, inputs.3 + 4, inputs.3 + 5);

            (inputs.3 + 1, inputs.3 + 6)
        }

        fn first_adder<D: Domain>(
            wires: &mut VecMap<D::Scalar>,
            transcript: &mut RingHasher<D::Sharing>,
            masks: &mut Cloned<Iter<D::Sharing>>,
            ab_gamma: &mut Cloned<Iter<D::Sharing>>,
            broadcast: &mut ShareIterator<D, Cloned<Iter<D::Batch>>>,
            inputs: (usize, usize, usize),
        ) -> (usize, usize) {
            process_add::<D>(wires, inputs.2, inputs.0, inputs.1);
            process_mul(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                (inputs.2 + 1, inputs.0, inputs.1),
            );

            (inputs.2, inputs.2 + 1)
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
            inputs: (Vec<usize>, Vec<usize>, usize),
        ) -> (Vec<usize>, usize) {
            assert_eq!(inputs.0.len(), inputs.1.len());
            assert!(!inputs.0.is_empty());
            let mut output_bits = Vec::new();
            let mut start_new_wires_mut = inputs.2;

            let (mut output_bit, mut carry_out) = first_adder(
                wires,
                transcript,
                masks,
                ab_gamma,
                broadcast,
                (inputs.0[0], inputs.1[0], start_new_wires_mut),
            );
            output_bits.push(output_bit);
            for i in 1..inputs.0.len() {
                start_new_wires_mut = carry_out + 1;
                let (output_bit1, carry_out1) = adder(
                    wires,
                    transcript,
                    masks,
                    ab_gamma,
                    broadcast,
                    (inputs.0[i], inputs.1[i], carry_out, start_new_wires_mut),
                );
                output_bit = output_bit1;
                carry_out = carry_out1;
                output_bits.push(output_bit);
            }

            (output_bits, carry_out + 1)
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for run in runs.iter().cloned() {
            let (sender_inputs, reader_inputs) = async_channel::bounded(5);
            let (sender_outputs, reader_outputs) = async_channel::bounded(5);
            tasks.push(task::spawn(process::<D>(
                run,
                sender_outputs,
                reader_inputs,
                fieldswitching_io.clone(),
                challenge,
            )));
            inputs.push(sender_inputs);
            outputs.push(reader_outputs);
        }

        let collection_task = task::spawn(collect_transcript_hashes::<D>(tasks));

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
        let (oracle_feed, omitted, pp_hashes, result) = collection_task.await?;

        // return output to verify against pre-processing
        Ok((oracle_feed, omitted, Output { pp_hashes, result }))
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
