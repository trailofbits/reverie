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
use std::iter::Cloned;
use std::slice::Iter;

/// A type alias for a tuple of a program slice and its witness slice.
type ProgWitSlice<D> = (Arc<Instructions<D>>, Arc<Vec<<D as Domain>::Scalar>>);

const DEFAULT_CAPACITY: usize = BATCH_SIZE;

async fn feed<
    D: Domain,
    PI: Iterator<Item=Instruction<D::Scalar>>,
    WI: Iterator<Item=D::Scalar>,
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

struct Prover<D: Domain, I: Iterator<Item=D::Scalar>> {
    #[cfg(test)]
    #[cfg(debug_assertions)]
    plain: VecMap<Option<D::Scalar>>,
    wires: VecMap<D::Scalar>,
    branch: I,
}

impl<D: Domain, I: Iterator<Item=D::Scalar>> Prover<D, I> {
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
        fieldswitching_input: Vec<usize>,
        fieldswitching_output: Vec<Vec<usize>>,
        output: &mut Vec<D::Scalar>,
    ) {
        let mut witness = witness.iter().cloned();
        let mut ab_gamma = preprocessing_ab_gamma.iter().cloned();
        let mut masks = preprocessing_masks.iter().cloned();
        let mut nr_of_wires = 0;
        let mut fieldswitching_output_done = Vec::new();

        for step in program {
            match *step {
                Instruction::NrOfWires(nr) => {
                    nr_of_wires = nr.clone();
                }
                Instruction::LocalOp(dst, src) => {
                    assert_ne!(nr_of_wires, 0);
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
                    assert_ne!(nr_of_wires, 0);

                    let mut new_dst = dst;
                    if fieldswitching_input.contains(&dst) {
                        new_dst = nr_of_wires;
                    }

                    let value: D::Scalar = witness.next().unwrap();
                    let mask: D::Sharing = masks.next().unwrap();
                    let wire = value + D::Sharing::reconstruct(&mask);
                    self.wires.set(new_dst, wire);
                    masked_witness.write(wire);

                    #[cfg(feature = "trace")]
                        {
                            println!(
                                "prover-input    : Input({}) ; wire = {:?}, mask = {:?}, value = {:?}",
                                new_dst, wire, mask, value
                            );
                        }

                    // evaluate the circuit in plain for testing
                    #[cfg(test)]
                        #[cfg(debug_assertions)]
                        {
                            assert_eq!(self.wires.get(new_dst) + mask.reconstruct(), value);
                            #[cfg(feature = "trace")]
                            println!("  mask = {:?}, value = {:?}", mask, value);
                            self.plain.set(new_dst, Some(value));
                        }

                    if fieldswitching_input.contains(&dst) {
                        //TODO(gvl) Subtract constant instead of add
                        self.process_add_const(&mut masks, dst, nr_of_wires, D::Scalar::ZERO);
                        nr_of_wires += 1;
                    }
                }
                Instruction::Branch(dst) => {
                    assert_ne!(nr_of_wires, 0);
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
                Instruction::Const(dst, c) => {
                    assert_ne!(nr_of_wires, 0);
                    self.process_const(&mut masks, dst, c);
                }
                Instruction::AddConst(dst, src, c) => {
                    assert_ne!(nr_of_wires, 0);
                    self.process_add_const(&mut masks, dst, src, c);
                }
                Instruction::MulConst(dst, src, c) => {
                    assert_ne!(nr_of_wires, 0);
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
                    assert_ne!(nr_of_wires, 0);
                    self.process_add(&mut masks, dst, src1, src2);
                }
                Instruction::Mul(dst, src1, src2) => {
                    assert_ne!(nr_of_wires, 0);
                    self.process_mul(broadcast, &mut ab_gamma, &mut masks, dst, src1, src2);
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
                            fieldswitching_output_done.append(&mut out_list.clone());
                            let mut zeroes = Vec::new();
                            for _i in 0..out_list.len() {
                                self.process_const(&mut masks, nr_of_wires, D::Scalar::ZERO);
                                zeroes.push(nr_of_wires);
                                nr_of_wires += 1;
                            }
                            let (outputs, carry_out) = self.full_adder(broadcast, &mut ab_gamma, &mut masks, out_list, zeroes, nr_of_wires);
                            nr_of_wires = carry_out;
                            for outs in outputs {
                                self.process_output(broadcast, &mut masks, output, outs);
                            }
                        }
                    } else {
                        self.process_output(broadcast, &mut masks, output, src);
                    }
                }
            }
        }
        debug_assert!(witness.next().is_none());
        debug_assert!(masks.next().is_none());
    }

    fn process_add(&mut self, masks: &mut Cloned<Iter<<D as Domain>::Sharing>>, dst: usize, src1: usize, src2: usize) {
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

    fn process_mul<BW: Writer<D::Sharing>>(&mut self, broadcast: &mut BW, ab_gamma: &mut Cloned<Iter<<D as Domain>::Sharing>>, masks: &mut Cloned<Iter<<D as Domain>::Sharing>>, dst: usize, src1: usize, src2: usize) {
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

    fn process_const(&mut self, masks: &mut Cloned<Iter<D::Sharing>>, dst: usize, c: D::Scalar) {
        let mask: D::Sharing = masks.next().unwrap();
        let wire = c + D::Sharing::reconstruct(&mask);
        self.wires.set(dst, wire);

        #[cfg(feature = "trace")]
            {
                println!(
                    "prover-const : Const({}, {:?}) ; wire = {:?}",
                    dst,
                    c,
                    self.wires.get(dst),
                );
            }

        // evaluate the circuit in plain for testing
        #[cfg(test)]
            #[cfg(debug_assertions)]
            {
                self.plain.set(dst, Some(c));
            }
    }

    fn process_output<BW: Writer<D::Sharing>>(&mut self, broadcast: &mut BW, masks: &mut Cloned<Iter<D::Sharing>>, output: &mut Vec<D::Scalar>, src: usize) {
        let recon: D::Sharing = masks.next().unwrap();
        broadcast.write(recon);
        output.write(self.wires.get(src) + recon.reconstruct());

        #[cfg(feature = "trace")]
            {
                println!(
                    "prover-output   : Output({}) ; recon = {:?}, wire = {:?}",
                    src,
                    recon,
                    self.wires.get(src),
                );
            }

        // check result correctly reconstructed
        #[cfg(test)]
            #[cfg(debug_assertions)]
            {
                let value: D::Scalar = self.plain.get(src).unwrap();
                assert_eq!(
                    self.wires.get(src) + recon.reconstruct(),
                    value,
                    "wire-index: {}, wire-value: {:?} recon: {:?}",
                    src,
                    self.wires.get(src),
                    recon
                );
            }
    }

    fn process_add_const(&mut self, masks: &mut Cloned<Iter<D::Sharing>>, dst: usize, src: usize, c: D::Scalar) {
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
    fn adder<BW: Writer<D::Sharing>>(&mut self, broadcast: &mut BW, ab_gamma: &mut Cloned<Iter<D::Sharing>>, masks: &mut Cloned<Iter<D::Sharing>>, input1: usize, input2: usize, carry_in: usize, start_new_wires: usize) -> (usize, usize) {
        self.process_add(masks, start_new_wires, input1, input2);
        self.process_add(masks, start_new_wires + 1, carry_in, start_new_wires);
        self.process_mul(broadcast, ab_gamma, masks, start_new_wires + 2, carry_in, start_new_wires);
        self.process_mul(broadcast, ab_gamma, masks, start_new_wires + 3, input1, input2);
        self.process_mul(broadcast, ab_gamma, masks, start_new_wires + 4, start_new_wires + 2, start_new_wires + 3);
        self.process_add(masks, start_new_wires + 5, start_new_wires + 2, start_new_wires + 3);
        self.process_add(masks, start_new_wires + 6, start_new_wires + 4, start_new_wires + 5);

        (start_new_wires + 1, start_new_wires + 6)
    }

    fn first_adder<BW: Writer<D::Sharing>>(&mut self, broadcast: &mut BW, ab_gamma: &mut Cloned<Iter<D::Sharing>>, masks: &mut Cloned<Iter<D::Sharing>>, input1: usize, input2: usize, start_new_wires: usize) -> (usize, usize) {
        self.process_add(masks, start_new_wires, input1, input2);
        self.process_mul(broadcast, ab_gamma, masks, start_new_wires + 1, input1, input2);

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
    fn full_adder<BW: Writer<D::Sharing>>(&mut self, broadcast: &mut BW, ab_gamma: &mut Cloned<Iter<D::Sharing>>, masks: &mut Cloned<Iter<D::Sharing>>, start_input1: Vec<usize>, start_input2: Vec<usize>, start_new_wires: usize) -> (Vec<usize>, usize) {
        assert_eq!(start_input1.len(), start_input2.len());
        assert!(start_input1.len() > 0);
        let mut output_bits = Vec::new();
        let mut start_new_wires_mut = start_new_wires.clone();

        let (mut output_bit, mut carry_out) = self.first_adder(broadcast, ab_gamma, masks, start_input1[0], start_input2[0], start_new_wires);
        output_bits.push(output_bit);
        for i in 1..start_input1.len() {
            start_new_wires_mut += carry_out;
            let (output_bit1, carry_out1) = self.adder(broadcast, ab_gamma, masks, start_input1[i], start_input2[i], carry_out, start_new_wires_mut);
            output_bit = output_bit1;
            carry_out = carry_out1;
            output_bits.push(output_bit);
        }

        (output_bits, carry_out)
    }
}

impl<D: Domain> StreamingProver<D> {
    /// Creates a new proof of program execution on the input provided.
    ///
    /// It is crucial for zero-knowledge that the pre-processing output is not reused!
    /// To help ensure this Proof::new takes ownership of PreprocessedProverOutput,
    /// which prevents the programmer from accidentally re-using the output
    pub async fn new<
        PI: Iterator<Item=Instruction<D::Scalar>>,
        WI: Iterator<Item=D::Scalar>,
    >(
        bind: Option<&[u8]>, // included Fiat-Shamir transform (for signatures of knowledge)
        preprocessing: PreprocessingOutput<D>, // output of preprocessing
        branch_index: usize, // branch index (from preprocessing)
        mut program: PI,
        mut witness: WI,
        fieldswitching_input: Vec<usize>,
        fieldswitching_output: Vec<Vec<usize>>,
    ) -> (Proof<D>, Self) {
        assert_eq!(preprocessing.hidden.len(), D::ONLINE_REPETITIONS);

        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            branches: Arc<Vec<Vec<D::Batch>>>,
            branch_index: usize,
            branch: Arc<Vec<D::Scalar>>,
            outputs: Sender<()>,
            inputs: Receiver<ProgWitSlice<D>>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
        ) -> Result<(Vec<u8>, MerkleSetProof, Hash, Vec<D::Scalar>), SendError<Vec<u8>>> {
            // online execution
            let mut online = Prover::<D, _>::new(branch.iter().cloned());

            // public transcript (broadcast channel)
            let mut transcript = RingHasher::new();

            // preprocessing execution
            let mut preprocessing = PreprocessingExecution::<D>::new(root);

            // vectors for values passed between preprocessing and online execution
            let mut masks = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut output = Vec::new();

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
                                fieldswitching_input.clone(),
                                fieldswitching_output.clone(),
                            );

                            // compute public transcript
                            online.run(
                                &program[..],
                                &witness[..],
                                &masks[..],
                                &ab_gamma[..],
                                &mut VoidWriter::new(),
                                &mut transcript,
                                fieldswitching_input.clone(),
                                fieldswitching_output.clone(),
                                &mut output,
                            );
                        }

                        // needed for synchronization
                        outputs.send(()).await.unwrap();
                    }
                    Err(_) => {
                        let mut packed: Vec<u8> = Vec::with_capacity(256);
                        let (branch, proof) = preprocessing.prove_branch(&*branches, branch_index);
                        Packable::pack(&mut packed, branch.iter()).unwrap();
                        return Ok((packed, proof, transcript.finalize(), output));
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
                fieldswitching_input.clone(),
                fieldswitching_output.clone(),
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
            let (masked, proof, transcript, output) = t.await.unwrap();
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
        PI: Iterator<Item=Instruction<D::Scalar>>,
        WI: Iterator<Item=D::Scalar>,
    >(
        self,
        dst: Sender<Vec<u8>>,
        mut program: PI,
        mut witness: WI,
        fieldswitching_input: Vec<usize>,
        fieldswitching_output: Vec<Vec<usize>>,
    ) -> Result<Vec<D::Scalar>, SendError<Vec<u8>>> {
        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            omitted: usize,
            branch: Arc<Vec<D::Scalar>>,
            outputs: Sender<Vec<u8>>,
            inputs: Receiver<ProgWitSlice<D>>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
        ) -> Result<Vec<D::Scalar>, SendError<Vec<u8>>> {
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
            let mut output = Vec::new();

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
                                fieldswitching_input.clone(),
                                fieldswitching_output.clone(),
                            );

                            // compute public transcript
                            online.run(
                                &program[..],
                                &witness[..],
                                &masks[..],
                                &ab_gamma[..],
                                &mut masked,
                                &mut BatchExtractor::<D, _>::new(omitted, &mut broadcast),
                                fieldswitching_input.clone(),
                                fieldswitching_output.clone(),
                                &mut output,
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
                    Err(_) => return Ok(output),
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
                fieldswitching_input.clone(),
                fieldswitching_output.clone(),
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
        let mut output = Vec::new();
        let mut start = true;
        for t in tasks {
            let new_output = t.await.unwrap();
            if start {
                output = new_output.clone();
                start = false;
            }
            assert_eq!(output, new_output);
            output = new_output;
        }
        Ok(output)
    }
}
