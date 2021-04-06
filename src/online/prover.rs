use super::*;

use crate::algebra::Packable;
use crate::algebra::{Domain, LocalOperation, RingModule, Sharing};
use crate::consts::*;
use crate::crypto::{Hash, TreePrf};
use crate::oracle::RandomOracle;
use crate::preprocessing::prover::PreprocessingExecution;
use crate::preprocessing::PreprocessingOutput;
use crate::util::*;
use crate::Instructions;

use std::sync::Arc;

use crate::fieldswitching::util::{Eda, FieldSwitchingIo};
use async_channel::{Receiver, SendError, Sender};
use async_std::task;
use std::iter::Cloned;
use std::slice::Iter;

/// A type alias for a tuple of a program slice and its witness slice.
type ProgWitSlice<D> = (Arc<Instructions<D>>, Arc<Vec<<D as Domain>::Scalar>>);
type PreprocessedValues<'a, D> = (
    &'a [<D as Domain>::Sharing],
    &'a [<D as Domain>::Sharing],
    &'a [Vec<<D as Domain>::Sharing>],
    &'a [<D as Domain>::Sharing],
);
type ProgramWitnessNrOfWires<'a, D> = (
    &'a [Instruction<<D as Domain>::Scalar>],
    &'a [<D as Domain>::Scalar],
    usize,
);

const DEFAULT_CAPACITY: usize = BATCH_SIZE;

pub struct StreamingProver<D: Domain> {
    pub(crate) branch: Arc<Vec<D::Scalar>>,
    pub(crate) preprocessing: PreprocessingOutput<D>,
    pub(crate) omitted: Vec<usize>,
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
        program_witness: ProgramWitnessNrOfWires<D>,
        preprocessing: PreprocessedValues<D>,
        masked_witness: &mut WW,
        broadcast: &mut BW,
        fieldswitching_io: FieldSwitchingIo,
        challenge: Option<(usize, D::Scalar)>,
        mut output: (&mut Vec<D::Scalar>, &mut Vec<usize>),
    ) -> usize {
        // println!("prover eda_bits: {:?}", preprocessing_eda_bits);
        // println!("prover eda_composed: {:?}", preprocessing_eda_composed);
        let mut witness = program_witness.1.iter().cloned();
        let mut ab_gamma = preprocessing.1.iter().cloned();
        let mut masks = preprocessing.0.iter().cloned();
        let mut eda_bits = Vec::<Cloned<Iter<D::Sharing>>>::new();
        let fieldswitching_input = fieldswitching_io.0;
        let fieldswitching_output = fieldswitching_io.1;
        for eda_bit in preprocessing.2 {
            eda_bits.push(eda_bit.iter().cloned());
        }
        let mut eda_composed = preprocessing.3.iter().cloned();

        let mut nr_of_wires = program_witness.2;
        let mut fieldswitching_output_done = Vec::new();

        for step in program_witness.0 {
            match *step {
                Instruction::NrOfWires(nr) => {
                    nr_of_wires = nr;
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
                    nr_of_wires = self.process_input(
                        masked_witness,
                        fieldswitching_input.clone(),
                        &mut eda_composed,
                        witness.next().unwrap(),
                        &mut masks,
                        (nr_of_wires, dst),
                    );
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
                        assert_eq!(self.wires.get(dst) - mask.reconstruct(), value);
                        #[cfg(feature = "trace")]
                        println!("  mask = {:?}, value = {:?}", mask, value);
                        self.plain.set(dst, Some(value));
                    }
                }
                Instruction::Const(dst, c) => {
                    assert_ne!(nr_of_wires, 0);
                    if let Some(cha) = challenge {
                        if cha.0 == dst {
                            self.process_const(&mut masks, dst, cha.1);
                        } else {
                            self.process_const(&mut masks, dst, c);
                        }
                    } else {
                        self.process_const(&mut masks, dst, c);
                    }
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
                            assert_eq!(correct, self.wires.get(dst) - mask.reconstruct());
                        }
                    }
                }
                Instruction::Add(dst, src1, src2) => {
                    assert_ne!(nr_of_wires, 0);
                    self.process_add(&mut masks, dst, src1, src2);
                }
                Instruction::Sub(dst, src1, src2) => {
                    assert_ne!(nr_of_wires, 0);
                    self.process_sub(&mut masks, dst, src1, src2);
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
                        fieldswitching_output_done.push(src);
                        let mut contains_all = true;
                        for item in out_list.clone() {
                            if !fieldswitching_output_done.contains(&item) {
                                contains_all = false;
                            }
                        }
                        if contains_all {
                            let mut zeroes = Vec::new();
                            for eda_bit in eda_bits.iter_mut() {
                                let added = eda_bit.next().unwrap().reconstruct();
                                zeroes.push(nr_of_wires);
                                nr_of_wires = self.process_input(
                                    masked_witness,
                                    fieldswitching_input.clone(),
                                    &mut eda_composed,
                                    added,
                                    &mut masks,
                                    (nr_of_wires, nr_of_wires),
                                );
                                nr_of_wires += 1;
                            }
                            let (outputs, carry_out) = self.full_adder(
                                broadcast,
                                &mut ab_gamma,
                                &mut masks,
                                out_list.clone(),
                                zeroes,
                                nr_of_wires,
                            );
                            nr_of_wires = carry_out;
                            for (outs, original) in outputs.iter().cloned().zip(out_list.clone()) {
                                self.process_output(
                                    broadcast,
                                    &mut masks,
                                    &mut output,
                                    outs,
                                    original,
                                );
                            }
                        }
                    } else {
                        self.process_output(broadcast, &mut masks, &mut output, src, src);
                    }
                }
            }
        }
        debug_assert!(witness.next().is_none());
        debug_assert!(masks.next().is_none());

        nr_of_wires
    }

    fn process_input<WW: Writer<D::Scalar>>(
        &mut self,
        masked_witness: &mut WW,
        fieldswitching_input: Vec<usize>,
        eda_composed: &mut Cloned<Iter<D::Sharing>>,
        value: D::Scalar,
        masks: &mut Cloned<Iter<D::Sharing>>,
        mut wire_nrs: (usize, usize),
    ) -> usize {
        let mut new_dst = wire_nrs.1;
        if fieldswitching_input.contains(&wire_nrs.1) {
            new_dst = wire_nrs.0;
        }

        let mask: D::Sharing = masks.next().unwrap();
        let wire = value + mask.reconstruct();
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
            #[cfg(feature = "trace")]
            println!(
                "wire={:?},  mask = {:?}, value = {:?}",
                self.wires.get(new_dst),
                mask.reconstruct(),
                value
            );
            assert_eq!(self.wires.get(new_dst) - mask.reconstruct(), value);
            self.plain.set(new_dst, Some(value));
        }

        if fieldswitching_input.contains(&wire_nrs.1) {
            let min_one = D::Scalar::ZERO - D::Scalar::ONE;
            let added: D::Scalar = eda_composed.next().unwrap().reconstruct() * min_one;
            wire_nrs.0 += 1;
            wire_nrs.0 = self.process_input(
                masked_witness,
                fieldswitching_input,
                eda_composed,
                added,
                masks,
                (wire_nrs.0, wire_nrs.0),
            );
            self.process_add(masks, wire_nrs.1, new_dst, wire_nrs.0);
            wire_nrs.0 += 1;
        }
        wire_nrs.0
    }

    fn process_add(
        &mut self,
        _masks: &mut Cloned<Iter<<D as Domain>::Sharing>>,
        dst: usize,
        src1: usize,
        src2: usize,
    ) {
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
                let mask = _masks.next().unwrap();
                #[cfg(feature = "trace")]
                println!("  mask = {:?}, value = {:?}", mask, correct);
                assert_eq!(correct, self.wires.get(dst) - mask.reconstruct());
            }
        }
    }

    fn process_sub(
        &mut self,
        _masks: &mut Cloned<Iter<<D as Domain>::Sharing>>,
        dst: usize,
        src1: usize,
        src2: usize,
    ) {
        let a_w = self.wires.get(src1);
        let b_w = self.wires.get(src2);
        self.wires.set(dst, a_w - b_w);

        #[cfg(feature = "trace")]
        {
            println!(
                "prover-sub      : Sub({}, {}, {}) ; wire = {:?}",
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
            let correct = self.plain.get(src1).unwrap() - self.plain.get(src2).unwrap();
            self.plain.set(dst, Some(correct));

            // reconstruct masked wire and check computation
            #[cfg(feature = "debug_eval")]
            {
                let mask = _masks.next().unwrap();
                #[cfg(feature = "trace")]
                println!("  mask = {:?}, value = {:?}", mask, correct);
                assert_eq!(correct, self.wires.get(dst) - mask.reconstruct());
            }
        }
    }

    fn process_mul<BW: Writer<D::Sharing>>(
        &mut self,
        broadcast: &mut BW,
        ab_gamma: &mut Cloned<Iter<<D as Domain>::Sharing>>,
        masks: &mut Cloned<Iter<<D as Domain>::Sharing>>,
        dst: usize,
        src1: usize,
        src2: usize,
    ) {
        // calculate reconstruction shares for every player
        let a_w = self.wires.get(src1);
        let b_w = self.wires.get(src2);
        let a_m: D::Sharing = masks.next().unwrap();
        let b_m: D::Sharing = masks.next().unwrap();
        let ab_gamma: D::Sharing = ab_gamma.next().unwrap();
        let recon = a_m.action(b_w) + b_m.action(a_w) - ab_gamma;

        // reconstruct
        // println!("broadcast prover: {:?}", recon);
        broadcast.write(recon);

        // corrected wire
        let min_one = D::Scalar::ZERO - D::Scalar::ONE;
        let c_w = min_one * (recon.reconstruct() - a_w * b_w);

        // reconstruct and correct share
        self.wires.set(dst, c_w);

        #[cfg(feature = "trace")]
        {
            println!(
                "prover-mul      : Mul({}, {}, {}) ; wire = {:?}, recon: {:?}",
                dst,
                src1,
                src2,
                self.wires.get(dst),
                recon,
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
                assert_eq!(correct, self.wires.get(dst) - mask.reconstruct());
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

    fn process_output<BW: Writer<D::Sharing>>(
        &mut self,
        broadcast: &mut BW,
        masks: &mut Cloned<Iter<D::Sharing>>,
        output: &mut (&mut Vec<D::Scalar>, &mut Vec<usize>),
        src: usize,
        original_src: usize,
    ) {
        let recon: D::Sharing = masks.next().unwrap();
        // println!("broadcast prover: {:?}", recon);
        broadcast.write(recon);
        output.0.write(self.wires.get(src) - recon.reconstruct());
        output.1.write(original_src);

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
                self.wires.get(src) - recon.reconstruct(),
                value,
                "wire-index: {}, wire-value: {:?} recon: {:?}, value: {:?}",
                src,
                self.wires.get(src),
                recon,
                value
            );
        }
    }

    fn process_add_const(
        &mut self,
        _masks: &mut Cloned<Iter<D::Sharing>>,
        dst: usize,
        src: usize,
        c: D::Scalar,
    ) {
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
                let mask = _masks.next().unwrap();
                #[cfg(feature = "trace")]
                println!("  mask = {:?}, value = {:?}", mask, correct);
                assert_eq!(correct, self.wires.get(dst) - mask.reconstruct());
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
    fn adder<BW: Writer<D::Sharing>>(
        &mut self,
        broadcast: &mut BW,
        ab_gamma: &mut Cloned<Iter<D::Sharing>>,
        masks: &mut Cloned<Iter<D::Sharing>>,
        inputs: (usize, usize, usize, usize),
    ) -> (usize, usize) {
        self.process_add(masks, inputs.3, inputs.0, inputs.1);
        self.process_add(masks, inputs.3 + 1, inputs.2, inputs.3);
        self.process_mul(broadcast, ab_gamma, masks, inputs.3 + 2, inputs.2, inputs.3);
        self.process_mul(broadcast, ab_gamma, masks, inputs.3 + 3, inputs.0, inputs.1);
        self.process_mul(
            broadcast,
            ab_gamma,
            masks,
            inputs.3 + 4,
            inputs.3 + 2,
            inputs.3 + 3,
        );
        self.process_add(masks, inputs.3 + 5, inputs.3 + 2, inputs.3 + 3);
        self.process_add(masks, inputs.3 + 6, inputs.3 + 4, inputs.3 + 5);

        (inputs.3 + 1, inputs.3 + 6)
    }

    fn first_adder<BW: Writer<D::Sharing>>(
        &mut self,
        broadcast: &mut BW,
        ab_gamma: &mut Cloned<Iter<D::Sharing>>,
        masks: &mut Cloned<Iter<D::Sharing>>,
        input1: usize,
        input2: usize,
        start_new_wires: usize,
    ) -> (usize, usize) {
        self.process_add(masks, start_new_wires, input1, input2);
        self.process_mul(
            broadcast,
            ab_gamma,
            masks,
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
    fn full_adder<BW: Writer<D::Sharing>>(
        &mut self,
        broadcast: &mut BW,
        ab_gamma: &mut Cloned<Iter<D::Sharing>>,
        masks: &mut Cloned<Iter<D::Sharing>>,
        start_input1: Vec<usize>,
        start_input2: Vec<usize>,
        start_new_wires: usize,
    ) -> (Vec<usize>, usize) {
        assert_eq!(start_input1.len(), start_input2.len());
        assert!(!start_input1.is_empty());
        let mut output_bits = Vec::new();
        let mut start_new_wires_mut = start_new_wires;

        let (output_bit, mut carry_out) = self.first_adder(
            broadcast,
            ab_gamma,
            masks,
            start_input1[0],
            start_input2[0],
            start_new_wires_mut,
        );
        output_bits.push(output_bit);
        for i in 1..start_input1.len() {
            start_new_wires_mut = carry_out + 1;
            let (output_bit, carry_out1) = self.adder(
                broadcast,
                ab_gamma,
                masks,
                (
                    start_input1[i],
                    start_input2[i],
                    carry_out,
                    start_new_wires_mut,
                ),
            );
            carry_out = carry_out1;
            output_bits.push(output_bit);
        }

        (output_bits, carry_out + 1)
    }
}

impl<D: Domain> StreamingProver<D> {
    /// Creates a new proof of program execution on the input provided.
    ///
    /// It is crucial for zero-knowledge that the pre-processing output is not reused!
    /// To help ensure this Proof::new takes ownership of PreprocessedProverOutput,
    /// which prevents the programmer from accidentally re-using the output
    pub async fn new(
        bind: Option<Vec<u8>>, // included Fiat-Shamir transform (for signatures of knowledge)
        preprocessing: PreprocessingOutput<D>, // output of preprocessing
        branch_index: usize,   // branch index (from preprocessing)
        program: Arc<Vec<Instruction<D::Scalar>>>,
        witness: Arc<Vec<D::Scalar>>,
        fieldswitching_io: FieldSwitchingIo,
        eda: Eda<D>,
    ) -> (Proof<D>, Self) {
        assert_eq!(preprocessing.hidden.len(), D::ONLINE_REPETITIONS);
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind.as_ref().map(|x| &x[..]));
        let (branch, masked_branches, _output, oracle_inputs) = <StreamingProver<D>>::new_round_1(
            preprocessing.clone(),
            branch_index,
            program,
            witness,
            fieldswitching_io,
            eda,
        )
        .await;

        for oracle_feed in oracle_inputs {
            oracle.feed(&oracle_feed)
        }

        let omitted = <StreamingProver<D>>::get_challenge(&mut oracle);

        <StreamingProver<D>>::new_round_3(preprocessing, Arc::new(branch), masked_branches, omitted)
    }

    pub async fn new_round_1(
        preprocessing: PreprocessingOutput<D>,
        branch_index: usize,
        mut program: Arc<Vec<Instruction<D::Scalar>>>,
        mut witness: Arc<Vec<D::Scalar>>,
        fieldswitching_io: FieldSwitchingIo,
        eda: Eda<D>,
    ) -> (
        Vec<<D as Domain>::Scalar>,
        Vec<(Vec<u8>, MerkleSetProof)>,
        (Vec<D::Scalar>, Vec<usize>),
        Vec<[u8; 32]>,
    ) {
        let runs = preprocessing.hidden.clone();
        <StreamingProver<D>>::do_runs_round_1(
            preprocessing,
            branch_index,
            &mut program,
            &mut witness,
            fieldswitching_io,
            eda,
            runs,
            None,
        )
        .await
    }

    pub(crate) async fn do_runs_round_1(
        preprocessing: PreprocessingOutput<D>,
        branch_index: usize,
        program: &mut Arc<Vec<Instruction<D::Scalar>>>,
        witness: &mut Arc<Vec<D::Scalar>>,
        fieldswitching_io: FieldSwitchingIo,
        eda: Eda<D>,
        runs: Vec<preprocessing::PreprocessingRun>,
        challenge: Option<(usize, D::Scalar)>,
    ) -> (
        Vec<D::Scalar>,
        Vec<(Vec<u8>, MerkleSetProof)>,
        (Vec<D::Scalar>, Vec<usize>),
        Vec<[u8; 32]>,
    ) {
        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            branches: Arc<Vec<Vec<D::Batch>>>,
            branch_index: usize,
            branch: Arc<Vec<D::Scalar>>,
            io: (Sender<()>, Receiver<ProgWitSlice<D>>),
            fieldswitching_io: FieldSwitchingIo,
            eda: Eda<D>,
            challenge: Option<(usize, D::Scalar)>,
        ) -> Result<(Vec<u8>, MerkleSetProof, Hash, (Vec<D::Scalar>, Vec<usize>)), SendError<Vec<u8>>>
        {
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
            let mut out_wires = Vec::new();
            let mut nr_of_wires = 0;

            loop {
                match io.1.recv().await {
                    Ok((program, witness)) => {
                        // execute the next slice of program
                        {
                            // reset preprocessing output buffers
                            masks.clear();
                            ab_gamma.clear();

                            // prepare pre-processing execution (online mode)
                            preprocessing.process(
                                (&program[..], nr_of_wires),
                                &mut VoidWriter::new(),
                                &mut masks,
                                &mut ab_gamma,
                                fieldswitching_io.0.clone(),
                                fieldswitching_io.1.clone(),
                            );
                            // println!("prover masks: {:?}", masks);

                            // compute public transcript
                            nr_of_wires = online.run(
                                (&program[..], &witness[..], nr_of_wires),
                                (&masks[..], &ab_gamma[..], &eda.0[..], &eda.1[..]),
                                &mut VoidWriter::new(),
                                &mut transcript,
                                fieldswitching_io.clone(),
                                challenge,
                                (&mut output, &mut out_wires),
                            );
                        }

                        // needed for synchronization
                        io.0.send(()).await.unwrap();
                    }
                    Err(_) => {
                        let mut packed: Vec<u8> = Vec::with_capacity(256);
                        let (branch, proof) = preprocessing.prove_branch(&*branches, branch_index);
                        Packable::pack(&mut packed, branch.iter()).unwrap();
                        return Ok((packed, proof, transcript.finalize(), (output, out_wires)));
                    }
                }
            }
        }

        type TaskHandle<T> = task::JoinHandle<
            Result<
                (
                    Vec<u8>,
                    MerkleSetProof,
                    Hash,
                    (Vec<<T as Domain>::Scalar>, Vec<usize>),
                ),
                SendError<Vec<u8>>,
            >,
        >;
        async fn extract_output<D: Domain>(
            runs: Vec<preprocessing::PreprocessingRun>,
            tasks: Vec<TaskHandle<D>>,
        ) -> (
            Vec<(Vec<u8>, MerkleSetProof)>,
            (Vec<D::Scalar>, Vec<usize>),
            Vec<[u8; 32]>,
        ) {
            // extract which players to omit in every run (Fiat-Shamir)
            let mut masked_branches = Vec::with_capacity(D::ONLINE_REPETITIONS);
            let mut output = (Vec::new(), Vec::new());

            let mut oracle_input = Vec::new();
            for (pp, t) in runs.iter().zip(tasks.into_iter()) {
                let (masked, proof, transcript, _output) = t.await.unwrap();
                output = _output;
                masked_branches.push((masked, proof));

                // RO((preprocessing, transcript))
                // println!("transcript feed: {:?}", transcript);
                oracle_input.push(*pp.union.as_bytes());
                oracle_input.push(*transcript.as_bytes());
            }
            (masked_branches, output, oracle_input)
        }

        // unpack selected branch into scalars again
        let branch_batches = &preprocessing.branches[branch_index][..];
        let mut _branch = Vec::with_capacity(branch_batches.len() * D::Batch::DIMENSION);
        for batch in branch_batches.iter() {
            for j in 0..D::Batch::DIMENSION {
                _branch.push(batch.get(j))
            }
        }
        let branch = Arc::new(_branch.clone());

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs: Vec<Sender<ProgWitSlice<D>>> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for run in runs.iter() {
            let (send_inputs, recv_inputs) = async_channel::bounded(2);
            let (send_outputs, recv_outputs) = async_channel::bounded(2);
            tasks.push(task::spawn(process::<D>(
                run.seed,
                preprocessing.branches.clone(),
                branch_index,
                branch.clone(),
                (send_outputs, recv_inputs),
                fieldswitching_io.clone(),
                eda.clone(),
                challenge,
            )));
            inputs.push(send_inputs);
            outputs.push(recv_outputs);
        }

        let extraction_task = task::spawn(extract_output::<D>(runs, tasks));

        let chunk_size = chunk_size(program.len(), inputs.len());

        while !inputs.is_empty() {
            for sender in inputs.drain(..chunk_size) {
                sender
                    .send((program.clone(), witness.clone()))
                    .await
                    .unwrap();
            }
            for rx in outputs.drain(..chunk_size) {
                let _ = rx.recv().await;
            }
        }

        // close input writers
        inputs.clear();

        let (masked_branches, output, oracle_input) = extraction_task.await;
        (_branch.clone(), masked_branches, output, oracle_input)
    }

    pub fn get_challenge(oracle: &mut RandomOracle) -> Vec<usize> {
        let omitted: Vec<usize> = random_vector(
            &mut oracle.clone().query(),
            D::PLAYERS,
            D::ONLINE_REPETITIONS,
        );

        debug_assert_eq!(omitted.len(), D::ONLINE_REPETITIONS);
        omitted
    }

    pub fn new_round_3(
        preprocessing: PreprocessingOutput<D>,
        branch: Arc<Vec<<D as Domain>::Scalar>>,
        masked_branches: Vec<(Vec<u8>, MerkleSetProof)>,
        omitted: Vec<usize>,
    ) -> (Proof<D>, StreamingProver<D>) {
        (
            Proof {
                // omit player from TreePrf and provide pre-processing commitment
                runs: omitted
                    .iter()
                    .cloned()
                    .zip(preprocessing.hidden.iter())
                    .zip(masked_branches.into_iter())
                    .map(|((omit, run), (branch, proof))| {
                        let tree = TreePrf::new(D::PLAYERS, run.seed);
                        OnlineRun {
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
                preprocessing,
                omitted,
            },
        )
    }

    pub async fn stream(
        self,
        dst: Sender<Vec<u8>>,
        program: Arc<Vec<Instruction<D::Scalar>>>,
        witness: Arc<Vec<D::Scalar>>,
        fieldswitching_io: FieldSwitchingIo,
        eda_bits: Vec<Vec<Vec<D::Sharing>>>,
        eda_composed: Vec<Vec<D::Sharing>>,
    ) -> Result<(), SendError<Vec<u8>>> {
        async fn process<D: Domain>(
            root: [u8; KEY_SIZE],
            omitted: usize,
            branch: Arc<Vec<D::Scalar>>,
            outputs: Sender<Vec<u8>>,
            inputs: Receiver<ProgWitSlice<D>>,
            fieldswitching_io: FieldSwitchingIo,
            eda: Eda<D>,
        ) -> Result<(), SendError<Vec<u8>>> {
            let mut seeds = vec![[0u8; KEY_SIZE]; D::PLAYERS];
            TreePrf::expand_full(&mut seeds, root);

            let mut online = Prover::<D, _>::new(branch.iter().cloned());
            let mut preprocessing = PreprocessingExecution::<D>::new(root);

            // output buffers used during execution
            let mut masks = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut ab_gamma = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut corrections = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut broadcast = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut masked: Vec<D::Scalar> = Vec::with_capacity(DEFAULT_CAPACITY);
            // let mut output = (&mut Vec::new(), &mut Vec::new());

            // packed elements to be serialized
            let mut chunk = Chunk {
                witness: Vec::with_capacity(BATCH_SIZE),
                broadcast: Vec::with_capacity(BATCH_SIZE),
                corrections: Vec::with_capacity(BATCH_SIZE),
            };
            let mut nr_of_wires = 0;

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
                                (&program[..], nr_of_wires),
                                &mut SwitchWriter::new(&mut corrections, omitted != 0),
                                &mut masks,
                                &mut ab_gamma,
                                fieldswitching_io.0.clone(),
                                fieldswitching_io.1.clone(),
                            );

                            // compute public transcript
                            nr_of_wires = online.run(
                                (&program[..], &witness[..], nr_of_wires),
                                (&masks[..], &ab_gamma[..], &eda.0[..], &eda.1[..]),
                                &mut masked,
                                &mut BatchExtractor::<D, _>::new(omitted, &mut broadcast),
                                fieldswitching_io.clone(),
                                None,
                                (&mut Vec::new(), &mut Vec::new()),
                            );
                        }

                        // serialize the chunk

                        chunk.witness.clear();
                        chunk.broadcast.clear();
                        chunk.corrections.clear();
                        // println!("masked witness prover: {:?}", masked);

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

        async fn wait_for_all(tasks: Vec<task::JoinHandle<Result<(), SendError<Vec<u8>>>>>) {
            for t in tasks {
                t.await.unwrap();
            }
        }

        // create async parallel task for every repetition
        let mut tasks = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut inputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut outputs = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for (i, (run, omit)) in self
            .preprocessing
            .hidden
            .iter()
            .zip(self.omitted.iter().cloned())
            .enumerate()
        {
            let (sender_inputs, reader_inputs) = async_channel::bounded(3);
            let (sender_outputs, reader_outputs) = async_channel::bounded(3);
            let _eda_bits = if eda_bits.is_empty() {
                vec![]
            } else {
                eda_bits[i].clone()
            };
            let _eda_composed = if eda_composed.is_empty() {
                vec![]
            } else {
                eda_composed[i].clone()
            };
            tasks.push(task::spawn(process::<D>(
                run.seed,
                omit,
                self.branch.clone(),
                sender_outputs,
                reader_inputs,
                fieldswitching_io.clone(),
                (_eda_bits, _eda_composed),
            )));
            inputs.push(sender_inputs);
            outputs.push(reader_outputs);
        }

        let tasks_finished = task::spawn(wait_for_all(tasks));

        let chunk_size = chunk_size(program.len(), inputs.len());
        while !inputs.is_empty() {
            for sender in inputs.drain(..chunk_size) {
                sender
                    .send((program.clone(), witness.clone()))
                    .await
                    .unwrap();
            }
            for rx in outputs.drain(..chunk_size) {
                let output = rx.recv().await;
                dst.send(output.unwrap()).await?; // can fail
            }
        }

        // wait for tasks to finish
        tasks_finished.await;
        Ok(())
    }
}
