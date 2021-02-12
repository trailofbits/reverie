use super::util::PartialSharesGenerator;

use crate::algebra::{Domain, LocalOperation, RingElement, RingModule, Samplable};
use crate::consts::CONTEXT_RNG_CORRECTION;
use crate::crypto::{hash, kdf, Hash, Hasher, Prg, RingHasher, TreePrf, KEY_SIZE};
use crate::fieldswitching::util::FieldSwitchingIo;
use crate::util::{VecMap, Writer};
use crate::Instruction;
use std::iter::Cloned;
use std::slice::Iter;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain> {
    commitments: Vec<Hash>,
    corrections: RingHasher<D::Batch>,

    // interpreter state
    omitted: usize,
    masks: VecMap<D::Sharing>,

    // sharings
    shares: PartialSharesGenerator<D>,

    // scratch space
    scratch: Vec<D::Batch>,

    // Beaver multiplication state
    corrections_prg: Vec<Prg>,
    share_a: Vec<D::Sharing>,
    // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
}

impl<D: Domain> PreprocessingExecution<D> {
    pub fn omitted(&self) -> usize {
        self.omitted
    }

    pub fn commitment(mut self, branch_root: &Hash, omitted_commitment: &Hash) -> Hash {
        // add corrections to player0
        self.commitments[0] = {
            let mut hash = Hasher::new();
            hash.update(self.commitments[0].as_bytes());
            hash.update(self.corrections.finalize().as_bytes());
            hash.finalize()
        };

        //
        let mut hasher = Hasher::new();
        hasher.update(branch_root.as_bytes());
        for i in 0..D::PLAYERS {
            hasher.update(
                if i == self.omitted {
                    &omitted_commitment
                } else {
                    &self.commitments[i]
                }
                .as_bytes(),
            );
        }
        hasher.finalize()
    }

    pub fn new(tree: &TreePrf) -> Self {
        // expand repetition seed into per-player seeds
        let mut player_seeds: Vec<Option<[u8; KEY_SIZE]>> = vec![None; D::PLAYERS];
        tree.expand(&mut player_seeds);

        // find omitted player
        let mut omitted: usize = 0;
        for (i, seed) in player_seeds.iter().enumerate() {
            if seed.is_none() {
                omitted = i;
            }
        }

        // replace omitted player with dummy key
        let player_seeds: Vec<[u8; KEY_SIZE]> = player_seeds
            .into_iter()
            .map(|seed| seed.unwrap_or([0u8; KEY_SIZE]))
            .collect();

        // commit to per-player randomness
        let commitments: Vec<Hash> = player_seeds.iter().map(|seed| hash(seed)).collect();

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        let corrections_prg = player_seeds
            .iter()
            .map(|seed| Prg::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
            .collect();

        let shares = PartialSharesGenerator::new(&player_seeds[..], omitted);

        PreprocessingExecution {
            omitted,
            corrections: RingHasher::new(),
            commitments,
            corrections_prg,
            shares,
            scratch: vec![D::Batch::ZERO; D::PLAYERS],
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            masks: VecMap::new(),
        }
    }

    #[inline(always)]
    fn generate<I: Iterator<Item = D::Batch>>(
        &mut self,
        ab_gamma: &mut Vec<D::Sharing>,
        corrections: &mut I,
        batch_a: &mut [D::Batch],
        batch_b: &mut [D::Batch],
    ) -> Option<()> {
        debug_assert!(self.shares.beaver.is_empty());
        debug_assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_b.len(), D::Batch::DIMENSION);

        // transpose sharings into per player batches
        D::convert_inv(batch_a, &self.share_a[..]);
        D::convert_inv(batch_b, &self.share_b[..]);
        self.share_a.clear();
        self.share_b.clear();

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..D::PLAYERS {
            if i != self.omitted {
                self.scratch[i] =
                    self.shares.beaver.batches()[i] + D::Batch::gen(&mut self.corrections_prg[i]);
                if i == 0 {
                    let corr = corrections.next()?;
                    self.scratch[i] = self.scratch[i] + corr;
                    self.corrections.update(corr);
                }
            }
        }

        debug_assert_eq!(self.scratch[self.omitted], D::Batch::ZERO);

        // transpose into shares
        let start = ab_gamma.len();
        ab_gamma.resize(start + D::Batch::DIMENSION, D::Sharing::ZERO);
        D::convert(&mut ab_gamma[start..], &self.scratch);
        Some(())
    }

    #[inline(always)]
    pub fn process(
        &mut self,
        program: (&[Instruction<D::Scalar>], usize), // program slice + nr_of_wires
        corrections: &[D::Batch],                    // player 0 corrections
        masks: &mut Vec<D::Sharing>,                 // resulting sharings consumed by online phase
        ab_gamma: &mut Vec<D::Sharing>,              // a * b + \gamma sharings for online phase
        fieldswitching_io: FieldSwitchingIo,
    ) -> Option<()> {
        let fieldswitching_input = fieldswitching_io.0;
        let fieldswitching_output = fieldswitching_io.1;
        let mut corrections = corrections.iter().cloned();

        // invariant: multiplication batch empty at the start
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
        debug_assert!(self.shares.beaver.is_empty());

        // look forward in program until executed enough multiplications for next batch
        let mut batch_a = vec![D::Batch::ZERO; D::PLAYERS];
        let mut batch_b = vec![D::Batch::ZERO; D::PLAYERS];
        let mut nr_of_wires = program.1;
        let mut fieldswitching_output_done = Vec::new();

        for step in program.0 {
            debug_assert_eq!(self.share_a.len(), self.share_b.len());
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            match *step {
                Instruction::NrOfWires(nr) => {
                    nr_of_wires = nr;
                }
                Instruction::LocalOp(dst, src) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.masks.set(dst, self.masks.get(src).operation());
                }
                Instruction::Branch(dst) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    // check if need for new batch of branch masks
                    let mask = self.shares.branch.next();

                    // assign the next unused branch share to the destination wire
                    self.masks.set(dst, mask);
                }
                Instruction::Input(dst) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );

                    let mut new_dst = dst;
                    if fieldswitching_input.contains(&dst) {
                        new_dst = nr_of_wires;
                    }

                    // check if need for new batch of input masks
                    let mask = self.shares.input.next();

                    // assign the next unused input share to the destination wire
                    self.masks.set(new_dst, mask);

                    if fieldswitching_input.contains(&dst) {
                        nr_of_wires += 1;
                        // check if need for new batch of input masks
                        let mask = self.shares.input.next();

                        // assign the next unused input share to the destination wire
                        self.masks.set(nr_of_wires, mask);

                        self.process_add(dst, new_dst, nr_of_wires);
                        nr_of_wires += 1;
                    }
                }
                Instruction::Const(dst, _c) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.masks.set(dst, D::Sharing::ZERO);
                    // We don't need to mask constant inputs because the circuit is public
                }
                Instruction::AddConst(dst, src, _c) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    // noop in pre-processing
                    self.masks.set(dst, self.masks.get(src));
                }
                Instruction::MulConst(dst, src, c) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    // resolve input
                    let sw = self.masks.get(src);

                    // let the single element act on the vector
                    self.masks.set(dst, sw.action(c));
                }
                Instruction::Add(dst, src1, src2) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.process_add(dst, src1, src2);
                }
                Instruction::Mul(dst, src1, src2) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.process_mul(
                        &mut corrections,
                        masks,
                        ab_gamma,
                        &mut batch_a,
                        &mut batch_b,
                        (dst, src1, src2),
                    )?;
                }
                Instruction::Output(src) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );

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
                                // check if need for new batch of input masks
                                let mask = self.shares.input.next();

                                // assign the next unused input share to the destination wire
                                self.masks.set(nr_of_wires, mask);
                                zeroes.push(nr_of_wires);
                                nr_of_wires += 1;
                            }
                            let (outputs, carry_out) = self.full_adder(
                                &mut corrections,
                                masks,
                                ab_gamma,
                                &mut batch_a,
                                &mut batch_b,
                                (out_list, zeroes, nr_of_wires),
                            );
                            nr_of_wires = carry_out;
                            for outs in outputs {
                                masks.write(self.masks.get(outs));
                            }
                        }
                    } else {
                        masks.write(self.masks.get(src));
                    }
                }
            }
        }

        // pad final multiplication batch if needed
        if !self.share_a.is_empty() {
            self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.shares.beaver.empty();
            self.generate(ab_gamma, &mut corrections, &mut batch_a, &mut batch_b)
        } else {
            Some(())
        }
    }

    fn process_add(&mut self, dst: usize, src1: usize, src2: usize) {
        self.masks
            .set(dst, self.masks.get(src1) + self.masks.get(src2));
    }

    fn process_mul(
        &mut self,
        mut corrections: &mut Cloned<Iter<<D as Domain>::Batch>>,
        masks: &mut Vec<<D as Domain>::Sharing>,
        ab_gamma: &mut Vec<<D as Domain>::Sharing>,
        mut batch_a: &mut Vec<D::Batch>,
        mut batch_b: &mut Vec<D::Batch>,
        wire_nrs: (usize, usize, usize),
    ) -> Option<()> {
        // push the input masks to the stack
        let mask_a = self.masks.get(wire_nrs.1);
        let mask_b = self.masks.get(wire_nrs.2);
        self.share_a.push(mask_a);
        self.share_b.push(mask_b);

        // assign mask to output
        // (NOTE: can be done before the correction bits are computed, allowing batching regardless of circuit topology)
        self.masks.set(wire_nrs.0, self.shares.beaver.next());

        // return the mask to online phase for Beaver multiplication
        masks.write(mask_a);
        masks.write(mask_b);

        // if the batch is full, generate next batch of ab_gamma shares
        if self.share_a.len() == D::Batch::DIMENSION {
            self.generate(ab_gamma, &mut corrections, &mut batch_a, &mut batch_b)
        } else {
            Some(())
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
    fn adder(
        &mut self,
        corrections: &mut Cloned<Iter<<D as Domain>::Batch>>,
        masks: &mut Vec<<D as Domain>::Sharing>,
        ab_gamma: &mut Vec<<D as Domain>::Sharing>,
        batch_a: &mut Vec<D::Batch>,
        batch_b: &mut Vec<D::Batch>,
        inputs: (usize, usize, usize, usize),
    ) -> (usize, usize) {
        self.process_add(inputs.3, inputs.0, inputs.1);
        self.process_add(inputs.3 + 1, inputs.2, inputs.3);
        self.process_mul(
            corrections,
            masks,
            ab_gamma,
            batch_a,
            batch_b,
            (inputs.3 + 2, inputs.2, inputs.3),
        );
        self.process_mul(
            corrections,
            masks,
            ab_gamma,
            batch_a,
            batch_b,
            (inputs.3 + 3, inputs.0, inputs.1),
        );
        self.process_mul(
            corrections,
            masks,
            ab_gamma,
            batch_a,
            batch_b,
            (inputs.3 + 4, inputs.3 + 2, inputs.3 + 3),
        );
        self.process_add(inputs.3 + 5, inputs.3 + 2, inputs.3 + 3);
        self.process_add(inputs.3 + 6, inputs.3 + 4, inputs.3 + 5);

        (inputs.3 + 1, inputs.3 + 6)
    }

    fn first_adder(
        &mut self,
        corrections: &mut Cloned<Iter<<D as Domain>::Batch>>,
        masks: &mut Vec<<D as Domain>::Sharing>,
        ab_gamma: &mut Vec<<D as Domain>::Sharing>,
        batch_a: &mut Vec<D::Batch>,
        batch_b: &mut Vec<D::Batch>,
        inputs: (usize, usize, usize),
    ) -> (usize, usize) {
        self.process_add(inputs.2, inputs.0, inputs.1);
        self.process_mul(
            corrections,
            masks,
            ab_gamma,
            batch_a,
            batch_b,
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
    fn full_adder(
        &mut self,
        corrections: &mut Cloned<Iter<<D as Domain>::Batch>>,
        masks: &mut Vec<<D as Domain>::Sharing>,
        ab_gamma: &mut Vec<<D as Domain>::Sharing>,
        batch_a: &mut Vec<D::Batch>,
        batch_b: &mut Vec<D::Batch>,
        inputs: (Vec<usize>, Vec<usize>, usize),
    ) -> (Vec<usize>, usize) {
        assert_eq!(inputs.0.len(), inputs.1.len());
        assert!(!inputs.0.is_empty());
        let mut output_bits = Vec::new();
        let mut start_new_wires_mut = inputs.2;

        let (mut output_bit, mut carry_out) = self.first_adder(
            corrections,
            masks,
            ab_gamma,
            batch_a,
            batch_b,
            (inputs.0[0], inputs.1[0], start_new_wires_mut),
        );
        output_bits.push(output_bit);
        for i in 1..inputs.0.len() {
            start_new_wires_mut = carry_out + 1;
            let (output_bit1, carry_out1) = self.adder(
                corrections,
                masks,
                ab_gamma,
                batch_a,
                batch_b,
                (inputs.0[i], inputs.1[i], carry_out, start_new_wires_mut),
            );
            output_bit = output_bit1;
            carry_out = carry_out1;
            output_bits.push(output_bit);
        }

        (output_bits, carry_out + 1)
    }
}
