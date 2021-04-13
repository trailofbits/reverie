use super::util::SharesGenerator;

use crate::algebra::{Domain, LocalOperation, RingElement, RingModule, Samplable};
use crate::consts::{CONTEXT_RNG_BRANCH_MASK, CONTEXT_RNG_BRANCH_PERMUTE, CONTEXT_RNG_CORRECTION};
use crate::crypto::{kdf, Hash, MerkleSet, MerkleSetProof, Prg, RingHasher, TreePrf, KEY_SIZE};
use crate::fieldswitching::util::DedupMap;
use crate::util::{VecMap, Writer};
use crate::Instruction;
use std::collections::HashSet;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain> {
    // branch opening state
    root: [u8; KEY_SIZE],
    player_seeds: Vec<[u8; KEY_SIZE]>,

    // interpreter state
    masks: VecMap<D::Sharing>,

    // sharings
    shares: SharesGenerator<D>,

    // scratch space
    scratch: Vec<D::Batch>,

    // Beaver multiplication state
    corrections_prg: Vec<Prg>,
    share_a: Vec<D::Sharing>,
    // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
}

impl<D: Domain> PreprocessingExecution<D> {
    pub fn prove_branch(
        &self,
        branches: &[Vec<D::Batch>],
        index: usize,
    ) -> (Vec<D::Batch>, MerkleSetProof) {
        let mut prgs: Vec<Prg> = self
            .player_seeds
            .iter()
            .map(|seed| Prg::new(kdf(CONTEXT_RNG_BRANCH_MASK, seed)))
            .collect();

        let mut hashes: Vec<RingHasher<D::Batch>> =
            (0..branches.len()).map(|_| RingHasher::new()).collect();

        let mut branch = Vec::with_capacity(branches[index].len());

        for j in 0..branches[0].len() {
            let mut pad = D::Batch::ZERO;
            for prg in prgs.iter_mut().take(D::PLAYERS) {
                pad = pad + D::Batch::gen(prg);
            }
            for b in 0..branches.len() {
                debug_assert_eq!(branches[b].len(), branches[0].len());
                hashes[b].write(pad + branches[b][j]);
            }
            branch.push(pad + branches[index][j])
        }

        let hashes: Vec<Hash> = hashes.into_iter().map(|hs| hs.finalize()).collect();
        let set = MerkleSet::new(kdf(CONTEXT_RNG_BRANCH_PERMUTE, &self.root), &hashes[..]);
        let proof = set.prove(index);

        debug_assert_eq!(proof.verify(&hashes[index]), set.root().clone());

        (branch, proof)
    }

    pub fn new(root: [u8; KEY_SIZE]) -> Self {
        // expand repetition seed into per-player seeds
        let mut player_seeds: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; D::PLAYERS];
        TreePrf::expand_full(&mut player_seeds, root);

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        let corrections_prg = player_seeds
            .iter()
            .map(|seed| Prg::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
            .collect();

        let shares = SharesGenerator::new(&player_seeds[..]);

        PreprocessingExecution {
            root,
            player_seeds,
            corrections_prg,
            shares,
            scratch: vec![D::Batch::ZERO; D::PLAYERS],
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            masks: VecMap::new(),
        }
    }

    #[inline(always)]
    fn generate<CW: Writer<D::Batch>>(
        &mut self,
        ab_gamma: &mut Vec<D::Sharing>,
        corrections: &mut CW, // player 0 corrections
        batch_a: &mut [D::Batch],
        batch_b: &mut [D::Batch],
    ) {
        debug_assert!(self.shares.beaver.is_empty());
        debug_assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_b.len(), D::Batch::DIMENSION);

        // transpose sharings into per player batches
        D::convert_inv(batch_a, &self.share_a[..]);
        D::convert_inv(batch_b, &self.share_b[..]);
        self.share_a.clear();
        self.share_b.clear();

        // reconstruct 3 batches of shares (D::Batch::DIMENSION multiplications in parallel)
        let mut a = D::Batch::ZERO;
        let mut b = D::Batch::ZERO;
        let mut c = D::Batch::ZERO;

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..D::PLAYERS {
            let m = D::Batch::gen(&mut self.corrections_prg[i]);
            a = a + batch_a[i];
            b = b + batch_b[i];
            c = c + m;
            self.scratch[i] = m + self.shares.beaver.batches()[i];
        }

        // correct shares for player 0 (correction bits)
        let delta = a * b - c;

        // output correction batch (player 0 correction bits)
        corrections.write(delta);

        // correct ab_gamma (in parallel)
        self.scratch[0] = self.scratch[0] + delta;

        // check that ab_gamma is a sharing of a * b + \gamma
        #[cfg(test)]
        {
            let mut gamma = D::Batch::ZERO;
            let mut ab_gamma_recons = D::Batch::ZERO;
            for i in 0..D::PLAYERS {
                gamma = gamma + self.shares.beaver.batches()[i];
                ab_gamma_recons = ab_gamma_recons + self.scratch[i];
            }
            assert_eq!(a * b + gamma, ab_gamma_recons);
        }

        // transpose into shares
        let start = ab_gamma.len();
        ab_gamma.resize(start + D::Batch::DIMENSION, D::Sharing::ZERO);
        D::convert(&mut ab_gamma[start..], &self.scratch[..]);
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
        debug_assert_eq!(ab_gamma.len() % D::Batch::DIMENSION, 0);
    }

    #[inline(always)]
    pub fn process<CW: Writer<D::Batch>, MW: Writer<D::Sharing>>(
        &mut self,
        program: (&[Instruction<D::Scalar>], usize), // program slice
        corrections: &mut CW,                        // player 0 corrections
        masks: &mut MW,                              // masks for online phase
        ab_gamma: &mut Vec<D::Sharing>,              // a * b + \gamma sharings for online phase
        fieldswitching_input: HashSet<usize>,
        fieldswitching_output: DedupMap<usize>,
    ) {
        // invariant: multiplication batch empty at the start
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
        debug_assert!(self.shares.beaver.is_empty());

        // look forward in program until executed enough multiplications for next batch
        let mut batch_a = vec![D::Batch::ZERO; D::PLAYERS];
        let mut batch_b = vec![D::Batch::ZERO; D::PLAYERS];
        let mut nr_of_wires = program.1;
        let mut fieldswitching_output_done = HashSet::new();

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

                    // return the mask to the online phase (for hiding the branch)
                    masks.write(mask);
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

                    // return the mask to the online phase (for hiding the witness)
                    masks.write(mask);

                    if fieldswitching_input.contains(&dst) {
                        nr_of_wires += 1;
                        // check if need for new batch of input masks
                        let mask = self.shares.input.next();

                        // assign the next unused input share to the destination wire
                        self.masks.set(nr_of_wires, mask);

                        // return the mask to the online phase (for hiding the witness)
                        masks.write(mask);

                        self.process_add(masks, dst, new_dst, nr_of_wires);
                        nr_of_wires += 1;
                    }
                }
                Instruction::Const(dst, _c) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.masks.set(dst, D::Sharing::ZERO);
                    masks.write(D::Sharing::ZERO);
                    // We don't need to mask constant inputs because the circuit is public
                }
                Instruction::AddConst(dst, src, _c) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    // noop in pre-processing
                    self.masks.set(dst, self.masks.get(src));

                    // return mask for debugging
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    #[cfg(feature = "debug_eval")]
                    {
                        masks.write(self.masks.get(dst));
                    }
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

                    // return mask for debugging
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    #[cfg(feature = "debug_eval")]
                    {
                        masks.write(self.masks.get(dst));
                    }
                }
                Instruction::Add(dst, src1, src2) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.process_add(masks, dst, src1, src2)
                }
                Instruction::Sub(dst, src1, src2) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.process_sub(masks, dst, src1, src2)
                }
                Instruction::Mul(dst, src1, src2) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );
                    self.process_mul(
                        corrections,
                        masks,
                        ab_gamma,
                        &mut batch_a,
                        &mut batch_b,
                        (dst, src1, src2),
                    )
                }
                Instruction::Output(src) => {
                    assert_ne!(
                        nr_of_wires, 0,
                        "Make sure to have Instruction::NrOfWires as first gate in a program"
                    );

                    let maybe_out_list = fieldswitching_output.get(&src);
                    let found = maybe_out_list.is_some();
                    let out_list: Vec<usize> = if found {
                        maybe_out_list.unwrap().clone()
                    } else {
                        Vec::new()
                    };

                    if found {
                        fieldswitching_output_done.insert(src);
                        let contains_all = out_list
                            .iter()
                            .all(|i| fieldswitching_output_done.contains(i));

                        if contains_all {
                            let mut zeroes = Vec::new();
                            for _i in 0..out_list.len() {
                                // check if need for new batch of input masks
                                let mask = self.shares.input.next();

                                // assign the next unused input share to the destination wire
                                self.masks.set(nr_of_wires, mask);

                                // return the mask to the online phase (for hiding the witness)
                                masks.write(mask);
                                zeroes.push(nr_of_wires);
                                nr_of_wires += 1;
                            }
                            let (outputs, carry_out) = self.full_adder(
                                corrections,
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
            self.generate(ab_gamma, corrections, &mut batch_a, &mut batch_b);
        }
    }

    fn process_add<MW: Writer<D::Sharing>>(
        &mut self,
        _masks: &mut MW,
        dst: usize,
        src1: usize,
        src2: usize,
    ) {
        self.masks
            .set(dst, self.masks.get(src1) + self.masks.get(src2));

        // return mask for debugging
        #[cfg(test)]
        #[cfg(debug_assertions)]
        #[cfg(feature = "debug_eval")]
        {
            _masks.write(self.masks.get(dst));
        }
    }

    fn process_sub<MW: Writer<D::Sharing>>(
        &mut self,
        _masks: &mut MW,
        dst: usize,
        src1: usize,
        src2: usize,
    ) {
        self.masks
            .set(dst, self.masks.get(src1) - self.masks.get(src2));

        // return mask for debugging
        #[cfg(test)]
        #[cfg(debug_assertions)]
        #[cfg(feature = "debug_eval")]
        {
            _masks.write(self.masks.get(dst));
        }
    }

    fn process_mul<CW: Writer<D::Batch>, MW: Writer<D::Sharing>>(
        &mut self,
        corrections: &mut CW,
        masks: &mut MW,
        ab_gamma: &mut Vec<<D as Domain>::Sharing>,
        mut batch_a: &mut Vec<D::Batch>,
        mut batch_b: &mut Vec<D::Batch>,
        wire_nrs: (usize, usize, usize),
    ) {
        // push the input masks to the stack
        let mask_a = self.masks.get(wire_nrs.1);
        let mask_b = self.masks.get(wire_nrs.2);
        self.share_a.push(mask_a);
        self.share_b.push(mask_b);

        // return the mask to online phase for Beaver multiplication
        masks.write(mask_a);
        masks.write(mask_b);

        // assign mask to output
        // (NOTE: can be done before the correction bits are computed, allowing batching regardless of circuit topology)
        self.masks.set(wire_nrs.0, self.shares.beaver.next());

        // if the batch is full, generate next batch of ab_gamma shares
        if self.share_a.len() == D::Batch::DIMENSION {
            self.generate(ab_gamma, corrections, &mut batch_a, &mut batch_b);
        }

        // return mask for debugging
        #[cfg(test)]
        #[cfg(debug_assertions)]
        #[cfg(feature = "debug_eval")]
        {
            masks.write(self.masks.get(wire_nrs.0));
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
    fn adder<CW: Writer<D::Batch>, MW: Writer<D::Sharing>>(
        &mut self,
        corrections: &mut CW,
        masks: &mut MW,
        ab_gamma: &mut Vec<<D as Domain>::Sharing>,
        batch_a: &mut Vec<D::Batch>,
        batch_b: &mut Vec<D::Batch>,
        inputs: (usize, usize, usize, usize),
    ) -> (usize, usize) {
        self.process_add(masks, inputs.3, inputs.0, inputs.1);
        self.process_add(masks, inputs.3 + 1, inputs.2, inputs.3);
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
        self.process_add(masks, inputs.3 + 5, inputs.3 + 2, inputs.3 + 3);
        self.process_add(masks, inputs.3 + 6, inputs.3 + 4, inputs.3 + 5);

        (inputs.3 + 1, inputs.3 + 6)
    }

    fn first_adder<CW: Writer<D::Batch>, MW: Writer<D::Sharing>>(
        &mut self,
        corrections: &mut CW,
        masks: &mut MW,
        ab_gamma: &mut Vec<<D as Domain>::Sharing>,
        batch_a: &mut Vec<D::Batch>,
        batch_b: &mut Vec<D::Batch>,
        inputs: (usize, usize, usize),
    ) -> (usize, usize) {
        self.process_add(masks, inputs.2, inputs.0, inputs.1);
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
    fn full_adder<CW: Writer<D::Batch>, MW: Writer<D::Sharing>>(
        &mut self,
        corrections: &mut CW,
        masks: &mut MW,
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
