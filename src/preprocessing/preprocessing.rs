use super::util::SharesGenerator;

use crate::algebra::{Domain, LocalOperation, RingElement, RingModule, Samplable};
use crate::consts::{CONTEXT_RNG_BRANCH_MASK, CONTEXT_RNG_BRANCH_PERMUTE, CONTEXT_RNG_CORRECTION};
use crate::crypto::{hash, kdf, Hash, Hasher, MerkleSet, RingHasher, TreePRF, KEY_SIZE, PRG};
use crate::util::{VecMap, Writer};
use crate::Instruction;

use std::marker::PhantomData;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain> {
    root: Hash,

    // commitments to player random
    commitments: Vec<Hash>,

    // interpreter state
    masks: VecMap<D::Sharing>,

    // sharings
    shares: SharesGenerator<D>,

    // Beaver multiplication state
    corrections_prg: Vec<PRG>,
    corrections: RingHasher<D::Batch>, // player 0 corrections
    share_a: Vec<D::Sharing>,          // beta sharings (from input)
    share_b: Vec<D::Sharing>,          // alpha sharings (from input)
    _ph: PhantomData<D>,
}

impl<D: Domain> PreprocessingExecution<D> {
    pub fn new(root: [u8; KEY_SIZE], branches: &[Vec<D::Batch>]) -> Self {
        // expand repetition seed into per-player seeds
        let mut player_seeds: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; D::PLAYERS];
        TreePRF::expand_full(&mut player_seeds, root);

        // mask the branches and compute the root of the Merkle tree
        let root: Hash = {
            let mut hashes: Vec<RingHasher<D::Batch>> =
                (0..branches.len()).map(|_| RingHasher::new()).collect();

            let mut prgs: Vec<PRG> = player_seeds
                .iter()
                .map(|seed| PRG::new(kdf(CONTEXT_RNG_BRANCH_MASK, seed)))
                .collect();

            for j in 0..branches[0].len() {
                let mut pad = D::Batch::ZERO;
                for prg in prgs.iter_mut().take(D::PLAYERS) {
                    pad = pad + D::Batch::gen(prg);
                }
                for b in 0..branches.len() {
                    hashes[b].write(pad + branches[b][j]) // notice the permutation
                }
            }

            let hashes: Vec<Hash> = hashes.into_iter().map(|hs| hs.finalize()).collect();
            MerkleSet::new(kdf(CONTEXT_RNG_BRANCH_PERMUTE, &root), &hashes[..])
                .root()
                .clone()
        };

        // commit to per-player randomness
        let commitments: Vec<Hash> = player_seeds.iter().map(|seed| hash(seed)).collect();

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        PreprocessingExecution {
            root,
            commitments,
            corrections_prg: player_seeds
                .iter()
                .map(|seed| PRG::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
                .collect(),
            corrections: RingHasher::new(),
            shares: SharesGenerator::new(&player_seeds[..]),
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            masks: VecMap::new(),
            _ph: PhantomData,
        }
    }

    #[inline(always)]
    fn generate(&mut self, batch_a: &mut [D::Batch], batch_b: &mut [D::Batch]) {
        debug_assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_b.len(), D::Batch::DIMENSION);
        debug_assert!(self.shares.beaver.is_empty());

        // transpose sharings into per player batches
        D::convert_inv(&mut batch_a[..], &self.share_a[..]);
        D::convert_inv(&mut batch_b[..], &self.share_b[..]);
        self.share_a.clear();
        self.share_b.clear();

        // generate 3 batches of shares for every player
        let mut a = D::Batch::ZERO;
        let mut b = D::Batch::ZERO;
        let mut c = D::Batch::ZERO;

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..D::PLAYERS {
            let corr = D::Batch::gen(&mut self.corrections_prg[i]);
            a = a + batch_a[i];
            b = b + batch_b[i];
            c = c + corr;
        }

        // correct shares for player 0 (correction bits)
        let delta = a * b - c;

        // write correction batch (player 0 correction bits)
        // for the pre-processing phase, the writer will simply be a hash function.
        self.corrections.write(delta);

        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
    }

    pub fn prove(&mut self,
                 program: &[Instruction<D::Scalar>],
                 fieldswitching_input: Vec<usize>,
                 fieldswitching_output: Vec<Vec<usize>>,) {
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);

        let mut batch_a = vec![D::Batch::ZERO; D::PLAYERS];
        let mut batch_b = vec![D::Batch::ZERO; D::PLAYERS];
        let mut nr_of_wires = 0;
        let mut fieldswitching_output_done = Vec::new();

        for step in program {
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert_eq!(self.share_a.len(), self.share_b.len());

            match *step {
                Instruction::NrOfWires(nr) => {
                    nr_of_wires = nr.clone();
                }
                Instruction::LocalOp(dst, src) => {
                    assert_ne!(nr_of_wires, 0);
                    self.masks.set(dst, self.masks.get(src).operation());
                }
                Instruction::Input(dst) => {
                    assert_ne!(nr_of_wires, 0);

                    let mut new_dst = dst;
                    if fieldswitching_input.contains(&dst) {
                        new_dst = nr_of_wires;
                    }

                    self.masks.set(new_dst, self.shares.input.next());

                    if fieldswitching_input.contains(&dst) {
                        self.masks.set(dst, self.masks.get(nr_of_wires));
                        nr_of_wires += 1;
                    }
                }
                Instruction::Branch(dst) => {
                    assert_ne!(nr_of_wires, 0);
                    self.masks.set(dst, self.shares.branch.next());
                }
                Instruction::Const(dst, _c) => {
                    assert_ne!(nr_of_wires, 0);
                    self.masks.set(dst, D::Sharing::ZERO);
                    // We don't need to mask constant inputs because the circuit is public
                }
                Instruction::AddConst(dst, src, _c) => {
                    assert_ne!(nr_of_wires, 0);
                    self.masks.set(dst, self.masks.get(src));
                }
                Instruction::MulConst(dst, src, c) => {
                    assert_ne!(nr_of_wires, 0);
                    let sw = self.masks.get(src);
                    self.masks.set(dst, sw.action(c));
                }
                Instruction::Add(dst, src1, src2) => {
                    assert_ne!(nr_of_wires, 0);
                    self.process_add(dst, src1, src2);
                }
                Instruction::Mul(dst, src1, src2) => {
                    assert_ne!(nr_of_wires, 0);
                    self.process_mul(&mut batch_a, &mut batch_b, dst, src1, src2)
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
                                self.masks.set(nr_of_wires, D::Sharing::ZERO); //process_const
                                zeroes.push(nr_of_wires);
                                nr_of_wires += 1;
                            }
                            let (_outputs, carry_out) = self.full_adder(&mut batch_a, &mut batch_b, out_list, zeroes, nr_of_wires);
                            nr_of_wires = carry_out;
                        }
                    }
                },
            }
        }

        // pad final multiplication batch if needed
        if !self.share_a.is_empty() {
            self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.shares.beaver.empty();
            self.generate(&mut batch_a, &mut batch_b);
        }
    }

    fn process_add(&mut self, dst: usize, src1: usize, src2: usize) {
        self.masks.set(dst, self.masks.get(src1) + self.masks.get(src2));
    }

    fn process_mul(&mut self, mut batch_a: &mut Vec<D::Batch>, mut batch_b: &mut Vec<D::Batch>, dst: usize, src1: usize, src2: usize) {
        // push the input masks to the deferred multiplication stack
        let mask_a = self.masks.get(src1);
        let mask_b = self.masks.get(src2);
        self.share_a.push(mask_a);
        self.share_b.push(mask_b);

        // assign mask to output
        self.masks.set(dst, self.shares.beaver.next());

        // if the batch is full, generate next batch of ab_gamma shares
        if self.share_a.len() == D::Batch::DIMENSION {
            self.generate(&mut batch_a, &mut batch_b);
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
    fn adder(&mut self, mut batch_a: &mut Vec<D::Batch>, mut batch_b: &mut Vec<D::Batch>, input1: usize, input2: usize, carry_in: usize, start_new_wires: usize) -> (usize, usize) {
        self.process_add(start_new_wires, input1, input2);
        self.process_add(start_new_wires + 1, carry_in, start_new_wires);
        self.process_mul(batch_a, batch_b, start_new_wires + 2, carry_in, start_new_wires);
        self.process_mul(batch_a, batch_b, start_new_wires + 3, input1, input2);
        self.process_mul(batch_a, batch_b, start_new_wires + 4, start_new_wires + 2, start_new_wires + 3);
        self.process_add(start_new_wires + 5, start_new_wires + 2, start_new_wires + 3);
        self.process_add(start_new_wires + 6, start_new_wires + 4, start_new_wires + 5);

        (start_new_wires + 1, start_new_wires + 6)
    }

    fn first_adder(&mut self, mut batch_a: &mut Vec<D::Batch>, mut batch_b: &mut Vec<D::Batch>, input1: usize, input2: usize, start_new_wires: usize) -> (usize, usize) {
        self.process_add(start_new_wires, input1, input2);
        self.process_mul(batch_a, batch_b, start_new_wires + 1, input1, input2);

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
    fn full_adder(&mut self, mut batch_a: &mut Vec<D::Batch>, mut batch_b: &mut Vec<D::Batch>, start_input1: Vec<usize>, start_input2: Vec<usize>, start_new_wires: usize) -> (Vec<usize>, usize) {
        assert_eq!(start_input1.len(), start_input2.len());
        assert!(start_input1.len() > 0);
        let mut output_bits = Vec::new();
        let mut start_new_wires_mut = start_new_wires.clone();

        let (mut output_bit, mut carry_out) = self.first_adder(batch_a, batch_b, start_input1[0], start_input2[0], start_new_wires);
        output_bits.push(output_bit);
        for i in 1..start_input1.len() {
            start_new_wires_mut += carry_out;
            let (output_bit1, carry_out1) = self.adder(batch_a, batch_b, start_input1[i], start_input2[i], carry_out, start_new_wires_mut);
            output_bit = output_bit1;
            carry_out = carry_out1;
            output_bits.push(output_bit);
        }

        (output_bits, carry_out)
    }

    pub fn done(mut self) -> (Hash, Vec<Hash>) {
        // add corrections and Merkle root to player 0 commitment
        self.commitments[0] = {
            let mut comm = Hasher::new();
            comm.update(self.commitments[0].as_bytes());
            comm.update(self.corrections.finalize().as_bytes());
            comm.finalize()
        };

        // merge player commitments with branch tree commitment
        let mut union = Hasher::new();
        union.update(self.root.as_bytes());
        for comm in self.commitments.iter() {
            union.update(comm.as_bytes());
        }

        // return player commitments
        (union.finalize(), self.commitments)
    }
}
