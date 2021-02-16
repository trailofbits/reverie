use super::util::PartialSharesGenerator;

use crate::algebra::{Domain, LocalOperation, RingElement, RingModule, Samplable};
use crate::consts::CONTEXT_RNG_CORRECTION;
use crate::crypto::{hash, kdf, Hash, Hasher, RingHasher, TreePrf, KEY_SIZE, Prg};
use crate::util::{VecMap, Writer};
use crate::Instruction;

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
    share_a: Vec<D::Sharing>, // beta sharings (from input)
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
        D::convert_inv(&mut batch_a[..], &self.share_a[..]);
        D::convert_inv(&mut batch_b[..], &self.share_b[..]);
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
        program: &[Instruction<D::Scalar>], // program slice
        corrections: &[D::Batch],           // player 0 corrections
        masks: &mut Vec<D::Sharing>,        // resulting sharings consumed by online phase
        ab_gamma: &mut Vec<D::Sharing>,     // a * b + \gamma sharings for online phase
    ) -> Option<()> {
        let mut corrections = corrections.iter().cloned();

        // invariant: multiplication batch empty at the start
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
        debug_assert!(self.shares.beaver.is_empty());

        // look forward in program until executed enough multiplications for next batch
        let mut batch_a = vec![D::Batch::ZERO; D::PLAYERS];
        let mut batch_b = vec![D::Batch::ZERO; D::PLAYERS];

        for step in program {
            debug_assert_eq!(self.share_a.len(), self.share_b.len());
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            match *step {
                Instruction::LocalOp(dst, src) => {
                    self.masks.set(dst, self.masks.get(src).operation());
                }
                Instruction::Branch(dst) => {
                    // check if need for new batch of branch masks
                    let mask = self.shares.branch.next();

                    // assign the next unused branch share to the destination wire
                    self.masks.set(dst, mask);
                }
                Instruction::Input(dst) => {
                    // check if need for new batch of input masks
                    let mask = self.shares.input.next();

                    // assign the next unused input share to the destination wire
                    self.masks.set(dst, mask);
                }
                Instruction::AddConst(dst, src, _c) => {
                    // noop in pre-processing
                    self.masks.set(dst, self.masks.get(src));
                }
                Instruction::MulConst(dst, src, c) => {
                    // resolve input
                    let sw = self.masks.get(src);

                    // let the single element act on the vector
                    self.masks.set(dst, sw.action(c));
                }
                Instruction::Add(dst, src1, src2) => {
                    self.masks
                        .set(dst, self.masks.get(src1) + self.masks.get(src2));
                }
                Instruction::Mul(dst, src1, src2) => {
                    // push the input masks to the stack
                    let mask_a = self.masks.get(src1);
                    let mask_b = self.masks.get(src2);
                    self.share_a.push(mask_a);
                    self.share_b.push(mask_b);

                    // assign mask to output
                    // (NOTE: can be done before the correction bits are computed, allowing batching regardless of circuit topology)
                    self.masks.set(dst, self.shares.beaver.next());

                    // return the mask to online phase for Beaver multiplication
                    masks.write(mask_a);
                    masks.write(mask_b);

                    // if the batch is full, generate next batch of ab_gamma shares
                    if self.share_a.len() == D::Batch::DIMENSION {
                        self.generate(ab_gamma, &mut corrections, &mut batch_a, &mut batch_b)?;
                    }
                }
                Instruction::Output(src) => {
                    // return to online phase for reconstruction
                    masks.write(self.masks.get(src));
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
}
