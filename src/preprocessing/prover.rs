use rand::Rng;

use crate::algebra::{Domain, LocalOperation, RingElement, RingModule, Samplable};
use crate::consts::{CONTEXT_RNG_BRANCH_PERMUTE, CONTEXT_RNG_CORRECTION};
use crate::crypto::{kdf, MerkleSetProof, Prg, TreePrf, KEY_SIZE};
use crate::util::{VecMap, Writer};
use crate::Instruction;

use super::util::SharesGenerator;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain> {
    // branch opening state
    root: [u8; KEY_SIZE],

    // interpreter state
    masks: VecMap<D::Sharing>,

    // sharings
    shares: SharesGenerator<D>,

    // scratch space
    scratch: Vec<D::Batch>,

    // Beaver multiplication state
    corrections_prg: Vec<Prg>,
    share_a: Vec<D::Sharing>, // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
}

impl<D: Domain> PreprocessingExecution<D> {
    pub fn prove_branch(&self) -> MerkleSetProof {
        let seed = kdf(CONTEXT_RNG_BRANCH_PERMUTE, &self.root);
        let mut rng = Prg::new(seed);
        MerkleSetProof { rand: rng.gen() }
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
        program: &[Instruction<D::Scalar>], // program slice
        corrections: &mut CW,               // player 0 corrections
        masks: &mut MW,                     // masks for online phase
        ab_gamma: &mut Vec<D::Sharing>,     // a * b + \gamma sharings for online phase
    ) {
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
                Instruction::Input(dst) => {
                    // check if need for new batch of input masks
                    let mask = self.shares.input.next();

                    // assign the next unused input share to the destination wire
                    self.masks.set(dst, mask);

                    // return the mask to the online phase (for hiding the witness)
                    masks.write(mask);
                }
                Instruction::Const(dst, _c) => {
                    // We don't need to mask constant inputs because the circuit is public
                    self.masks.set(dst, D::Sharing::ZERO);
                }
                Instruction::AddConst(dst, src, _c) => {
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
                    self.masks
                        .set(dst, self.masks.get(src1) + self.masks.get(src2));

                    // return mask for debugging
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    #[cfg(feature = "debug_eval")]
                    {
                        masks.write(self.masks.get(dst));
                    }
                }
                Instruction::Sub(dst, src1, src2) => {
                    self.masks
                        .set(dst, self.masks.get(src1) - self.masks.get(src2));

                    // return mask for debugging
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    #[cfg(feature = "debug_eval")]
                    {
                        masks.write(self.masks.get(dst));
                    }
                }
                Instruction::Mul(dst, src1, src2) => {
                    // push the input masks to the stack
                    let mask_a = self.masks.get(src1);
                    let mask_b = self.masks.get(src2);
                    self.share_a.push(mask_a);
                    self.share_b.push(mask_b);

                    // return the mask to online phase for Beaver multiplication
                    masks.write(mask_a);
                    masks.write(mask_b);

                    // assign mask to output
                    // (NOTE: can be done before the correction bits are computed, allowing batching regardless of circuit topology)
                    self.masks.set(dst, self.shares.beaver.next());

                    // if the batch is full, generate next batch of ab_gamma shares
                    if self.share_a.len() == D::Batch::DIMENSION {
                        self.generate(ab_gamma, corrections, &mut batch_a, &mut batch_b);
                    }

                    // return mask for debugging
                    #[cfg(test)]
                    #[cfg(debug_assertions)]
                    #[cfg(feature = "debug_eval")]
                    {
                        masks.write(self.masks.get(dst));
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
            self.generate(ab_gamma, corrections, &mut batch_a, &mut batch_b);
        }
    }
}
