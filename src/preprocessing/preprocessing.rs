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

    pub fn prove(&mut self, program: &[Instruction<D::Scalar>]) {
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);

        let mut batch_a = vec![D::Batch::ZERO; D::PLAYERS];
        let mut batch_b = vec![D::Batch::ZERO; D::PLAYERS];

        for step in program {
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert_eq!(self.share_a.len(), self.share_b.len());

            match *step {
                Instruction::LocalOp(dst, src) => {
                    self.masks.set(dst, self.masks.get(src).operation());
                }
                Instruction::Input(dst) => {
                    self.masks.set(dst, self.shares.input.next());
                }
                Instruction::Branch(dst) => {
                    self.masks.set(dst, self.shares.branch.next());
                }
                Instruction::Const(_dst, _c) => {
                    // We don't need to mask constant inputs because the circuit is public
                }
                Instruction::AddConst(dst, src, _c) => {
                    self.masks.set(dst, self.masks.get(src));
                }
                Instruction::MulConst(dst, src, c) => {
                    let sw = self.masks.get(src);
                    self.masks.set(dst, sw.action(c));
                }
                Instruction::Add(dst, src1, src2) => {
                    self.masks
                        .set(dst, self.masks.get(src1) + self.masks.get(src2));
                }
                Instruction::Mul(dst, src1, src2) => {
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
                Instruction::Output(_) => (), // noop in preprocessing
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
