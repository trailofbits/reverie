use super::*;

use crate::consts::{LABEL_RNG_BEAVER, LABEL_RNG_BRANCH, LABEL_RNG_INPUT};
use crate::crypto::PRG;
use crate::util::{VoidWriter, Writer};
use crate::Instruction;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain> {
    // commitments to player random
    commitments: Vec<Hash>,
    branches: MerkleTree,

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

        // commit to per-player randomness
        let commitments: Vec<Hash> = player_seeds.iter().map(|seed| hash(seed)).collect();

        // create per-player PRG instances
        let mut players: Vec<Player> = player_seeds.iter().map(|seed| Player::new(seed)).collect();

        // randomly permute the branches
        let mut perm_prg = PRG::new(kdf(CONTEXT_RNG_BRANCH_PERMUTE, &root));
        let mut perm: Vec<&[D::Batch]> = branches.iter().map(|v| &v[..]).collect();
        perm.shuffle(&mut perm_prg);

        // mask the branches
        let mut branch_hashes: Vec<RingHasher<D::Batch>> =
            (0..D::PLAYERS).map(|_| RingHasher::new()).collect();

        for j in 0..branches[0].len() {
            let mut pad = D::Batch::ZERO;
            for i in 0..D::PLAYERS {
                pad = pad + D::Batch::gen(&mut players[i].branch);
            }
            for b in 0..branches.len() {
                branch_hashes[b].write(pad + branches[b][j])
            }
        }

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        let tree = MerkleTree::try_from_iter(branch_hashes.into_iter().map(|hs| Ok(hs.finalize())))
            .unwrap();

        PreprocessingExecution {
            commitments,
            corrections_prg: player_seeds
                .iter()
                .map(|seed| PRG::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
                .collect(),
            corrections: RingHasher::new(),
            shares: SharesGenerator::new(&player_seeds[..]),
            branches: tree,
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
                Instruction::Input(dst) => {
                    self.masks.set(dst, self.shares.input.next());
                }
                Instruction::Branch(dst) => {
                    self.masks.set(dst, self.shares.branch.next());
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
        if self.share_a.len() > 0 {
            self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.shares.beaver.empty();
            self.generate(&mut batch_a, &mut batch_b);
        }
    }

    pub fn done(mut self) -> Vec<Hash> {
        // add corrections and Merkle root to player 0 commitment
        self.commitments[0] = {
            let mut comm = Hasher::new();
            comm.update(self.commitments[0].as_bytes());
            comm.update(self.corrections.finalize().as_bytes());
            comm.update(self.branches.root().as_bytes());
            comm.finalize()
        };

        // return player commitments
        self.commitments
    }
}
