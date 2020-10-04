use super::util::SharesGenerator;
use super::ExecutionCommitment;

use crate::algebra::{Domain, LocalOperation, RingElement, RingModule, Samplable, Sharing};
use crate::consts::{CONTEXT_RNG_BRANCH_MASK, CONTEXT_RNG_BRANCH_PERMUTE, CONTEXT_RNG_CORRECTION};
use crate::crypto::{hash, kdf, Hash, Hasher, MerkleSet, RingHasher, TreePRF, KEY_SIZE, PRG};
use crate::util::{VecMap, Writer};
use crate::Instruction;

use std::marker::PhantomData;

#[derive(Copy, Clone)]
struct WireState<D: Domain> {
    plain: D::Scalar,
    wire: D::Scalar,
    mask: D::Sharing,
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<
    D: Domain,
    WI: Iterator<Item = D::Scalar>,
    BI: Iterator<Item = D::Scalar>,
> {
    root: Hash,

    // witness iterator (dummy for the verifier)
    witness: WI,

    // branch iterator (dummy for the verifier)
    branch: BI,

    // interpreter state
    wires: VecMap<WireState<D>>,

    // commitments to player random
    commitments: Vec<Hash>,

    // sharings
    shares: SharesGenerator<D>,

    // messages
    messages: RingHasher<D::Sharing>,

    // Beaver multiplication state
    corrections_prg: Vec<PRG>,
    corrections: RingHasher<D::Batch>, // player 0 corrections
    share_a: Vec<D::Sharing>,          // beta sharings (from input)
    share_b: Vec<D::Sharing>,          // alpha sharings (from input)
    share_ab: Vec<D::Sharing>,         // share ab
    _ph: PhantomData<D>,
}

impl<D: Domain, WI: Iterator<Item = D::Scalar>, BI: Iterator<Item = D::Scalar>>
    PreprocessingExecution<D, WI, BI>
{
    pub fn new(
        root: [u8; KEY_SIZE],       // randomness for this preprocessing
        branches: &[Vec<D::Batch>], // branches
        witness: WI,                // witness (dummy iterator for verifier)
        branch: BI,                 // active branch bits (dummy iterator for verifier)
    ) -> Self {
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
                for i in 0..D::PLAYERS {
                    pad = pad + D::Batch::gen(&mut prgs[i]);
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
            wires: VecMap::new(),
            witness,
            branch,
            corrections_prg: player_seeds
                .iter()
                .map(|seed| PRG::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
                .collect(),
            messages: RingHasher::new(),
            corrections: RingHasher::new(),
            shares: SharesGenerator::new(&player_seeds[..]),
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            share_ab: Vec::with_capacity(D::Batch::DIMENSION),
            _ph: PhantomData,
        }
    }

    #[inline(always)]
    fn generate(
        &mut self,
        batch_ab: &mut [D::Batch],
        batch_a: &mut [D::Batch],
        batch_b: &mut [D::Batch],
    ) {
        debug_assert_eq!(self.share_ab.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_b.len(), D::Batch::DIMENSION);
        debug_assert!(self.shares.beaver.is_empty());

        // transpose sharings into per player batches
        D::convert_inv(&mut batch_a[..], &self.share_a[..]);
        D::convert_inv(&mut batch_b[..], &self.share_b[..]);
        D::convert_inv(&mut batch_ab[..], &self.share_ab[..]);
        self.share_a.clear();
        self.share_b.clear();
        self.share_ab.clear();

        // generate 3 batches of shares for every player
        let mut a = batch_a[0];
        let mut b = batch_b[0];
        let mut c = batch_ab[0];

        // compute random c sharing and reconstruct a,b sharings
        for i in 1..D::PLAYERS {
            a = a + batch_a[i];
            b = b + batch_b[i];
            c = c + batch_ab[i];
        }

        // correct shares for player 0 (correction bits)
        let delta = a * b - c;

        // write correction batch (player 0 correction bits)
        // for the pre-processing phase, the writer will simply be a hash function.
        self.corrections.write(delta);

        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
        debug_assert_eq!(self.share_ab.len(), 0);
    }

    pub fn process(&mut self, program: &[Instruction<D::Scalar>]) {
        let mut batch_a = vec![D::Batch::ZERO; D::PLAYERS];
        let mut batch_b = vec![D::Batch::ZERO; D::PLAYERS];
        let mut batch_ab = vec![D::Batch::ZERO; D::PLAYERS];

        for step in program.iter().cloned() {
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert!(self.share_ab.len() < D::Batch::DIMENSION);
            debug_assert_eq!(self.share_a.len(), self.share_b.len());
            debug_assert_eq!(self.share_a.len(), self.share_ab.len());

            match step {
                Instruction::LocalOp(dst, src) => {
                    let w = self.wires.get(src);
                    self.wires.set(
                        dst,
                        WireState {
                            plain: w.plain.operation(),
                            wire: w.wire.operation(),
                            mask: w.mask.operation(),
                        },
                    );
                }
                Instruction::Input(dst) => {
                    let mask = self.shares.input.next();
                    let witness = self.witness.next().unwrap();
                    self.wires.set(
                        dst,
                        WireState {
                            plain: witness,
                            wire: mask.reconstruct() + witness,
                            mask: mask,
                        },
                    );

                    // assert correctness
                    #[cfg(debug_assertions)]
                    {
                        let w = self.wires.get(dst);
                        assert_eq!(w.mask.reconstruct() - w.wire, w.plain);
                    }
                }
                Instruction::Branch(dst) => {
                    let mask = self.shares.branch.next();
                    let branch = self.branch.next().unwrap();
                    self.wires.set(
                        dst,
                        WireState {
                            plain: branch,
                            wire: mask.reconstruct() + branch,
                            mask: mask,
                        },
                    );

                    // assert correctness
                    #[cfg(debug_assertions)]
                    {
                        let w = self.wires.get(dst);
                        assert_eq!(w.mask.reconstruct() - w.wire, w.plain);
                    }
                }
                Instruction::AddConst(dst, src, c) => {
                    let w = self.wires.get(src);
                    self.wires.set(
                        dst,
                        WireState {
                            plain: w.plain + c,
                            wire: w.wire + c,
                            mask: w.mask,
                        },
                    );

                    // assert correctness
                    #[cfg(debug_assertions)]
                    {
                        let w = self.wires.get(dst);
                        assert_eq!(w.mask.reconstruct() - w.wire, w.plain);
                    }
                }
                Instruction::MulConst(dst, src, c) => {
                    let w = self.wires.get(src);
                    self.wires.set(
                        dst,
                        WireState {
                            plain: w.plain * c,
                            wire: w.wire * c,
                            mask: w.mask.action(c),
                        },
                    );

                    // assert correctness
                    #[cfg(debug_assertions)]
                    {
                        let w = self.wires.get(dst);
                        assert_eq!(w.mask.reconstruct() - w.wire, w.plain);
                    }
                }
                Instruction::Add(dst, src1, src2) => {
                    let w1 = self.wires.get(src1);
                    let w2 = self.wires.get(src2);
                    self.wires.set(
                        dst,
                        WireState {
                            plain: w1.plain + w2.plain,
                            wire: w1.wire + w2.wire,
                            mask: w1.mask + w2.mask,
                        },
                    );

                    // assert correctness
                    #[cfg(debug_assertions)]
                    {
                        let w = self.wires.get(dst);
                        assert_eq!(w.mask.reconstruct() - w.wire, w1.plain);
                    }
                }
                Instruction::Mul(dst, src1, src2) => {
                    let w1 = self.wires.get(src1);
                    let w2 = self.wires.get(src2);

                    // generate mask for [ab] and [\lambda]
                    let mask_l = self.shares.beaver.next();
                    let mask_ab = self.shares.beaver.next();

                    // push the input masks to the deferred correction bit computation
                    self.share_a.push(w1.mask);
                    self.share_b.push(w2.mask);
                    self.share_ab.push(mask_ab);

                    // add multiplication message to transcript (except correction bit)
                    self.messages.update(
                        w1.mask.action(w2.wire) + w2.mask.action(w1.wire) + mask_l + mask_ab,
                    );

                    // assign output
                    let plain = w1.plain * w2.plain;
                    self.wires.set(
                        dst,
                        WireState {
                            plain,
                            wire: plain + mask_l.reconstruct(),
                            mask: mask_l,
                        },
                    );

                    // if the batch is full, generate next batch of ab_gamma shares
                    if self.share_a.len() == D::Batch::DIMENSION {
                        self.generate(&mut batch_ab, &mut batch_a, &mut batch_b);
                    }

                    // assert correctness
                    #[cfg(debug_assertions)]
                    {
                        let w = self.wires.get(dst);
                        assert_eq!(w.mask.reconstruct() - w.wire, w1.plain);
                    }
                }
                Instruction::Output(src) => self.messages.update(self.wires.get(src).mask),
            }
        }
    }

    pub fn done(mut self) -> ExecutionCommitment {
        // pad final multiplication batch if needed
        if self.share_a.len() > 0 {
            let mut batch_a = vec![D::Batch::ZERO; D::PLAYERS];
            let mut batch_b = vec![D::Batch::ZERO; D::PLAYERS];
            let mut batch_ab = vec![D::Batch::ZERO; D::PLAYERS];
            self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.share_ab.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.generate(&mut batch_ab, &mut batch_a, &mut batch_b);
        }

        // return commitment to preprocessing and online
        ExecutionCommitment::new(
            self.commitments,
            self.corrections.finalize(),
            self.root,
            self.messages.finalize(),
        )
    }
}
