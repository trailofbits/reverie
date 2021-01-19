use crate::{ConnectionInstruction};
use crate::algebra::{Domain, RingElement, RingModule, Samplable};
use crate::consts::{CONTEXT_RNG_CORRECTION, CONTEXT_RNG_BRANCH_MASK, CONTEXT_RNG_BRANCH_PERMUTE};
use crate::crypto::{kdf, KEY_SIZE, PRG, TreePRF, MerkleSetProof, RingHasher, MerkleSet, Hash};
use crate::fieldswitching::preprocessing::util::convert_bit_domain;
use crate::util::{VecMap, Writer};

use super::util::SharesGenerator;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain, D2: Domain> {
    root: [u8; KEY_SIZE],
    player_seeds: Vec<[u8; KEY_SIZE]>,

    // interpreter state
    masks: VecMap<D::Sharing>,
    masks_2: VecMap<D2::Sharing>,

    // sharings
    shares: SharesGenerator<D, D2>,

    // scratch space
    scratch: Vec<D::Batch>,
    scratch2: Vec<Vec<D2::Batch>>,

    corrections_prg: Vec<PRG>,
    eda_shares: Vec<D::Sharing>,
    eda_2_shares: Vec<Vec<D2::Sharing>>,
}

impl<D: Domain, D2: Domain> PreprocessingExecution<D, D2> {
    pub fn prove_branch(
        &self,
        branches: &[Vec<D::Batch>],
        index: usize,
    ) -> (Vec<D::Batch>, MerkleSetProof) {
        let mut prgs: Vec<PRG> = self
            .player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_BRANCH_MASK, seed)))
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
        TreePRF::expand_full(&mut player_seeds, root);

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        let corrections_prg = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
            .collect();

        let shares = SharesGenerator::new(&player_seeds[..]);

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        PreprocessingExecution {
            root,
            player_seeds,
            shares,
            scratch: vec![D::Batch::ZERO; D::PLAYERS],
            scratch2: vec![vec![D2::Batch::ZERO; D::PLAYERS]; 2],
            masks: VecMap::new(),
            masks_2: VecMap::new(),
            corrections_prg: corrections_prg,
            eda_shares: Vec::with_capacity(D::Batch::DIMENSION),
            eda_2_shares: Vec::with_capacity(D2::Batch::DIMENSION),
        }
    }

    #[inline(always)]
    fn generate<CW: Writer<D::Batch>>(
        &mut self,
        eda_bits: &mut Vec<Vec<D2::Sharing>>,
        eda_composed: &mut Vec<D::Sharing>,
        corrections: &mut CW, // player 0 corrections
        batch_eda: &mut Vec<Vec<D2::Batch>>,
        len: usize) {
        debug_assert_eq!(self.eda_2_shares[0].len(), D2::Batch::DIMENSION);
        debug_assert!(self.shares.eda_2.is_empty());

        // transpose sharings into per player batches
        batch_eda.resize(len, vec![D2::Batch::ZERO; D2::Sharing::DIMENSION]);
        for pos in 0..len {
            D2::convert_inv(&mut batch_eda[pos][..], &self.eda_2_shares[pos][..]);
        }
        self.eda_2_shares.clear();

        // generate 3 batches of shares for every player
        let mut eda = vec![D::Batch::ZERO; len];
        let mut eda_out = D::Batch::ZERO;

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..D::PLAYERS {
            let corr = D::Batch::gen(&mut self.corrections_prg[i]);
            for j in 0..len {
                eda[j] = eda[j] + convert_bit_domain::<D2, D>(batch_eda[j][i]).unwrap();
                self.scratch2[j][i] = self.scratch2[j][i] + batch_eda[j][i];
            }
            eda_out = eda_out + corr;
            self.scratch[i] = corr + self.shares.eda.batches()[i];
        }

        let two = D::Batch::ONE + D::Batch::ONE;
        let mut pow_two = D::Batch::ONE;
        let mut arith = D::Batch::ZERO;
        for j in 0..len {
            arith = arith + pow_two * eda[j];
            pow_two = pow_two * two;
        }
        // correct shares for player 0 (correction bits)
        let delta = arith - eda_out;

        // write correction batch (player 0 correction bits)
        // for the pre-processing phase, the writer will simply be a hash function.
        corrections.write(delta);

        // correct eda (in parallel)
        self.scratch[0] = self.scratch[0] + delta;

        // check that ab_gamma is a sharing of sum_{i=0}^{m} e*2^i + \gamma
        #[cfg(test)]
            {
                let mut eda_comp = D::Batch::ZERO;
                let mut eda_composed_recons = D::Batch::ZERO;
                for i in 0..D::PLAYERS {
                    eda_comp = eda_comp + self.shares.eda.batches()[i];
                    eda_composed_recons = eda_composed_recons + self.scratch[i];
                }
                assert_eq!(arith + eda_comp, eda_composed_recons);
            }

        // transpose into shares
        if eda_bits.len() != len {
            eda_bits.resize(len, Vec::with_capacity(D2::Batch::DIMENSION));
        }
        for j in 0..len {
            let start = eda_bits[j].len();
            eda_bits[j].resize(start + D2::Batch::DIMENSION, D2::Sharing::ZERO);
            D2::convert(&mut eda_bits[j][start..], &self.scratch2[j][..]);
        }

        let start = eda_composed.len();
        eda_composed.resize(start + D::Batch::DIMENSION, D::Sharing::ZERO);
        D::convert(&mut eda_composed[start..], &self.scratch[..]);

        debug_assert_eq!(self.eda_2_shares.len(), 0);
    }

    pub fn process<CW: Writer<D::Batch>, MW: Writer<D::Sharing>, MW2: Writer<D2::Sharing>>(
        &mut self,
        program: &[ConnectionInstruction], // program slice
        corrections: &mut CW,               // player 0 corrections
        masks: &mut MW,                     // masks for online phase
        masks2: &mut MW2,                     // masks for online phase
        eda_bits: &mut Vec<Vec<D2::Sharing>>,     // eda bits in boolean form
        eda_composed: &mut Vec<D::Sharing>,     // eda bits composed in arithmetic form
    ) {
        //TODO: set outer dimension to size of target field
        let mut m = 1;
        let mut batch_eda = vec![vec![D2::Batch::ZERO; D2::PLAYERS]; m];

        for step in program {
            match *step {
                ConnectionInstruction::Input(dst) => {
                    //TODO: take mask from first circuit output
                    let mask = self.shares.input.next();
                    self.masks.set(dst, mask);
                    masks.write(mask);
                    let mask2 = self.shares.input_2.next();
                    self.masks_2.set(dst, mask2);
                    masks2.write(mask2);
                }
                ConnectionInstruction::AToB(dst, src) => {
                    if dst.len() > m {
                        m = dst.len()
                    }
                    self.eda_2_shares.resize(dst.len(), Vec::with_capacity(D2::Batch::DIMENSION));
                    // assign output masks and push to the deferred eda stack
                    for (pos, &_dst) in dst.iter().enumerate() {
                        let mask = self.shares.eda_2.next();
                        self.masks_2.set(_dst, mask.clone());
                        self.eda_2_shares[pos].push(mask.clone());
                        masks2.write(mask);
                    }

                    // get masks from input?
                    // let mask = self.masks.get(dst);
                    // self.eda_shares.push(mask.clone());

                    // if the batch is full, generate next batch of edaBits shares
                    if self.eda_2_shares[0].len() == D2::Batch::DIMENSION {
                        self.generate(eda_bits, eda_composed, corrections, &mut batch_eda, dst.len());
                    }
                }
                ConnectionInstruction::BToA(dst, src) => {
                    if src.len() > m {
                        m = src.len()
                    }
                    self.eda_2_shares.resize(src.len(), Vec::with_capacity(D2::Batch::DIMENSION));
                    // push the input masks to the deferred eda stack
                    for (pos, &_src) in src.iter().enumerate() {
                        let mask = self.masks_2.get(_src);
                        self.eda_2_shares[pos].push(mask.clone());
                    }

                    // assign mask to output
                    let mask = self.shares.eda.next();
                    self.masks.set(dst, mask);
                    masks.write(mask);

                    // if the batch is full, generate next batch of edaBits shares
                    if self.eda_2_shares[0].len() == D2::Batch::DIMENSION {
                        self.generate(eda_bits, eda_composed, corrections, &mut batch_eda, src.len());
                    }
                }
                ConnectionInstruction::Output(src) => {
                    masks.write(self.masks.get(src));
                }
            }
        }

        // pad final eda batch if needed
        if !self.eda_2_shares[0].is_empty() {
            self.eda_2_shares.resize(m, Vec::with_capacity(D2::Batch::DIMENSION));
            for i in 0..m {
                self.eda_2_shares[i].resize(D2::Batch::DIMENSION, D2::Sharing::ZERO);
            }
            self.shares.eda_2.empty();
            self.generate(eda_bits, eda_composed, corrections, &mut batch_eda, m);
        }
    }
}
