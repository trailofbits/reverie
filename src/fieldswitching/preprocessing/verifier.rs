use crate::{ConnectionInstruction};
use crate::algebra::{Domain, RingElement, RingModule, Samplable};
use crate::consts::{CONTEXT_RNG_CORRECTION};
use crate::crypto::{hash, Hash, Hasher, kdf, KEY_SIZE, PRG, RingHasher, TreePRF};
use crate::fieldswitching::preprocessing::util::convert_bit_domain;
use crate::util::{VecMap, Writer};

use super::util::SharesGenerator;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain, D2: Domain> {
    // commitments to player random
    commitments: Vec<Hash>,

    // interpreter state
    masks: VecMap<D::Sharing>,
    masks_2: VecMap<D2::Sharing>,
    eda_shares: Vec<D::Sharing>,
    eda_2_shares: Vec<Vec<D2::Sharing>>,

    // sharings
    shares: SharesGenerator<D, D2>,

    corrections_prg: Vec<PRG>,
    corrections: RingHasher<D::Batch>, // player 0 corrections
}

impl<D: Domain, D2: Domain> PreprocessingExecution<D, D2> {
    pub fn new(root: [u8; KEY_SIZE]) -> Self {
        // expand repetition seed into per-player seeds
        let mut player_seeds: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; D::PLAYERS];
        TreePRF::expand_full(&mut player_seeds, root);

        // commit to per-player randomness
        let commitments: Vec<Hash> = player_seeds.iter().map(|seed| hash(seed)).collect();

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        PreprocessingExecution {
            commitments,
            shares: SharesGenerator::new(&player_seeds[..]),
            eda_shares: Vec::with_capacity(D::Batch::DIMENSION),
            eda_2_shares: Vec::with_capacity(D2::Batch::DIMENSION),
            masks: VecMap::new(),
            masks_2: VecMap::new(),
            corrections_prg: player_seeds
                .iter()
                .map(|seed| PRG::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
                .collect(),
            corrections: RingHasher::new(),
        }
    }

    #[inline(always)]
    fn generate(&mut self, batch_eda: &mut Vec<Vec<D2::Batch>>, len: usize) {
        debug_assert_eq!(self.eda_2_shares[0].len(), D2::Batch::DIMENSION);
        debug_assert!(self.shares.eda_2.is_empty());

        // transpose sharings into per player batches
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
            }
            eda_out = eda_out + corr;
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
        self.corrections.write(delta);

        debug_assert_eq!(self.eda_2_shares.len(), 0);
    }

    pub fn prove(&mut self, program: &[ConnectionInstruction]) {
        //TODO: set outer dimension to size of target field
        let m = 2;
        let mut batch_eda = vec![vec![D2::Batch::ZERO; D2::PLAYERS]; m];

        for step in program {
            match *step {
                ConnectionInstruction::AToB(dst, src) => {
                    self.eda_2_shares.resize(dst.len(), Vec::with_capacity(D2::Batch::DIMENSION));
                    // assign output masks and push to the deferred eda stack
                    for (pos, &_dst) in dst.iter().enumerate() {
                        let mask = self.shares.eda_2.next();
                        self.masks_2.set(_dst, mask.clone());
                        self.eda_2_shares[pos].push(mask.clone());
                    }

                    // get masks from input?
                    // let mask = self.masks.get(dst);
                    // self.eda_shares.push(mask.clone());

                    // if the batch is full, generate next batch of edaBits shares
                    if self.eda_2_shares[0].len() == D2::Batch::DIMENSION {
                        self.generate(&mut batch_eda, dst.len());
                    }
                }
                ConnectionInstruction::BToA(dst, src) => {
                    self.eda_2_shares.resize(src.len(), Vec::with_capacity(D2::Batch::DIMENSION));
                    // push the input masks to the deferred eda stack
                    for (pos, &_src) in src.iter().enumerate() {
                        let mask = self.masks_2.get(_src);
                        self.eda_2_shares[pos].push(mask.clone());
                    }

                    // assign mask to output
                    self.masks.set(dst, self.shares.eda.next());

                    // if the batch is full, generate next batch of edaBits shares
                    if self.eda_2_shares[0].len() == D2::Batch::DIMENSION {
                        self.generate(&mut batch_eda, src.len());
                    }
                }
            }
        }

        // pad final eda batch if needed
        if !self.eda_2_shares[0].is_empty() {
            self.eda_2_shares.resize(m, Vec::with_capacity(D2::Batch::DIMENSION));
            //TODO: make len flexible
            for i in 0..m {
                self.eda_2_shares[i].resize(D2::Batch::DIMENSION, D2::Sharing::ZERO);
            }
            self.shares.eda_2.empty();
            self.generate(&mut batch_eda, m);
        }
    }

    pub fn done(mut self) -> (Hash, Vec<Hash>) {
        // add corrections and Merkle root to player 0 commitment
        self.commitments[0] = {
            let mut comm = Hasher::new();
            comm.update(self.commitments[0].as_bytes());
            comm.finalize()
        };

        // merge player commitments with branch tree commitment
        let mut union = Hasher::new();
        for comm in self.commitments.iter() {
            union.update(comm.as_bytes());
        }

        // return player commitments
        (union.finalize(), self.commitments)
    }
}
