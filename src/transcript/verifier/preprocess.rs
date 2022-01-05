use num_traits::Zero;

use super::*;
use crate::algebra::{Domain, Hashable};
use crate::crypto::hash::PackedHasher;
use crate::generator::ShareGen;
use crate::proof::OpenPreprocessing;
use crate::PACKED;

pub struct VerifierTranscriptPreprocess<D: Domain> {
    share_gen: Box<ShareGen<D>>,
    comms_online: [Hash; PACKED],
    hash_preprocess: PackedHasher,
}

impl<D: Domain> VerifierTranscriptPreprocess<D> {
    pub(crate) fn new(proofs: &[OpenPreprocessing; PACKED]) -> Self {
        let comms_online = [
            proofs[0].comm_online.into(),
            proofs[1].comm_online.into(),
            proofs[2].comm_online.into(),
            proofs[3].comm_online.into(),
            proofs[4].comm_online.into(),
            proofs[5].comm_online.into(),
            proofs[6].comm_online.into(),
            proofs[7].comm_online.into(),
        ];
        let seeds = [
            proofs[0].seed,
            proofs[1].seed,
            proofs[2].seed,
            proofs[3].seed,
            proofs[4].seed,
            proofs[5].seed,
            proofs[6].seed,
            proofs[7].seed,
        ];
        Self {
            comms_online,
            share_gen: share_gen_from_rep_seeds(&seeds),
            hash_preprocess: PackedHasher::new(),
        }
    }
}

impl<D: Domain> Transcript<D> for VerifierTranscriptPreprocess<D> {
    fn input(&mut self) -> Wire<D> {
        let mask = self.share_gen.next();
        Wire {
            mask,
            corr: D::Recon::zero(), // any junk
        }
    }

    fn online_hash(&self) -> [Hash; PACKED] {
        self.comms_online
    }

    fn preprocess_hash(&self) -> [Hash; PACKED] {
        self.hash_preprocess.finalize()
    }

    fn reconstruct(&mut self, _mask: D::Share) -> D::Recon {
        D::Recon::zero() // any junk
    }

    fn correction(&mut self, corr: D::Recon) -> D::Recon {
        corr.hash(&mut self.hash_preprocess);
        corr
    }

    fn zero_check(&mut self, _recon: D::Recon) {
        // NOP: the online phase will be foobar
    }

    fn new_mask(&mut self) -> D::Share {
        self.share_gen.next()
    }
}
