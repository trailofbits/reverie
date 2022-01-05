use num_traits::Zero;

use super::*;
#[cfg(debug_assertions)]
use crate::algebra::EqIndex;
use crate::algebra::{Domain, Hashable, Pack, PackSelected};
use crate::crypto::hash::PackedHasher;
use crate::generator::ShareGen;
use crate::proof::OpenOnline;
use crate::PACKED;

pub struct VerifierTranscriptOnline<D: Domain> {
    #[cfg(debug_assertions)]
    omit: [usize; PACKED],
    share_gen: Box<ShareGen<D>>,
    hash_online: PackedHasher,
    hash_preprocess: PackedHasher,
    recons: std::vec::IntoIter<D::Share>,
    corrs: std::vec::IntoIter<D::Recon>,
    inputs: std::vec::IntoIter<D::Recon>,
    okay: bool,
}

impl<D: Domain> VerifierTranscriptOnline<D> {
    pub(crate) fn new(open_proofs: &[OpenOnline; PACKED]) -> Self {
        //
        #[cfg(debug_assertions)]
        {
            for proof in open_proofs.iter().take(PACKED) {
                let omit = proof.omit as usize;
                debug_assert!(omit < PLAYERS);
                debug_assert_eq!(proof.seeds[omit], [0u8; KEY_SIZE]);
            }
        }

        // deserialize the corrections (pre-preprocessing)
        let mut corrs: Vec<D::Recon> = vec![];
        D::Recon::unpack(
            &mut corrs,
            &[
                &open_proofs[0].corrs[..],
                &open_proofs[1].corrs[..],
                &open_proofs[2].corrs[..],
                &open_proofs[3].corrs[..],
                &open_proofs[4].corrs[..],
                &open_proofs[5].corrs[..],
                &open_proofs[6].corrs[..],
                &open_proofs[7].corrs[..],
            ],
        );

        // deserialize masked input
        let mut inputs: Vec<D::Recon> = vec![];
        D::Recon::unpack(
            &mut inputs,
            &[
                &open_proofs[0].inputs[..],
                &open_proofs[1].inputs[..],
                &open_proofs[2].inputs[..],
                &open_proofs[3].inputs[..],
                &open_proofs[4].inputs[..],
                &open_proofs[5].inputs[..],
                &open_proofs[6].inputs[..],
                &open_proofs[7].inputs[..],
            ],
        );

        // deserialize the broadcast messages from the unopened player
        let mut recons: Vec<D::Share> = vec![];
        let omit = [
            open_proofs[0].omit as usize,
            open_proofs[1].omit as usize,
            open_proofs[2].omit as usize,
            open_proofs[3].omit as usize,
            open_proofs[4].omit as usize,
            open_proofs[5].omit as usize,
            open_proofs[6].omit as usize,
            open_proofs[7].omit as usize,
        ];

        D::Share::unpack_selected(
            &mut recons,
            &[
                &open_proofs[0].recons[..],
                &open_proofs[1].recons[..],
                &open_proofs[2].recons[..],
                &open_proofs[3].recons[..],
                &open_proofs[4].recons[..],
                &open_proofs[5].recons[..],
                &open_proofs[6].recons[..],
                &open_proofs[7].recons[..],
            ],
            omit,
        );

        Self {
            #[cfg(debug_assertions)]
            omit,
            share_gen: Box::new(ShareGen::new(
                &[
                    open_proofs[0].seeds,
                    open_proofs[1].seeds,
                    open_proofs[2].seeds,
                    open_proofs[3].seeds,
                    open_proofs[4].seeds,
                    open_proofs[5].seeds,
                    open_proofs[6].seeds,
                    open_proofs[7].seeds,
                ],
                omit,
            )),
            hash_online: PackedHasher::new(),
            hash_preprocess: PackedHasher::new(),
            recons: recons.into_iter(),
            inputs: inputs.into_iter(),
            corrs: corrs.into_iter(),
            okay: true,
        }
    }
}

impl<D: Domain> Transcript<D> for VerifierTranscriptOnline<D> {
    fn input(&mut self) -> Wire<D> {
        let corr = self.inputs.next().unwrap_or_default();
        corr.hash(&mut self.hash_online);
        Wire {
            mask: self.share_gen.next(),
            corr,
        }
    }

    fn online_hash(&self) -> [Hash; PACKED] {
        self.hash_online.finalize()
    }

    fn preprocess_hash(&self) -> [Hash; PACKED] {
        self.hash_preprocess.finalize()
    }

    fn reconstruct(&mut self, mask: D::Share) -> D::Recon {
        // sanity check: ensure that the share of the unopened player is set to zero
        #[cfg(debug_assertions)]
        {
            for i in 0..PACKED {
                debug_assert!(
                    D::Share::compare_index(
                        i,
                        self.omit[i],
                        &mask,
                        i,
                        self.omit[i],
                        &D::Share::zero()
                    ),
                    "omit[{}] = {:?}, mask = {:?}",
                    i,
                    self.omit[i],
                    &mask
                );
            }
        }

        // add share of unopened player
        let msg = self.recons.next().unwrap_or_default();
        let mask = mask + msg;
        mask.hash(&mut self.hash_online);
        D::reconstruct(&mask)
    }

    fn correction(&mut self, _corr: D::Recon) -> D::Recon {
        // ignore input and use provided correction
        let corr = self.corrs.next().unwrap_or_default();
        corr.hash(&mut self.hash_preprocess);
        corr
    }

    fn zero_check(&mut self, recon: D::Recon) {
        self.okay &= recon.is_zero();
    }

    fn new_mask(&mut self) -> D::Share {
        self.share_gen.next()
    }
}
