mod instr;
pub mod prover;
mod verifier;

pub use instr::Instruction;
pub use prover::Proof;

use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{View, ViewRNG};

use crate::algebra::{Domain, RingElement, Samplable};

use blake3::Hash;
use rand_core::RngCore;

struct SharingRng<D: Domain, R: RngCore, const N: usize> {
    rngs: Box<[R; N]>,
    sharings: Vec<D::Sharing>,
}

impl<D: Domain, R: RngCore, const N: usize> SharingRng<D, R, N> {
    pub fn new(rngs: Box<[R; N]>) -> SharingRng<D, R, N> {
        SharingRng {
            rngs,
            sharings: Vec::with_capacity(D::SHARINGS_PER_BATCH),
        }
    }

    pub fn gen(&mut self) -> D::Sharing {
        match self.sharings.pop() {
            Some(sharing) => sharing,
            None => {
                // generate a batch of shares for every player
                let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
                self.sharings
                    .resize(D::SHARINGS_PER_BATCH, D::Sharing::ZERO);
                for i in 0..N {
                    batches[i] = D::Batch::gen(&mut self.rngs[i]);
                }

                // transpose batches into sharings
                D::convert(&mut self.sharings[..], &batches[..]);

                // return the first sharing
                self.sharings.pop().unwrap()
            }
        }
    }
}
