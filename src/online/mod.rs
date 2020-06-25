mod instr;
pub mod prover;
mod verifier;

pub use instr::Instruction;

use crate::consts::*;
use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{Scope, View, ViewRNG};

use crate::util::*;

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

/*
impl<B: RingBatch, R: RngCore, N: ArrayLength<PlayerState<B, R>>> Execution<B, R, N> {
    fn step(&mut self, ins: Instruction<B::Element>) -> Option<()> {
        match ins {
            // addition of public constant
            Instruction::AddConst(dst, src, c) => {
                // add to the masked wire
                let wire = self.public.wires.get(src)?;
                self.public.wires.set(dst, wire + c);

                // successfully executed
                Some(())
            }

            // multiplication by public constant
            Instruction::MulConst(dst, src, c) => {
                // multiply the masked value by the constant
                let wire = self.public.wires.get(src)?;
                self.public.wires.set(dst, wire * c);

                // multiply all the masks by the constant
                for player in self.players.iter() {
                    let mask = player.masks.get(src)?;
                    player.masks.set(dst, mask * c);
                }

                // successfully executed
                Some(())
            }

            // addition of secret wires
            Instruction::Add(dst, src1, src2) => {
                // add the masked values
                let wire1 = self.public.wires.get(src1)?;
                let wire2 = self.public.wires.get(src2)?;
                self.public.wires.set(dst, wire1 + wire2);

                // add the masks
                for player in &mut self.players {
                    let mask1 = player.masks.get(src1)?;
                    let mask2 = player.masks.get(src2)?;
                    player.masks.set(dst, mask1 + mask2);
                }

                // successfully executed
                Some(())
            }

            // multiplication of secret wires
            Instruction::Mul(dst, src1, src2) => {
                // fetch the next Beaver triple
                let corr = self.corrections.get(self.next_corr)?;

                let wire1 = self.public.wires.get(src1)?;
                let wire2 = self.public.wires.get(src2)?;

                for player in &mut self.players {
                    wire1 *
                }

                Some(())
            }

            _ => unimplemented!(),
        }
    }
}

struct VerifierExecution<B: RingBatch, O: ArrayLength<PlayerState<B, R>>, R> {
    // views of opened players
    players: GenericArray<PlayerState<B, R>, O>,

    // messages sent by the hidden player
    messages: RingArray<B>,

    // masked wire values (initially holds the masked)
    wires: RingVector<B>,

    // broadcast channel (initially empty)
    broadcast: RingVector<B>,
}

impl<B: RingBatch, R> PlayerState<B, R> {
    /// Step takes:
    ///
    /// 1. The current state of the player.
    /// 2. The public state (broadcast channel, holding reconstructed elements).
    /// 3. The next instruction.
    ///
    /// Then mutates the local state of the player
    /// and optionally returns a message (single ring element) to broadcast.
    pub fn step(
        &mut self,
        public: &PublicState<B>,
        ins: Instruction<B::Element>,
    ) -> Option<B::Element> {
        match ins {
            // addition of constant is a noop outside of player 0
            Instruction::AddConst(dst, src, value) => None,
            // every player locally adds the shares
            Instruction::Add(dst, src1, src2) => {
                let v1 = self.masks.get(src1.into()).unwrap();
                let v2 = self.masks.get(src2.into()).unwrap();
                self.masks.set(dst.into(), v1 + v2);
                None
            }
            // every player locally multiplies his share by the constant
            Instruction::MulConst(dst, src, value) => {
                let old = self.masks.get(src.into()).unwrap();
                self.masks.set(dst.into(), old * value);
                None
            }
            Instruction::Input(dst) => None,
            Instruction::Ouput(src) => None,
            Instruction::Mul(dst, src1, src) => None,
        }
    }
}

struct OnlineProof<B: RingBatch, NT: PowerOfTwo + Unsigned> {
    // masked inputs
    inputs: RingArray<B>,

    // broadcast messages from hidden player
    messages: RingArray<B>,

    // correction bits (non-zero length if player 0 opened)
    corrections: RingArray<B>,

    // random-tapes of opened players
    random: TreePRF<NT>,

    // transcript hash for hidden view
    hidden: Hash,
}
*/
