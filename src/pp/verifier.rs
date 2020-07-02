use super::*;

use crate::Instruction;

use rand_core::RngCore;

/// Implementation of pre-processing phase used by the prover during online execution
struct BeaverStack<'a, D: Domain, R: RngCore, const N: usize> {
    next: usize,
    offset: usize,
    omitted: usize,
    broadcast: Vec<D::Batch>,   // omitted player broadcast messages
    corrections: Vec<D::Batch>, // player zero corrections
    share_a: Vec<D::Sharing>,   // beta sharings (from input)
    share_b: Vec<D::Sharing>,   // alpha sharings (from input)
    share_g: Vec<D::Sharing>,   // gamma sharings (output)
    batch_g: [D::Batch; N],     // gamma batch
    rngs: &'a mut [R; N],       // rngs
}

impl<'a, D: Domain, R: RngCore, const N: usize> BeaverStack<'a, D, R, N> {
    #[inline(always)]
    fn new_gamma(&mut self) {
        // generate output maskings and reconstruct it
        for i in 0..N {
            if i != self.omitted {
                self.batch_g[i] = D::Batch::gen(&mut self.rngs[i]);
            }
        }

        // transpose gamma batches into gamma sharings
        D::convert(&mut self.share_g[..], &self.batch_g[..]);
    }

    pub fn new(
        rngs: &'a mut [R; N],
        corrections: Vec<D::Batch>,
        broadcast: Vec<D::Batch>,
        omitted: usize,
    ) -> Self {
        debug_assert!(corrections.len() == 0 || omitted != 0);
        let mut ins = Self {
            next: 0,
            offset: 0,
            rngs,
            omitted,
            broadcast,
            corrections,
            batch_g: [D::Batch::ZERO; N],
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_b: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
        };
        ins.new_gamma();
        ins
    }

    #[inline(always)]
    pub fn generate(&mut self, ab_gamma: &mut [D::Sharing]) {
        let mut batches_a: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_b: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_c: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_gab: [D::Batch; N] = [D::Batch::ZERO; N];

        // transpose sharings into per player batches
        D::convert_inv(&mut batches_a[..], &self.share_a[..]);
        D::convert_inv(&mut batches_b[..], &self.share_b[..]);

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..N {
            if i != self.omitted {
                // generate shares for the included players from RNG
                batches_c[i] = D::Batch::gen(&mut self.rngs[i]);
                batches_gab[i] = batches_c[i] + self.batch_g[i];
            } else {
                // set ab_gamma batch for omitted player to the broadcast message from the exported transcript
                // NOTE: This works because the masks for the omitted player is set to zero.
                batches_gab[i] = self.broadcast[self.offset];
            }
        }

        // correct shares for player 0 (correction bits)
        if self.omitted == 0 {
            let delta = self.corrections[self.offset];
            batches_c[0] = batches_c[0] + delta;
            batches_gab[0] = batches_gab[0] + delta;
        }

        // return ab_gamma shares if online execution
        debug_assert_eq!(ab_gamma.len(), D::Batch::DIMENSION);
        D::convert(ab_gamma, &batches_gab);

        // get new batch of gamma shares
        self.new_gamma();

        // reset input pointer
        self.next = 0;
    }

    #[inline(always)]
    pub fn push(&mut self, a: D::Sharing, b: D::Sharing) -> D::Sharing {
        self.share_a[self.next] = a;
        self.share_b[self.next] = b;
        let gamma = self.share_g[self.next];
        self.next += 1;
        gamma
    }
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<'a, D: Domain, R: RngCore, const N: usize> {
    beaver: BeaverStack<'a, D, R, N>,
    pub masks: Vec<D::Sharing>,
}

impl<'a, D: Domain, R: RngCore, const N: usize> PreprocessingExecution<'a, D, R, N> {
    pub fn new(
        rngs: &'a mut [R; N],
        inputs: usize,
        omitted: usize,
        broadcast: Vec<D::Batch>,
        corrections: Vec<D::Batch>,
    ) -> Self {
        // compute then number of input masking batches/shares generated
        let num_batches = (inputs + D::Batch::DIMENSION - 1) / D::Batch::DIMENSION;
        let num_shares = num_batches * D::Batch::DIMENSION;
        debug_assert!(num_shares >= inputs);

        // generate input masks
        let mut masks: Vec<D::Sharing> = vec![D::Sharing::ZERO; num_shares];
        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
        for i in 0..num_batches {
            for j in 0..N {
                if omitted != j {
                    batches[j] = D::Batch::gen(&mut rngs[j]);
                }
            }
            D::convert(&mut masks[i * D::Batch::DIMENSION..], &batches[..]);
        }

        // discard the excess input masks
        masks.truncate(inputs);

        // return pre-processing with input wire masks set
        PreprocessingExecution {
            beaver: BeaverStack::new(rngs, corrections, broadcast, omitted),
            masks,
        }
    }

    #[inline(always)]
    fn set(&mut self, idx: usize, val: D::Sharing) {
        if idx >= self.masks.len() {
            self.masks.resize(idx + 1, D::Sharing::ZERO);
        }
        debug_assert!(idx < self.masks.len());
        self.masks[idx] = val;
    }

    #[inline(always)]
    pub fn next_batch(
        &mut self,
        ab_gamma: &mut [D::Sharing],
        look_ahead: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    ) -> usize {
        // check that it is aligned (many only arise due to buggy programming)
        debug_assert_eq!(
            self.beaver.next, 0,
            "beaver stack is not empty at the start of next_batch"
        );
        debug_assert!(
            ab_gamma.len() == D::Batch::DIMENSION,
            "a * b + \\gamma share buffer invalid dimension"
        );

        // look forward in program until executed enough multiplications
        for (i, ins) in look_ahead.iter().enumerate() {
            match ins {
                Instruction::AddConst(_dst, _src, _c) => (), // noop in pre-processing
                Instruction::MulConst(dst, src, c) => {
                    // resolve input
                    let sw = self.masks[*src];

                    // let the single element act on the vector
                    self.set(*dst, sw.action(*c));
                }
                Instruction::Add(dst, src1, src2) => {
                    // resolve inputs
                    let sw1 = self.masks[*src1];
                    let sw2 = self.masks[*src2];

                    // compute the sum and set output wire
                    self.set(*dst, sw1 + sw2);
                }
                Instruction::Mul(dst, src1, src2) => {
                    // resolve inputs
                    let sw1 = self.masks[*src1];
                    let sw2 = self.masks[*src2];

                    // push the masks to the Beaver stack
                    debug_assert!(self.beaver.next < D::Batch::DIMENSION);
                    let gamma = self.beaver.push(sw1, sw2);

                    // assign mask to output
                    self.set(*dst, gamma);

                    // check if current batch is full
                    if self.beaver.next == D::Batch::DIMENSION {
                        self.beaver.generate(ab_gamma);
                        debug_assert_eq!(self.beaver.next, 0);
                        return i + 1;
                    }
                }
                Instruction::Output(_src) => (),
            }
        }

        // we are at the end of the program look_ahead
        // push final dummy values to the Beaver stack.
        while self.beaver.next < D::Batch::DIMENSION {
            self.beaver.push(D::Sharing::ZERO, D::Sharing::ZERO);
        }
        self.beaver.generate(ab_gamma);
        look_ahead.len()
    }
}

#[cfg(test)]
mod benchmark {
    use super::*;
    use crate::algebra::gf2::GF2P8;
    use crate::crypto::RingHasher;

    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    use test::{black_box, Bencher};
}
