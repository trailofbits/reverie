use super::*;

use crate::util::Writer;
use crate::Instruction;

use rand_core::RngCore;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct BeaverStack<
    'a,
    'b,
    D: Domain,
    R: RngCore,
    W: Writer<D::Batch>,
    const N: usize,
    const O: bool,
> {
    next: usize,
    share_a: Vec<D::Sharing>, // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
    share_g: Vec<D::Sharing>, // gamma sharings (output)
    batch_g: [D::Batch; N],   // gamma batch
    rngs: &'b mut [R; N],     // rngs
    zero: &'a mut W,          // writer for player 0 shares
}

impl<'a, 'b, D: Domain, R: RngCore, W: Writer<D::Batch>, const N: usize, const O: bool>
    BeaverStack<'a, 'b, D, R, W, N, O>
{
    #[inline(always)]
    fn new_gamma(&mut self) {
        // generate output maskings and reconstruct it
        for i in 0..N {
            self.batch_g[i] = D::Batch::gen(&mut self.rngs[i]);
        }

        // transpose gamma batches into gamma sharings
        D::convert(&mut self.share_g[..], &self.batch_g[..]);
    }

    pub fn new(zero: &'a mut W, rngs: &'b mut [R; N]) -> Self {
        let mut ins = Self {
            next: 0,
            rngs,
            batch_g: [D::Batch::ZERO; N],
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_b: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            zero,
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

        // generate 3 batches of shares for every player
        let mut a = D::Batch::ZERO;
        let mut b = D::Batch::ZERO;
        let mut c = D::Batch::ZERO;

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..N {
            // reconstruct a, b and c
            batches_c[i] = D::Batch::gen(&mut self.rngs[i]);
            a = a + batches_a[i];
            b = b + batches_b[i];
            c = c + batches_c[i];

            // generate shares of [\lambda_{ab}] + [\lambda_\gamma]
            batches_gab[i] = batches_c[i] + self.batch_g[i];
        }

        // correct shares for player 0 (correction bits)
        let delta = a * b - c;
        batches_c[0] = batches_c[0] + delta;

        // return ab_gamma shares if online execution
        if O {
            debug_assert_eq!(ab_gamma.len(), D::Batch::DIMENSION);
            batches_gab[0] = batches_gab[0] + delta;
            D::convert(ab_gamma, &batches_gab);
        }

        // write player0 correction bits
        self.zero.write(&delta);

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
pub struct PreprocessingExecution<
    'a,
    'b,
    D: Domain,
    W: Writer<D::Batch>,
    R: RngCore,
    const N: usize,
    const O: bool,
> {
    beaver: BeaverStack<'a, 'b, D, R, W, N, O>,
    pub masks: Vec<D::Sharing>,
}

impl<'a, 'b, D: Domain, W: Writer<D::Batch>, R: RngCore, const N: usize, const O: bool>
    PreprocessingExecution<'a, 'b, D, W, R, N, O>
{
    pub fn new(rngs: &'b mut [R; N], zero: &'a mut W, inputs: usize) -> Self {
        // compute then number of input masking batches/shares generated
        let num_batches = (inputs + D::Batch::DIMENSION - 1) / D::Batch::DIMENSION;
        let num_shares = num_batches * D::Batch::DIMENSION;
        debug_assert!(num_shares >= inputs);

        // generate input masks
        let mut masks: Vec<D::Sharing> = vec![D::Sharing::ZERO; num_shares];
        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
        for i in 0..num_batches {
            for j in 0..N {
                batches[j] = D::Batch::gen(&mut rngs[j]);
            }
            D::convert(&mut masks[i * D::Batch::DIMENSION..], &batches[..]);
        }

        // discard the excess input masks
        masks.truncate(inputs);

        // return pre-processing with input wire masks set
        PreprocessingExecution {
            beaver: BeaverStack::new(zero, rngs),
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
            O == false || ab_gamma.len() == D::Batch::DIMENSION,
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
