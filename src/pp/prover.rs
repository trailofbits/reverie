use super::*;

use crate::util::Writer;
use crate::Instruction;

use rand_core::RngCore;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<
    'a,
    'b,
    'c,
    D: Domain,
    R: RngCore,
    W: Writer<D::Batch>,
    const N: usize,
    const O: bool,
> {
    next: usize,
    program: &'c [Instruction<<D::Sharing as RingModule>::Scalar>],
    masks: VecMap<D::Sharing>,
    share_ab_gamma: Vec<D::Sharing>,
    share_a: Vec<D::Sharing>, // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
    share_g: Vec<D::Sharing>, // gamma sharings (output)
    batch_g: [D::Batch; N],   // gamma batch
    rngs: &'b mut [R; N],     // rngs
    corrections: &'a mut W,   // writer for player 0 shares
}

impl<'a, 'b, 'c, D: Domain, W: Writer<D::Batch>, R: RngCore, const N: usize, const O: bool>
    PreprocessingExecution<'a, 'b, 'c, D, R, W, N, O>
{
    pub fn new(
        rngs: &'b mut [R; N],
        corrections: &'a mut W,
        inputs: usize,
        program: &'c [Instruction<<D::Sharing as RingModule>::Scalar>],
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
                batches[j] = D::Batch::gen(&mut rngs[j]);
            }
            D::convert(&mut masks[i * D::Batch::DIMENSION..], &batches[..]);
        }

        // discard the excess input masks
        masks.truncate(inputs);

        // return pre-processing with input wire masks set
        let mut ins = PreprocessingExecution {
            next: 0,
            rngs,
            program,
            batch_g: [D::Batch::ZERO; N],
            share_ab_gamma: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_b: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            corrections,
            masks: masks.into(),
        };

        // generate the initial batch
        ins.pack_batch();
        ins
    }

    #[inline(always)]
    fn generate(&mut self) {
        let mut batches_a: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_b: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_c: [D::Batch; N] = [D::Batch::ZERO; N];

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
        }

        // correct shares for player 0 (correction bits)
        let delta = a * b - c;
        batches_c[0] = batches_c[0] + delta;

        // sanity check in tests
        #[cfg(test)]
        {
            let mut share_c = vec![D::Sharing::ZERO; D::Batch::DIMENSION];
            D::convert(&mut share_c[..], &batches_c);
            for i in 0..D::Batch::DIMENSION {
                debug_assert_eq!(
                    share_c[i].reconstruct(),
                    self.share_a[i].reconstruct() * self.share_b[i].reconstruct()
                )
            }
        }

        // compute ab_gamma shares if online execution
        if O {
            let mut batches_gab: [D::Batch; N] = [D::Batch::ZERO; N];
            for i in 0..N {
                batches_gab[i] = batches_c[i] + self.batch_g[i];
            }
            D::convert(&mut self.share_ab_gamma[..], &batches_gab);
        }

        // write player0 correction bits
        self.corrections.write(&delta);
    }

    #[inline(always)]
    fn pack_batch(&mut self) {
        // generate sharings for the output of the next batch of multiplications
        for i in 0..N {
            self.batch_g[i] = D::Batch::gen(&mut self.rngs[i]);
        }
        D::convert(&mut self.share_g[..], &self.batch_g[..]);

        // look forward in program until executed enough multiplications
        let mut mults = 0;
        for (i, ins) in self.program.iter().enumerate() {
            match *ins {
                Instruction::AddConst(dst, src, _c) => {
                    // noop in pre-processing
                    #[cfg(test)]
                    println!("process {} {}", dst, src);
                    self.masks.set(dst, self.masks.get(src));
                }
                Instruction::MulConst(dst, src, c) => {
                    // resolve input
                    let sw = self.masks.get(src);

                    // let the single element act on the vector
                    self.masks.set(dst, sw.action(c));
                }
                Instruction::Add(dst, src1, src2) => {
                    self.masks
                        .set(dst, self.masks.get(src1) + self.masks.get(src2));
                }
                Instruction::Mul(dst, src1, src2) => {
                    // push the masks to the Beaver stack
                    self.share_a[mults] = self.masks.get(src1);
                    self.share_b[mults] = self.masks.get(src2);

                    // assign mask to output
                    self.masks.set(dst, self.share_g[mults]);
                    mults += 1;

                    // if the batch is full, stop.
                    if mults == D::Batch::DIMENSION {
                        self.program = &self.program[i + 1..];
                        self.generate();
                        return;
                    }
                    debug_assert!(mults < D::Batch::DIMENSION);
                }
                Instruction::Output(_src) => (),
            }
        }

        self.program = &self.program[..0];

        // we are at the end of the program look_ahead
        // push final dummy values to the Beaver stack.
        if mults > 0 {
            self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.generate();
        }
    }

    pub fn finish(&mut self) {
        while self.program.len() > 0 {
            self.pack_batch();
        }
    }
}

impl<'a, 'b, 'c, D: Domain, R: RngCore, W: Writer<D::Batch>, const N: usize, const O: bool>
    Preprocessing<D> for PreprocessingExecution<'a, 'b, 'c, D, R, W, N, O>
{
    fn mask(&self, idx: usize) -> D::Sharing {
        self.masks.get(idx)
    }

    /// Return the next ab_gamma sharings for reconstruction
    fn next_ab_gamma(&mut self) -> D::Sharing {
        assert!(O, "not online execution");
        debug_assert!(self.next < D::Batch::DIMENSION);
        let ab_gamma = self.share_ab_gamma[self.next];
        self.next += 1;
        if self.next >= D::Batch::DIMENSION {
            self.pack_batch();
            self.next = 0;
        }
        ab_gamma
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
