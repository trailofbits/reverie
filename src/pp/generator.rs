use super::*;

use crate::util::Writer;
use crate::Instruction;

use rand_core::RngCore;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct SharingRng<D: Domain, const N: usize> {
    shares: Vec<D::Sharing>,
    used: usize,
}

impl<D: Domain, const N: usize> SharingRng<D, N> {
    pub fn new() -> Self {
        Self {
            shares: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            used: 0,
        }
    }

    fn replenish<R: RngCore>(&mut self, rngs: &mut [R; N]) {
        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
        for i in 0..N {
            batches[i] = D::Batch::gen(&mut rngs[i]);
        }
        D::convert(&mut self.shares[..], &batches[..]);
        self.used = 0;
    }

    pub fn gen<R: RngCore>(&mut self, rngs: &mut [R; N]) -> D::Sharing {
        if self.used == D::Batch::DIMENSION {
            self.replenish(rngs);
            self.used = 1;
            self.shares[0]
        } else {
            self.used += 1;
            self.shares[self.used - 1]
        }
    }
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct BeaverStack<'a, 'b, D: Domain, R: RngCore, W: Writer<D::Batch>, const N: usize> {
    next: usize,
    outs: usize,
    share_a: Vec<D::Sharing>, // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
    share_g: Vec<D::Sharing>, // gamma sharings (output)
    batch_g: [D::Batch; N],   // gamma batch
    rngs: &'b mut [R; N],     // rngs
    zero: &'a mut W,          // writer for player 0 shares
}

impl<'a, 'b, D: Domain, R: RngCore, W: Writer<D::Batch>, const N: usize>
    BeaverStack<'a, 'b, D, R, W, N>
{
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
            outs: D::Batch::DIMENSION,
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
        batches_gab[0] = batches_gab[0] + delta;

        // write player 0 corrected share
        self.zero.write(&batches_c[0]);

        // transpose c back into D::Batch::DIMENSION sharings
        if ab_gamma.len() > 0 {
            D::convert(ab_gamma, &batches_gab);
        }

        // get new batch of gamma shares
        self.new_gamma();
    }

    pub fn push(
        &mut self,
        ab_gamma: &mut [D::Sharing],
        a: D::Sharing,
        b: D::Sharing,
    ) -> D::Sharing {
        // schedule for processing
        self.share_a[self.next] = a;
        self.share_b[self.next] = b;
        let gamma = self.share_g[self.next];
        self.next += 1;

        // check if current batch is full
        if self.next >= D::Batch::DIMENSION {
            self.generate(ab_gamma);
            self.outs = 0;
            self.next = 0;
        }
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
> {
    beaver: BeaverStack<'a, 'b, D, R, W, N>,
    pub masks: Vec<D::Sharing>,
}

impl<'a, 'b, D: Domain, W: Writer<D::Batch>, R: RngCore, const N: usize>
    PreprocessingExecution<'a, 'b, D, W, R, N>
{
    pub fn new(rngs: &'b mut [R; N], zero: &'a mut W, inputs: usize) -> Self {
        // generate masks for inputs
        let mut masks: Vec<D::Sharing> = Vec::with_capacity(inputs);
        {
            let mut share_gen: SharingRng<D, N> = SharingRng::new();
            for _ in 0..inputs {
                masks.push(share_gen.gen(rngs));
            }
        }

        // return pre-processing with input wire masks set
        PreprocessingExecution {
            beaver: BeaverStack::new(zero, rngs),
            masks,
        }
    }

    fn set(&mut self, idx: usize, val: D::Sharing) {
        if idx >= self.masks.len() {
            self.masks.resize(idx + 1, D::Sharing::ZERO);
        }
        self.masks[idx] = val;
    }

    pub fn step(
        &mut self,
        ab_gamma: &mut [D::Sharing],
        ins: &Instruction<<D::Sharing as RingModule>::Scalar>,
    ) -> bool {
        match ins {
            Instruction::AddConst(_dst, _src, _c) => false, // noop in pre-processing
            Instruction::MulConst(dst, src, c) => {
                // resolve input
                let sw = self.masks[*src];

                // let the single element act on the vector
                self.set(*dst, sw.action(*c));
                false
            }
            Instruction::Add(dst, src1, src2) => {
                // resolve inputs
                let sw1 = self.masks[*src1];
                let sw2 = self.masks[*src2];

                // compute the sum and set output wire
                self.set(*dst, sw1 + sw2);
                false
            }
            Instruction::Mul(dst, src1, src2) => {
                // resolve inputs
                let sw1 = self.masks[*src1];
                let sw2 = self.masks[*src2];

                // push the masks to the Beaver stack
                let gamma = self.beaver.push(ab_gamma, sw1, sw2);

                // assign mask to output
                self.set(*dst, gamma);
                true
            }
            Instruction::Output(_src) => false,
        }
    }

    pub fn next_batch(
        &mut self,
        ab_gamma: &mut [D::Sharing],
        look_ahead: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    ) -> usize {
        // check that it is aligned (many only arise due to buggy programming)
        debug_assert_eq!(self.beaver.outs, D::Batch::DIMENSION);
        debug_assert_eq!(ab_gamma.len(), D::Batch::DIMENSION);

        // look forward in program until executed enough multiplications
        let mut mults: usize = 0;
        let mut steps: usize = 0;
        for ins in look_ahead {
            steps += 1;
            mults += self.step(ab_gamma, ins) as usize;
            if mults == D::Batch::DIMENSION {
                // ab_gamma should have been written to
                debug_assert_eq!(self.beaver.outs, D::Batch::DIMENSION);
                break;
            }
        }

        // return how many instructions was pre-processed from the look_ahead
        steps
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

    #[bench]
    fn bench_preprocessing_n8_triples_simd(b: &mut Bencher) {
        let mut rngs: Box<[ThreadRng; 8]> = arr_from_iter!((0..8).map(|_| thread_rng()));
        let mut writer = RingHasher::new();
        let mut gen: PreprocessingExecution<GF2P8, _, _, 8> =
            PreprocessingExecution::new(&mut rngs, &mut writer, 64);

        b.iter(|| {
            black_box({
                let mut v: [_; 0] = [];
                gen.step(&mut v, &Instruction::Mul(0, 1, 2))
            })
        });
    }

    #[bench]
    fn bench_preprocessing_n8_triples_single(b: &mut Bencher) {
        let mut rngs: Box<[ThreadRng; 8]> = arr_from_iter!((0..8).map(|_| thread_rng()));
        let mut writer = RingHasher::new();
        let mut gen: PreprocessingExecution<GF2P8, _, _, 8> =
            PreprocessingExecution::new(&mut rngs, &mut writer, 64);

        b.iter(|| {
            black_box({
                let mut v: [_; 0] = [];
                gen.step(&mut v, &Instruction::Mul(1, 1, 2));
            })
        });
    }
}
