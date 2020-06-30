use super::*;

use crate::util::Writer;
use crate::Instruction;

use rand_core::RngCore;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct RandomSharingRng<'b, D: Domain, R: RngCore, const N: usize> {
    shares: Vec<D::Sharing>,
    rngs: &'b mut [R; N],
    used: usize,
}

impl<'b, D: Domain, R: RngCore, const N: usize> RandomSharingRng<'b, D, R, N> {
    pub fn new(rngs: &'b mut [R; N]) -> Self {
        Self {
            shares: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            rngs,
            used: 0,
        }
    }

    fn replenish(&mut self) {
        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
        for i in 0..N {
            batches[i] = D::Batch::gen(&mut self.rngs[i]);
        }
        D::convert(&mut self.shares[..], &batches[..]);
        self.used = 0;
    }

    pub fn gen(&mut self) -> D::Sharing {
        if self.used == D::Batch::DIMENSION {
            self.replenish();
            self.used = 1;
            self.shares[0]
        } else {
            self.used += 1;
            self.shares[self.used - 1]
        }
    }
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct BeaverStack<'a, 'b, D: Domain, W: Writer<D::Batch>, R: RngCore, const N: usize> {
    share_a: Vec<D::Sharing>,
    share_b: Vec<D::Sharing>,
    share_c: Vec<D::Sharing>,
    zero: &'a mut W,      // writer for player 0 shares
    rngs: &'b mut [R; N], // rngs for players
}

impl<'a, 'b, D: Domain, W: Writer<D::Batch>, R: RngCore, const N: usize>
    BeaverStack<'a, 'b, D, W, R, N>
{
    pub fn new(rngs: &'b mut [R; N], zero: &'a mut W) -> Self {
        Self {
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            share_c: Vec::with_capacity(D::Batch::DIMENSION),
            zero,
            rngs,
        }
    }

    pub fn generate(&mut self) {
        debug_assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_b.len(), D::Batch::DIMENSION);

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
            batches_c[i] = D::Batch::gen(&mut self.rngs[i]);
            a = a + batches_a[i];
            b = b + batches_b[i];
            c = c + batches_c[i];
        }

        // correct shares for player 0 (correction bits)
        batches_c[0] = batches_c[0] + (a * b - c);

        // write player 0 corrected share
        self.zero.write(&batches_c[0]);

        // transpose c back into D::Batch::DIMENSION sharings
        self.share_c.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
        D::convert(&mut self.share_c[..], &batches_c[..]);

        // remove input shares from internal buffer
        self.share_a.clear();
        self.share_b.clear();
    }

    pub fn push(&mut self, a: D::Sharing, b: D::Sharing) {
        debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
        debug_assert_eq!(self.share_a.len(), self.share_b.len());
        self.share_a.push(a);
        self.share_b.push(b);
    }

    pub fn pop(&mut self) -> Option<D::Sharing> {
        if self.share_c.len() == 1 {
            self.share_a.clear();
            self.share_b.clear();
        }
        self.share_c.pop()
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
    stack: BeaverStack<'a, 'b, D, W, R, N>,
    wires: Vec<Option<D::Sharing>>,
    mults: Vec<usize>,
}

impl<'a, 'b, D: Domain, W: Writer<D::Batch>, R: RngCore, const N: usize>
    PreprocessingExecution<'a, 'b, D, W, R, N>
{
    pub fn new(rngs: &'b mut [R; N], zero: &'a mut W, inputs: usize) -> Self {
        // generate masks for inputs
        let mut wires: Vec<Option<D::Sharing>> = Vec::with_capacity(inputs);
        {
            let mut input_gen: RandomSharingRng<D, R, N> = RandomSharingRng::new(rngs);
            for _ in 0..inputs {
                wires.push(Some(input_gen.gen()));
            }
        }

        // return pre-processing with input wire masks set
        PreprocessingExecution {
            stack: BeaverStack::new(rngs, zero),
            wires,
            mults: Vec::with_capacity(D::Batch::DIMENSION),
        }
    }

    fn empty_stack(&mut self) {
        debug_assert!(D::Batch::DIMENSION >= self.mults.len());
        let dummy: usize = D::Batch::DIMENSION - self.mults.len();

        // add padding sharings to each batch dimension
        for _ in 0..dummy {
            self.stack.push(D::Sharing::ZERO, D::Sharing::ZERO);
        }

        // generate output sharings
        self.stack.generate();

        // strip dummy sharings
        for _ in 0..dummy {
            self.stack.pop();
        }

        // write back the new sharings
        while let Some(idx) = self.mults.pop() {
            self.wires[idx] = self.stack.pop();
        }
        debug_assert_eq!(self.mults.len(), 0);
    }

    fn set(&mut self, idx: usize, val: Option<D::Sharing>) {
        if idx >= self.wires.len() {
            self.wires.resize(idx + 1, None);
        }
        self.wires[idx] = val;
    }

    fn compute(&mut self, idx: usize) -> D::Sharing {
        if let Some(mask) = self.wires[idx] {
            mask
        } else {
            // otherwise it is on the beaver stack
            self.empty_stack();

            // if this fails, the program is using an unassigned wire
            self.wires[idx].unwrap()
        }
    }

    pub fn step(&mut self, ins: &Instruction<<D::Sharing as RingModule>::Scalar>) {
        match ins {
            Instruction::AddConst(_dst, _src, _c) => (), // noop in pre-processing
            Instruction::MulConst(dst, src, c) => {
                // resolve input
                let sw = self.compute(*src);

                // let the single element act on the vector
                self.set(*dst, Some(sw.action(*c)));
            }
            Instruction::Add(dst, src1, src2) => {
                // resolve inputs
                let sw1 = self.compute(*src1);
                let sw2 = self.compute(*src2);

                // compute the sum and set output wire
                self.set(*dst, Some(sw1 + sw2));
            }
            Instruction::Mul(dst, src1, src2) => {
                // resolve inputs
                let sw1 = self.compute(*src1);
                let sw2 = self.compute(*src2);

                // check if space on Beaver stack
                if self.mults.len() >= D::Batch::DIMENSION {
                    self.empty_stack();
                    debug_assert_eq!(self.mults.len(), 0);
                }

                // push the masks to the Beaver stack
                self.stack.push(sw1, sw2);
                self.mults.push(*dst);

                // mark destination as pending computation
                self.set(*dst, None);
            }
            Instruction::Output(_src) => (),
        }
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
            black_box(
                // note that the multiplications may be executed using the SIMD technique
                gen.step(&Instruction::Mul(0, 1, 2)),
            )
        });
    }

    #[bench]
    fn bench_preprocessing_n8_triples_single(b: &mut Bencher) {
        let mut rngs: Box<[ThreadRng; 8]> = arr_from_iter!((0..8).map(|_| thread_rng()));
        let mut writer = RingHasher::new();
        let mut gen: PreprocessingExecution<GF2P8, _, _, 8> =
            PreprocessingExecution::new(&mut rngs, &mut writer, 64);

        b.iter(|| {
            black_box(
                // note that the multiplications must be immediately resolved for the next layer
                // hence can only be executed one at a time (very slow).
                gen.step(&Instruction::Mul(1, 1, 2)),
            )
        });
    }
}
