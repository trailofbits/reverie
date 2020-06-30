use super::*;

use crate::crypto::RingHasher;
use crate::Instruction;

use std::io::Write;

use blake3::Hash;
use rand_core::RngCore;

pub fn correction_hash<'a, D: Domain, R: RngCore>(rngs: &'a mut [R], batches: u64) -> Hash {
    assert_eq!(rngs.len(), D::Sharing::DIMENSION);

    let mut hasher = RingHasher::new();

    for _ in 0..batches {
        // generate 3 random sharings
        let a0 = D::Batch::gen(&mut rngs[0]);
        let b0 = D::Batch::gen(&mut rngs[0]);
        let c0 = D::Batch::gen(&mut rngs[0]);

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;

        for i in 1..D::Sharing::DIMENSION {
            a = a + D::Batch::gen(&mut rngs[i]);
            b = b + D::Batch::gen(&mut rngs[i]);
            c = c + D::Batch::gen(&mut rngs[i]);
        }

        // correct player 0 share:
        // Calculate \delta and add to player 0 share:
        // c + \delta = a * b
        hasher.update(&(c0 + (a * b - c)));
    }

    hasher.finalize()
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct BeaverStack<'a, D: Domain, W: Write, R: RngCore, const N: usize> {
    share_a: Vec<D::Sharing>,
    share_b: Vec<D::Sharing>,
    share_c: Vec<D::Sharing>,
    zero: &'a mut W,   // writer for player 0 shares
    rngs: Box<[R; N]>, // rngs for players
}

impl<'a, D: Domain, W: Write, R: RngCore, const N: usize> BeaverStack<'a, D, W, R, N> {
    pub fn new(rngs: Box<[R; N]>, zero: &'a mut W) -> Self {
        Self {
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            share_c: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            zero,
            rngs,
        }
    }

    pub fn generate(&mut self) {
        debug_assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_b.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_c.len(), 0);

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
        batches_c[0].serialize(&mut self.zero).unwrap();

        // transpose c back into D::Batch::DIMENSION sharings
        D::convert(&mut self.share_c[..], &batches_c[..]);

        // remove input shares from internal buffer
        self.share_a.clear();
        self.share_b.clear();
    }

    pub fn push(&mut self, a: D::Sharing, b: D::Sharing) {
        assert!(self.share_a.len() < D::Batch::DIMENSION);
        debug_assert_eq!(self.share_a.len(), self.share_b.len());
        self.share_a.push(a);
        self.share_b.push(b);
        if self.share_a.len() >= D::Batch::DIMENSION {
            self.generate();
        }
    }

    pub fn pop(&mut self) -> Option<D::Sharing> {
        assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        if self.share_c.len() == 1 {
            self.share_a.clear();
            self.share_b.clear();
        }
        self.share_c.pop()
    }
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<'a, D: Domain, W: Write, R: RngCore, const N: usize> {
    stack: BeaverStack<'a, D, W, R, N>,
    wires: Vec<Option<D::Sharing>>,
    mults: Vec<usize>,
}

impl<'a, D: Domain, W: Write, R: RngCore, const N: usize> PreprocessingExecution<'a, D, W, R, N> {
    pub fn new(rngs: Box<[R; N]>, zero: &'a mut W, inputs: usize) -> Self {
        PreprocessingExecution {
            stack: BeaverStack::new(rngs, zero),
            wires: Vec::new(),
            mults: Vec::with_capacity(D::Batch::DIMENSION),
        }
    }

    fn empty_stack(&mut self) {
        let mut dummy: usize = 0;

        // add padding sharings to each batch dimension
        while self.mults.len() < D::Batch::DIMENSION {
            self.stack.push(D::Sharing::ZERO, D::Sharing::ZERO);
            dummy += 1;
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
    }

    fn compute(&mut self, idx: usize) -> D::Sharing {
        if let Some(mask) = self.wires[idx] {
            mask
        } else {
            // otherwise it is on the beaver stack
            self.empty_stack();
            self.wires[idx].unwrap()
        }
    }

    pub fn step(&mut self, ins: &Instruction<<D::Sharing as RingModule>::Scalar>) {
        match ins {
            Instruction::AddConst(_dst, _src, _c) => (), // noop in pre-processing
            Instruction::MulConst(dst, src, c) => {
                let sw = self.compute(*src);
                self.wires[*dst] = Some(sw.action(*c))
            }
            Instruction::Add(dst, src1, src2) => {
                let sw1 = self.compute(*src1);
                let sw2 = self.compute(*src2);
                self.wires[*dst] = Some(sw1 + sw2);
            }
            Instruction::Mul(dst, src1, src2) => {
                let sw1 = self.compute(*src1);
                let sw2 = self.compute(*src2);

                // check if space on Beaver stack
                if self.mults.len() >= D::Batch::DIMENSION {
                    self.empty_stack();
                }

                // push the masks to the Beaver stack
                self.stack.push(sw1, sw2);
                self.mults.push(*dst);

                // mark destination as pending computation
                self.wires[*dst] = None;
            }
            Instruction::Output(_src) => (),
        }
    }
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct ProverOnlinePreprocessing<'a, D: Domain, W: Write, R: RngCore, const N: usize> {
    share_a: Vec<D::Sharing>,
    share_b: Vec<D::Sharing>,
    share_c: Vec<D::Sharing>,
    zero: &'a mut W,   // writer for player 0 shares
    rngs: Box<[R; N]>, // rngs for players
}

impl<'a, D: Domain, W: Write, R: RngCore, const N: usize>
    ProverOnlinePreprocessing<'a, D, W, R, N>
{
    pub fn new(rngs: Box<[R; N]>, zero: &'a mut W) -> Self {
        Self {
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            share_c: Vec::with_capacity(D::Batch::DIMENSION),
            zero,
            rngs,
        }
    }

    fn replenish(&mut self) {
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
        debug_assert_eq!(self.share_c.len(), 0);

        self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
        self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
        self.share_c.resize(D::Batch::DIMENSION, D::Sharing::ZERO);

        let mut share_a: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut share_b: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut share_c: [D::Batch; N] = [D::Batch::ZERO; N];

        // generate 3 batches of shares for every player
        let mut a = D::Batch::ZERO;
        let mut b = D::Batch::ZERO;
        let mut c = D::Batch::ZERO;

        for i in 0..N {
            share_a[i] = D::Batch::gen(&mut self.rngs[i]);
            share_b[i] = D::Batch::gen(&mut self.rngs[i]);
            share_c[i] = D::Batch::gen(&mut self.rngs[i]);
            a = a + share_a[i];
            b = b + share_b[i];
            c = c + share_c[i];
        }

        // correct share for player 0
        share_c[0] = share_c[0] + (a * b - c);

        // write player 0 corrected share
        share_c[0].serialize(&mut self.zero).unwrap();

        // transpose
        D::convert(&mut self.share_a[..], &mut share_a);
        D::convert(&mut self.share_b[..], &mut share_b);
        D::convert(&mut self.share_c[..], &mut share_c);
    }

    pub fn next(&mut self) -> (D::Sharing, D::Sharing, D::Sharing) {
        match (self.share_a.pop(), self.share_b.pop(), self.share_c.pop()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            (None, None, None) => {
                self.replenish();
                debug_assert!(self.share_a.len() > 0);
                debug_assert!(self.share_b.len() > 0);
                debug_assert!(self.share_c.len() > 0);
                self.next()
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::*;
    use crate::algebra::gf2::GF2P8;

    use std::io::{sink, Sink};

    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    use test::{black_box, Bencher};

    #[bench]
    fn bench_preprocessing_n8_triples(b: &mut Bencher) {
        let mut rngs: Box<[ThreadRng; 8]> = arr_from_iter!((0..8).map(|_| thread_rng()));
        let mut writer = sink();
        let mut gen: ProverOnlinePreprocessing<GF2P8, Sink, _, 8> =
            ProverOnlinePreprocessing::new(rngs, &mut writer);

        b.iter(|| black_box(gen.next()));
    }
}
