use super::*;

use crate::util::{VoidWriter, Writer};
use crate::Instruction;

use rand_core::RngCore;

macro_rules! new_sharings {
    ( $shares:expr, $batches:expr, $rngs:expr ) => {{
        for j in 0..N {
            $batches[j] = D::Batch::gen(&mut $rngs[j]);
        }
        D::convert($shares, &$batches[..]);
    }};
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<D: Domain, R: RngCore, const N: usize, const O: bool> {
    // interpreter state
    masks: VecMap<D::Sharing>,

    // input mask state
    next_input: usize,
    share_input: Vec<D::Sharing>,

    // Beaver multiplication state
    share_a: Vec<D::Sharing>, // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
    share_g: Vec<D::Sharing>, // gamma sharings (output)
    rngs: Array<R, N>,        // rngs
}

impl<D: Domain, R: RngCore, const N: usize, const O: bool> PreprocessingExecution<D, R, N, O> {
    pub fn new(rngs: Array<R, N>) -> Self {
        PreprocessingExecution {
            next_input: D::Batch::DIMENSION,
            share_input: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            rngs,
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            masks: VecMap::new(),
        }
    }

    #[inline(always)]
    fn generate<CW: Writer<D::Batch>>(
        &mut self,
        ab_gamma: &mut Vec<D::Sharing>,
        corrections: &mut CW, // player 0 corrections
        batch_g: &[D::Batch; N],
    ) {
        let mut batches_a: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_b: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_c: [D::Batch; N] = [D::Batch::ZERO; N];

        debug_assert_eq!(self.share_a.len(), D::Batch::DIMENSION);
        debug_assert_eq!(self.share_b.len(), D::Batch::DIMENSION);

        // transpose sharings into per player batches
        D::convert_inv(&mut batches_a[..], &self.share_a[..]);
        D::convert_inv(&mut batches_b[..], &self.share_b[..]);
        self.share_a.clear();
        self.share_b.clear();

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

        // write correction batch (player 0 correction bits)
        // for the pre-processing phase, the writer will simply be a hash function.
        corrections.write(delta);

        // compute ab_gamma shares only in online execution (to save time and memory)
        if O {
            // compute ab_gamma in parallel using batch operations
            batches_c[0] = batches_c[0] + delta;
            let mut batches_gab: [D::Batch; N] = [D::Batch::ZERO; N];
            for i in 0..N {
                batches_gab[i] = batches_c[i] + batch_g[i];
            }

            // transpose into shares
            let start = ab_gamma.len();
            ab_gamma.resize(start + D::Batch::DIMENSION, D::Sharing::ZERO);
            D::convert(&mut ab_gamma[start..], &batches_gab);
        }

        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);
    }

    #[inline(always)]
    pub fn process<CW: Writer<D::Batch>, MW: Writer<D::Sharing>>(
        &mut self,
        program: &[Instruction<D::Scalar>], // program slice
        corrections: &mut CW,               // player 0 corrections
        masks: &mut MW,                     // masks for online phase
        ab_gamma: &mut Vec<D::Sharing>,     // a * b + \gamma sharings for online phase
    ) {
        // invariant: multiplication batch empty at the start
        debug_assert_eq!(self.share_a.len(), 0);
        debug_assert_eq!(self.share_b.len(), 0);

        // look forward in program until executed enough multiplications for next batch
        let mut batch_g = [D::Batch::ZERO; N];
        for step in program {
            debug_assert_eq!(self.share_a.len(), self.share_b.len());
            debug_assert_eq!(self.share_g.len(), D::Batch::DIMENSION);
            debug_assert_eq!(self.share_input.len(), D::Batch::DIMENSION);
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            debug_assert!(self.share_a.len() < D::Batch::DIMENSION);
            match *step {
                Instruction::Input(dst) => {
                    // check if need for new batch of input masks
                    if self.next_input == D::Batch::DIMENSION {
                        let mut batch_m = [D::Batch::ZERO; N];
                        new_sharings!(&mut self.share_input[..], batch_m, &mut self.rngs);
                        self.next_input = 0;
                    }

                    // assign the next unused input share to the destination wire
                    let mask = self.share_input[self.next_input];
                    self.masks.set(dst, mask);
                    self.next_input += 1;

                    // return the mask to the online phase (for hiding the witness)
                    masks.write(mask);
                }
                Instruction::AddConst(dst, src, _c) => {
                    // noop in pre-processing
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
                    // generate sharings for the output of the next batch of multiplications
                    if self.share_a.len() == 0 {
                        new_sharings!(&mut self.share_g[..], batch_g, &mut self.rngs);
                    }

                    // push the input masks to the stack
                    let next_idx = self.share_a.len();
                    let mask_a = self.masks.get(src1);
                    let mask_b = self.masks.get(src2);
                    self.share_a.push(mask_a);
                    self.share_b.push(mask_b);

                    // return the mask to online phase for Beaver multiplication
                    masks.write(mask_a);
                    masks.write(mask_b);

                    // assign mask to output
                    self.masks.set(dst, self.share_g[next_idx]);

                    // if the batch is full, generate next batch of ab_gamma shares
                    if self.share_a.len() == D::Batch::DIMENSION {
                        self.generate(ab_gamma, corrections, &batch_g);
                    }
                }
                Instruction::Output(src) => {
                    // return to online phase for reconstruction
                    masks.write(self.masks.get(src));
                }
            }
        }

        // pad final multiplication batch if needed
        if self.share_a.len() > 0 {
            self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            self.generate(ab_gamma, corrections, &batch_g);
        }
    }

    pub fn prove<CW: Writer<D::Batch>>(
        &mut self,
        program: &[Instruction<D::Scalar>], // program slice (possibly a subset of the full program)
        corrections: &mut CW,               // player 0 corrections
    ) {
        assert!(!O, "method only valid in pre-processing proof");
        let mut ab_gamma = vec![];
        self.process(
            program,
            corrections,
            &mut VoidWriter::new(), // discard masks
            &mut ab_gamma,
        );
        debug_assert_eq!(ab_gamma.len(), 0);
    }
}
