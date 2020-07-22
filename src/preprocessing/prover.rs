use super::*;

use crate::util::Writer;
use crate::Instruction;

use rand_core::RngCore;

macro_rules! new_sharings {
    ( $dst:expr, $rngs:expr ) => {{
        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
        for j in 0..N {
            batches[j] = D::Batch::gen(&mut $rngs[j]);
        }
        D::convert($dst, &batches[..]);
    }};
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<
    'a,
    'b,
    D: Domain,
    CW: Writer<D::Batch>,                        // corrections writer
    PI: Iterator<Item = Instruction<D::Scalar>>, // program iterator
    R: RngCore,
    const N: usize,
    const O: bool,
> {
    // interpreter state
    program: PI,
    masks: VecMap<D::Sharing>,

    // input mask state
    next_input: usize,
    share_input: Vec<D::Sharing>,

    // Beaver multiplication state
    corrections: &'b mut CW,
    share_a: Vec<D::Sharing>, // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
    share_g: Vec<D::Sharing>, // gamma sharings (output)
    batch_g: [D::Batch; N],   // gamma batch
    rngs: &'a mut [R; N],     // rngs
}

impl<
        'a,
        'b,
        D: Domain,
        CW: Writer<D::Batch>,
        PI: Iterator<Item = Instruction<D::Scalar>>,
        R: RngCore,
        const N: usize,
        const O: bool,
    > PreprocessingExecution<'a, 'b, D, CW, PI, R, N, O>
{
    pub fn new(rngs: &'a mut [R; N], corrections: &'b mut CW, program: PI) -> Self {
        PreprocessingExecution {
            program,
            next_input: D::Batch::DIMENSION,
            share_input: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            corrections,
            rngs,
            batch_g: [D::Batch::ZERO; N],
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            masks: VecMap::new(),
        }
    }

    #[inline(always)]
    fn generate(&mut self, ab_gamma: &mut [D::Sharing]) {
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
        self.corrections.write(&delta);

        // compute ab_gamma shares if online execution
        if O {
            batches_c[0] = batches_c[0] + delta;
            let mut batches_gab: [D::Batch; N] = [D::Batch::ZERO; N];
            for i in 0..N {
                batches_gab[i] = batches_c[i] + self.batch_g[i];
            }
            D::convert(ab_gamma, &batches_gab);

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
        }
    }

    #[inline(always)]
    fn pack_batch(&mut self, masks: &mut Vec<D::Sharing>, ab_gamma: &mut [D::Sharing]) -> bool {
        // generate sharings for the output of the next batch of multiplications
        new_sharings!(&mut self.share_g[..], &mut self.rngs);

        // look forward in program until executed enough multiplications for next batch
        loop {
            match self.program.next() {
                Some(Instruction::Input(dst)) => {
                    // check if need for new batch of input masks
                    if self.next_input == D::Batch::DIMENSION {
                        new_sharings!(&mut self.share_input[..], &mut self.rngs);
                        self.next_input = 0;
                    }

                    // assign the next unused input share to the destination wire
                    let mask = self.share_input[self.next_input];
                    self.masks.set(dst, mask);
                    self.next_input += 1;

                    // return the mask to the online phase (for hiding the witness)
                    if O {
                        masks.push(mask);
                    }
                }
                Some(Instruction::AddConst(dst, src, _c)) => {
                    // noop in pre-processing
                    self.masks.set(dst, self.masks.get(src));
                }
                Some(Instruction::MulConst(dst, src, c)) => {
                    // resolve input
                    let sw = self.masks.get(src);

                    // let the single element act on the vector
                    self.masks.set(dst, sw.action(c));
                }
                Some(Instruction::Add(dst, src1, src2)) => {
                    self.masks
                        .set(dst, self.masks.get(src1) + self.masks.get(src2));
                }
                Some(Instruction::Mul(dst, src1, src2)) => {
                    let next_idx = self.share_a.len();

                    // push the masks to the Beaver stack
                    let mask_a = self.masks.get(src1);
                    let mask_b = self.masks.get(src2);
                    self.share_a.push(mask_a);
                    self.share_b.push(mask_b);

                    // return the mask to online phase for Beaver multiplication
                    if O {
                        masks.push(mask_a);
                        masks.push(mask_b);
                    }

                    // assign mask to output
                    self.masks.set(dst, self.share_g[next_idx]);

                    // if the batch is full, stop.
                    if self.share_a.len() == D::Batch::DIMENSION {
                        self.generate(ab_gamma);
                        return true;
                    }
                }
                Some(Instruction::Output(src)) => {
                    // return to online phase for reconstruction
                    masks.push(self.masks.get(src));
                }
                None => {
                    if self.share_a.len() > 0 {
                        self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
                        self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
                        self.generate(ab_gamma);
                        return true;
                    } else {
                        return false;
                    }
                }
            }
        }
    }

    pub fn finish(&mut self) {
        assert!(!O, "method only valid in pre-processing proof");
        let mut ab_gamma = [];
        let mut masks = vec![];
        while self.pack_batch(&mut masks, &mut ab_gamma) {}
        debug_assert_eq!(masks.len(), 0);
    }
}

impl<
        'a,
        'b,
        D: Domain,
        CW: Writer<D::Batch>,                        // corrections writer
        PI: Iterator<Item = Instruction<D::Scalar>>, // program iterator
        R: RngCore,
        const N: usize,
        const O: bool,
    > Preprocessing<D> for PreprocessingExecution<'a, 'b, D, CW, PI, R, N, O>
{
    fn next_sharings(&mut self, masks: &mut Vec<D::Sharing>, ab_gamma: &mut [D::Sharing]) {
        debug_assert_eq!(ab_gamma.len(), D::Batch::DIMENSION);
        self.pack_batch(masks, ab_gamma);
    }
}
