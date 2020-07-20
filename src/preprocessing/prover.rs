use super::*;

use crate::util::Writer;
use crate::Instruction;

use rand_core::RngCore;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<
    'a,
    'b,
    D: Domain,
    CW: Writer<D::Batch>, // corrections writer
    PI: Iterator<Item = Instruction<<D::Sharing as RingModule>::Scalar>>, // program iterator
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
    share_ab_gamma: Vec<D::Sharing>, // alpha * beta + gamma sharings
    share_a: Vec<D::Sharing>,        // beta sharings (from input)
    share_b: Vec<D::Sharing>,        // alpha sharings (from input)
    share_g: Vec<D::Sharing>,        // gamma sharings (output)
    batch_g: [D::Batch; N],          // gamma batch
    rngs: &'a mut [R; N],            // rngs
}

impl<
        'a,
        'b,
        D: Domain,
        CW: Writer<D::Batch>,
        PI: Iterator<Item = Instruction<<D::Sharing as RingModule>::Scalar>>,
        R: RngCore,
        const N: usize,
        const O: bool,
    > PreprocessingExecution<'a, 'b, D, CW, PI, R, N, O>
{
    pub fn new(rngs: &'a mut [R; N], corrections: &'b mut CW, program: PI) -> Self {
        PreprocessingExecution {
            program,
            next_input: 0,
            corrections,
            rngs,
            batch_g: [D::Batch::ZERO; N],
            share_input: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_ab_gamma: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_b: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            masks: VecMap::new(),
        }
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

        // write correction batch (player 0 correction bits)
        // for the pre-processing phase, the writer will simply be a hash function.
        self.corrections.write(&delta);

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
    }

    #[inline(always)]
    fn pack_batch(
        &mut self,
        sharings: &mut Vec<D::Sharing>, // resulting sharings consumed by online phase
    ) -> bool {
        // generate sharings for the output of the next batch of multiplications
        for i in 0..N {
            self.batch_g[i] = D::Batch::gen(&mut self.rngs[i]);
        }
        D::convert(&mut self.share_g[..], &self.batch_g[..]);

        // look forward in program until executed enough multiplications
        let mut mults = 0;
        loop {
            match self.program.next() {
                Some(Instruction::Input(dst)) => {
                    // check if need for new batch of input masks
                    if self.next_input == D::Batch::DIMENSION {
                        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
                        for j in 0..N {
                            batches[j] = D::Batch::gen(&mut self.rngs[j]);
                        }
                        D::convert(&mut self.share_input[..], &batches[..]);
                        self.next_input = 0;
                    }

                    // assign the next unused input share to the destination wire
                    let mask = self.share_input[self.next_input];
                    self.masks.set(dst, mask);
                    self.next_input += 1;

                    // return the mask to the online phase (for hiding the witness)
                    if O {
                        sharings.push(mask);
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
                    // push the masks to the Beaver stack
                    let mask_a = self.masks.get(src1);
                    let mask_b = self.masks.get(src2);
                    let mask_g = self.share_g[mults];
                    self.share_a[mults] = mask_a;
                    self.share_b[mults] = mask_b;

                    // return the mask to online phase for Beaver multiplication
                    if O {
                        sharings.push(mask_a);
                        sharings.push(mask_b);
                        sharings.push(mask_g);
                    }

                    // assign mask to output
                    self.masks.set(dst, mask_g);
                    mults += 1;

                    // if the batch is full, stop.
                    if mults == D::Batch::DIMENSION {
                        self.generate();
                        return true;
                    }
                    debug_assert!(mults < D::Batch::DIMENSION);
                }
                Some(Instruction::Output(src)) => {
                    if O {
                        // output the reconstruction messages to the online phase
                        sharings.push(self.masks.get(src));
                    }
                }
                None => {
                    if mults > 0 {
                        self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
                        self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
                        self.generate();
                        return true;
                    } else {
                        return false;
                    }
                }
            }
        }
    }

    pub fn finish(&mut self) {
        let mut batches = vec![];
        while self.pack_batch(&mut batches) {}
        debug_assert_eq!(batches.len(), 0);
    }

    pub fn next_sharings(&mut self, sharings: &mut Vec<D::Sharing>) {
        self.pack_batch(sharings);
    }
}
