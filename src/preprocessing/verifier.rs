use super::*;

use crate::Instruction;

use rand_core::RngCore;

macro_rules! new_sharings {
    ( $dst:expr, $rngs:expr, $omit:expr ) => {{
        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
        for j in 0..N {
            if $omit != j {
                batches[j] = D::Batch::gen(&mut $rngs[j]);
            }
        }
        D::convert($dst, &batches[..]);
    }};
}

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<
    'a,
    D: Domain,
    PI: Iterator<Item = Instruction<<D::Sharing as RingModule>::Scalar>>, // program
    BI: Iterator<Item = D::Batch>, // multiplication broadcast
    CI: Iterator<Item = D::Batch>, // player 0 corrections
    RI: Iterator<Item = D::Batch>, // reconstruction shares for omitted player (output)
    R: RngCore,
    const N: usize,
> {
    // interpreter state
    masks: VecMap<D::Sharing>, //
    rngs: &'a mut [R; N],      // rngs
    omitted: usize,            // omitted player
    program: PI,               // statement

    // input mask state
    next_input: usize,
    share_input: Vec<D::Sharing>,

    // reconstruction shares
    reconstruct: RI, // reconstruction shares
    share_recon: Vec<D::Sharing>,
    next_recon: usize,

    // Beaver multiplication state
    broadcast: BI,            // messages
    corrections: CI,          // player 0 corrections
    batch_g: [D::Batch; N],   // gamma batch
    share_a: Vec<D::Sharing>, // beta sharings (from input)
    share_b: Vec<D::Sharing>, // alpha sharings (from input)
    share_g: Vec<D::Sharing>, // gamma sharings (output)
}

impl<
        'a,
        D: Domain,
        PI: Iterator<Item = Instruction<<D::Sharing as RingModule>::Scalar>>, // program
        BI: Iterator<Item = D::Batch>, // multiplication broadcast
        CI: Iterator<Item = D::Batch>, // player 0 corrections
        RI: Iterator<Item = D::Batch>, // output shares for omitted player
        R: RngCore,
        const N: usize,
    > PreprocessingExecution<'a, D, PI, BI, CI, RI, R, N>
{
    pub fn new(
        rngs: &'a mut [R; N],
        omitted: usize,
        reconstruct: RI,
        broadcast: BI,
        corrections: CI,
        program: PI,
    ) -> Self {
        debug_assert!(omitted < N);
        PreprocessingExecution {
            corrections,
            next_input: D::Batch::DIMENSION,
            next_recon: D::Batch::DIMENSION,
            share_input: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_recon: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            broadcast,
            reconstruct,
            rngs,
            program,
            omitted,
            batch_g: [D::Batch::ZERO; N],
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: Vec::with_capacity(D::Batch::DIMENSION),
            share_b: Vec::with_capacity(D::Batch::DIMENSION),
            masks: VecMap::new(),
        }
    }

    #[inline(always)]
    fn generate(&mut self, ab_gamma: &mut [D::Sharing]) -> Option<()> {
        let mut batches_a: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_b: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_c: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_gab: [D::Batch; N] = [D::Batch::ZERO; N];

        // transpose sharings into per player batches
        D::convert_inv(&mut batches_a[..], &self.share_a[..]);
        D::convert_inv(&mut batches_b[..], &self.share_b[..]);
        self.share_a.clear();
        self.share_b.clear();

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..N {
            if i == self.omitted {
                batches_gab[i] = self.broadcast.next()?;

                #[cfg(test)]
                #[cfg(debug_assertions)]
                println!("batches_gab[{}] = {:?} (omitted)", i, batches_gab[i]);
            } else {
                batches_c[i] = D::Batch::gen(&mut self.rngs[i]);
                if i == 0 {
                    // correct shares for player 0 (correction bits)
                    batches_c[0] = batches_c[0] + self.corrections.next()?;
                }
                batches_gab[i] = batches_c[i] + self.batch_g[i];

                #[cfg(test)]
                #[cfg(debug_assertions)]
                println!("batches_gab[{}] = {:?}", i, batches_gab[i]);
            }
        }

        // return ab_gamma shares
        D::convert(ab_gamma, &batches_gab);
        Some(())
    }

    #[inline(always)]
    fn pack_batch(
        &mut self,
        masks: &mut Vec<D::Sharing>, // resulting sharings consumed by online phase
        ab_gamma: &mut [D::Sharing],
    ) -> Option<()> {
        // generate sharings for the output of the next batch of multiplications
        for i in 0..N {
            if i != self.omitted {
                self.batch_g[i] = D::Batch::gen(&mut self.rngs[i]);
            }
        }
        debug_assert_eq!(self.batch_g[self.omitted], D::Batch::ZERO);
        D::convert(&mut self.share_g[..], &self.batch_g[..]);

        #[cfg(test)]
        {
            for share in self.share_g.iter() {
                debug_assert_eq!(
                    share.get(self.omitted),
                    <D::Sharing as RingModule>::Scalar::ZERO
                );
            }
        }

        // look forward in program until executed enough multiplications
        loop {
            match self.program.next() {
                Some(Instruction::Input(dst)) => {
                    // check if need for new batch of input masks
                    if self.next_input == D::Batch::DIMENSION {
                        new_sharings!(&mut self.share_input[..], &mut self.rngs, self.omitted);
                        self.next_input = 0;
                    }

                    // assign the next unused input share to the destination wire
                    let mask = self.share_input[self.next_input];
                    self.masks.set(dst, mask);
                    self.next_input += 1;
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
                    // resolve inputs
                    let sw1 = self.masks.get(src1);
                    let sw2 = self.masks.get(src2);

                    // compute the sum and set output wire
                    self.masks.set(dst, sw1 + sw2);
                }
                Some(Instruction::Mul(dst, src1, src2)) => {
                    let next_idx = self.share_a.len();

                    // push the masks to the Beaver stack
                    let mask_a = self.masks.get(src1);
                    let mask_b = self.masks.get(src2);
                    let mask_g = self.share_g[next_idx];

                    // add input masks to the next multiplication batch
                    self.share_a.push(mask_a);
                    self.share_b.push(mask_b);
                    debug_assert_eq!(self.share_a.len(), self.share_b.len());
                    debug_assert!(self.share_a.len() <= D::Batch::DIMENSION);

                    // check that all shares for the omitted player are zero
                    debug_assert_eq!(
                        mask_g.get(self.omitted),
                        <D::Sharing as RingModule>::Scalar::ZERO
                    );
                    debug_assert_eq!(
                        self.masks.get(src1).get(self.omitted),
                        <D::Sharing as RingModule>::Scalar::ZERO
                    );
                    debug_assert_eq!(
                        self.masks.get(src2).get(self.omitted),
                        <D::Sharing as RingModule>::Scalar::ZERO
                    );

                    // assign mask to output
                    self.masks.set(dst, mask_g);

                    // return input masks to online phase
                    masks.push(mask_a);
                    masks.push(mask_b);

                    // if the batch is full, stop.
                    if self.share_a.len() == D::Batch::DIMENSION {
                        return self.generate(ab_gamma);
                    }
                }
                Some(Instruction::Output(src)) => {
                    self.reconstruct.next()?;
                }
                None => {
                    if self.share_a.len() > 0 {
                        // pad with dummy values and compute last batch
                        self.share_a.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
                        self.share_b.resize(D::Batch::DIMENSION, D::Sharing::ZERO);
                        return self.generate(ab_gamma);
                    }
                }
            }
        }
    }

    pub fn next_sharings(&mut self, masks: &mut Vec<D::Sharing>, ab_gamma: &mut [D::Sharing]) {
        debug_assert_eq!(ab_gamma.len(), D::Batch::DIMENSION);
        self.pack_batch(masks, ab_gamma);
    }
}
