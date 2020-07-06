use super::*;

use crate::Instruction;

use rand_core::RngCore;

/// Implementation of pre-processing phase used by the prover during online execution
pub struct PreprocessingExecution<'a, 'b, 'c, 'd, D: Domain, R: RngCore, const N: usize> {
    next: usize,
    omitted: usize,                                                 // omitted player
    broadcast: &'a [D::Batch],                                      // messages
    corrections: &'b [D::Batch],                                    // player 0 corrections
    program: &'c [Instruction<<D::Sharing as RingModule>::Scalar>], // statement
    rngs: &'d mut [R; N],                                           // rngs
    batch_g: [D::Batch; N],                                         // gamma batch
    masks: VecMap<D::Sharing>,                                      //
    share_ab_gamma: Vec<D::Sharing>,                                //
    share_a: Vec<D::Sharing>,                                       // beta sharings (from input)
    share_b: Vec<D::Sharing>,                                       // alpha sharings (from input)
    share_g: Vec<D::Sharing>,                                       // gamma sharings (output)
}

impl<'a, 'b, 'c, 'd, D: Domain, R: RngCore, const N: usize>
    PreprocessingExecution<'a, 'b, 'c, 'd, D, R, N>
{
    pub fn new(
        rngs: &'d mut [R; N],
        inputs: usize,
        omitted: usize,
        broadcast: &'a [D::Batch],
        corrections: &'b [D::Batch],
        program: &'c [Instruction<<D::Sharing as RingModule>::Scalar>],
    ) -> Self {
        debug_assert!(omitted < N);
        debug_assert!(corrections.len() == 0 || omitted != 0);
        debug_assert!(
            omitted == 0 || (corrections.len() == broadcast.len()),
            "omitted = {}, corrections.len() = {}, broadcast.len() = {}",
            omitted,
            corrections.len(),
            broadcast.len()
        );

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
        let mut ins = PreprocessingExecution {
            next: 0,
            corrections,
            broadcast,
            rngs,
            program,
            omitted,
            batch_g: [D::Batch::ZERO; N],
            share_ab_gamma: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_g: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_a: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            share_b: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            masks: masks.into(),
        };

        // generate the initial batch
        ins.pack_batch();
        ins
    }

    #[inline(always)]
    fn generate(&mut self) {
        debug_assert!(self.broadcast.len() > 0);
        debug_assert!(self.omitted == 0 || (self.corrections.len() == self.broadcast.len()),);

        let mut batches_a: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_b: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_c: [D::Batch; N] = [D::Batch::ZERO; N];
        let mut batches_gab: [D::Batch; N] = [D::Batch::ZERO; N];

        // transpose sharings into per player batches
        D::convert_inv(&mut batches_a[..], &self.share_a[..]);
        D::convert_inv(&mut batches_b[..], &self.share_b[..]);

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..N {
            if i == self.omitted {
                batches_c[i] = D::Batch::ZERO;
                batches_gab[i] = self.broadcast[0];
                self.broadcast = &self.broadcast[1..];

                #[cfg(test)]
                println!("batches_gab[{}] = {:?} (omitted)", i, batches_gab[i]);
            } else {
                batches_c[i] = D::Batch::gen(&mut self.rngs[i]);
                if i == 0 {
                    // correct shares for player 0 (correction bits)
                    batches_c[0] = batches_c[0] + self.corrections[0];
                    self.corrections = &self.corrections[1..];
                }
                batches_gab[i] = batches_c[i] + self.batch_g[i];

                #[cfg(test)]
                println!("batches_gab[{}] = {:?}", i, batches_gab[i]);
            }
        }

        // return ab_gamma shares
        D::convert(&mut self.share_ab_gamma[..], &batches_gab);
    }

    #[inline(always)]
    fn pack_batch(&mut self) {
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
        let mut mults = 0;
        for (i, ins) in self.program.iter().enumerate() {
            match *ins {
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
                    // resolve inputs
                    let sw1 = self.masks.get(src1);
                    let sw2 = self.masks.get(src2);

                    // compute the sum and set output wire
                    self.masks.set(dst, sw1 + sw2);
                }
                Instruction::Mul(dst, src1, src2) => {
                    // push the masks to the Beaver stack
                    self.share_a[mults] = self.masks.get(src1);
                    self.share_b[mults] = self.masks.get(src2);
                    let gamma = self.share_g[mults];
                    mults += 1;

                    // check that all shares for the omitted player are zero
                    debug_assert_eq!(
                        gamma.get(self.omitted),
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
                    self.masks.set(dst, gamma);

                    // if the batch is full, stop.
                    if mults == D::Batch::DIMENSION {
                        self.program = &self.program[i + 1..];
                        self.generate();
                        return;
                    }
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
            self.generate();
        }
    }
}

impl<'a, 'b, 'c, 'd, D: Domain, R: RngCore, const N: usize> Preprocessing<D>
    for PreprocessingExecution<'a, 'b, 'c, 'd, D, R, N>
{
    fn mask(&self, idx: usize) -> D::Sharing {
        self.masks.get(idx)
    }

    /// Return the next ab_gamma sharings for reconstruction
    fn next_ab_gamma(&mut self) -> D::Sharing {
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
