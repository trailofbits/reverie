use super::*;

use crate::algebra::{Domain, RingElement, RingModule, Serializable, Sharing};
use crate::consts::{LABEL_RNG_BEAVER, LABEL_RNG_MASKS};
use crate::pp::prover::PreprocessingExecution;
use crate::util::Writer;

use std::io::Write;

pub struct OnlineExecution<
    'a,
    'b,
    'c,
    D: Domain,             // algebraic domain
    W: Writer<D::Batch>,   // writer for player 0 shares
    T: Writer<D::Sharing>, // transcript for public channel
    const N: usize,
    const NT: usize,
> {
    output: Vec<<D::Sharing as RingModule>::Scalar>,
    transcript: &'c mut T,
    preprocessing: PreprocessingExecution<'a, 'b, D, W, ViewRNG, N, true>,
    wires: Vec<<D::Sharing as RingModule>::Scalar>,
}

pub fn execute<
    D: Domain,
    W: Writer<D::Batch>,
    T: Writer<D::Sharing>,
    const N: usize,
    const NT: usize,
>(
    keys: &[[u8; KEY_SIZE]; N],
    zero: &mut W,
    inputs: &[<D::Sharing as RingModule>::Scalar],
    transcript: &mut T,
    mut program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
) {
    // create pre-processing instance
    let views: Box<[View; N]> = arr_map!(keys, |key| View::new_keyed(key));
    let mut rngs: Box<[ViewRNG; N]> = arr_map!(&views, |view| { view.rng(LABEL_RNG_BEAVER) });
    let mut preprocessing: PreprocessingExecution<D, W, ViewRNG, N, true> =
        PreprocessingExecution::new(&mut *rngs, zero, inputs.len());

    // mask the inputs
    let mut wires: Vec<<D::Sharing as RingModule>::Scalar> = Vec::with_capacity(inputs.len());
    for (i, input) in inputs.iter().enumerate() {
        let mask: D::Sharing = preprocessing.masks.get(i);
        wires.push(*input - mask.reconstruct());
    }

    // a * b + \gamma sharings
    let mut ab_gamma = vec![<D::Sharing as RingElement>::ZERO; D::Batch::DIMENSION];

    // execute program in batches of D::Batch::DIMENSION multiplications
    while program.len() > 0 {
        let mut next = 0;
        let steps = preprocessing.next_batch(&mut ab_gamma[..], program);

        for i in 0..steps {
            match program[i] {
                Instruction::AddConst(dst, src, c) => {
                    let sw = wires[src];
                    wires[dst] = sw + c;
                }
                Instruction::MulConst(dst, src, c) => {
                    let sw = wires[src];
                    wires[dst] = sw * c;
                }
                Instruction::Add(dst, src1, src2) => {
                    let sw1 = wires[src1];
                    let sw2 = wires[src2];
                    wires[dst] = sw1 + sw2;
                }
                Instruction::Mul(dst, src1, src2) => {
                    let sw1 = wires[src1];
                    let sw2 = wires[src2];

                    // calculate reconstruction shares for every player
                    let a: D::Sharing = preprocessing.masks.get(src1);
                    let b: D::Sharing = preprocessing.masks.get(src2);
                    let recon = a.action(sw1) + b.action(sw2) + ab_gamma[next];

                    // we used an ab_gamma sharing
                    next += 1;

                    // append messages from all players to transcript
                    transcript.write(&recon);

                    // reconstruct and correct share
                    wires[dst] = recon.reconstruct() + sw1 * sw2;
                }
                Instruction::Output(src) => (),
            }
        }

        // move to next batch
        program = &program[steps..];
    }
}

/*
impl<
        'a,
        'b,
        'c,
        D: Domain,
        W: Writer<D::Batch>,
        T: Writer<D::Sharing>,
        const N: usize,
        const NT: usize,
    > OnlineExecution<'a, 'b, 'c, D, W, T, N, NT>
{
    /// Takes the seed for the random tapes (used for pre-processing and input masking)
    ///
    ///
    pub fn new(
        keys: &[[u8; KEY_SIZE]; N],
        zero: &'a mut W,
        inputs: &[<D::Sharing as RingModule>::Scalar],
        transcript: &'b mut T,
    ) -> Self {
        // create pre-processing instance (pre-processing is executed in parallel:
        // the online phase encapsulates an pre-processing instance which does not have access to the witness)
        let views: Box<[View; N]> = arr_map!(keys, |key| View::new_keyed(key));
        let preprocessing = PreprocessingExecution::new(
            arr_map!(&views, |view| { view.rng(LABEL_RNG_BEAVER) }),
            zero,
            inputs.len(),
        );

        // mask the inputs
        let mut wires: Vec<<D::Sharing as RingModule>::Scalar> = Vec::with_capacity(inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            let mask: D::Sharing = preprocessing.masks[i];
            wires.push(*input - mask.reconstruct());
        }

        OnlineExecution {
            output: Vec::new(),
            ab_gamma: vec![<D::Sharing as RingElement>::ZERO; D::Batch::DIMENSION],
            ab_gamma_next: D::Batch::DIMENSION,
            preprocessing,
            transcript,
            wires,
        }
    }

    ///
    fn step(&mut self, ins: &Instruction<<D::Sharing as RingModule>::Scalar>) -> bool {
        match ins {
            Instruction::AddConst(dst, src, c) => {
                let sw = self.wires[*src];
                self.wires[*dst] = sw + *c;
                false
            }

            Instruction::MulConst(dst, src, c) => {
                let sw = self.wires[*src];
                self.wires[*dst] = sw * *c;
                false
            }
            Instruction::Add(dst, src1, src2) => {
                let sw1 = self.wires[*src1];
                let sw2 = self.wires[*src2];
                self.wires[*dst] = sw1 + sw2;
                false
            }
            Instruction::Mul(dst, src1, src2) => {
                let sw1 = self.wires[*src1];
                let sw2 = self.wires[*src2];

                // calculate reconstruction shares for every player
                let a = self.preprocessing.masks[*src1];
                let b = self.preprocessing.masks[*src2];

                let abm = self.ab_gamma[self.ab_gamma_next];
                let recon = a.action(sw1) + b.action(sw2) + abm;

                // append messages from all players to transcript
                self.transcript.write(&recon);

                // reconstruct and correct share
                self.wires[*dst] = recon.reconstruct() + sw1 * sw2;

                // we used an ab_gamma sharing
                self.ab_gamma_next += 1;
                true
            }

            Instruction::Output(src) => false,
        }
    }

    pub fn execute(mut self, mut program: &[Instruction<<D::Sharing as RingModule>::Scalar>]) {
        loop {
            let steps = self
                .preprocessing
                .next_batch(&mut self.ab_gamma[..], program);
            self.ab_gamma_next = 0;

            for i in 0..steps {
                self.step(&program[i]);
            }

            // move to next batch
            program = &program[steps..];
        }
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::proof::StoredTranscript;
    use super::*;

    use crate::algebra::gf2::{GF2P64, GF2P8};
    use crate::algebra::RingElement;

    use rayon::prelude::*;

    use std::io::{sink, Sink};

    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    use test::{black_box, Bencher};

    const MULTIPLICATIONS: u64 = 100_000;

    fn bench_online_execution<D: Domain, const N: usize, const NT: usize, const R: usize>(
        b: &mut Bencher,
    ) {
        let one = <<D::Sharing as RingModule>::Scalar as RingElement>::ONE;
        let zero = <<D::Sharing as RingModule>::Scalar as RingElement>::ZERO;
        let mut inputs: Vec<<D::Sharing as RingModule>::Scalar> = vec![one, one, one];

        b.iter(|| {
            let _: Vec<()> = vec![0u8; R]
                .par_iter()
                .map(|_| {
                    let keys: [[u8; 16]; N] = [[0u8; 16]; N];

                    let mut transcript: StoredTranscript<D::Sharing> = StoredTranscript::new();

                    let mut writer = sink();
                    let mut exec: Execution<D, Sink, _, N, NT> =
                        Execution::new(&keys, &mut writer, &inputs[..], &mut transcript);

                    for _ in 0..MULTIPLICATIONS {
                        exec.step(&Instruction::Mul(2, 0, 1));
                    }
                })
                .collect();
        });
    }

    #[bench]
    fn bench_online_execution_n8(b: &mut Bencher) {
        bench_online_execution::<GF2P8, 8, 8, 44>(b);
    }

    #[bench]
    fn bench_online_execution_n64(b: &mut Bencher) {
        bench_online_execution::<GF2P64, 64, 64, 23>(b);
    }
}
*/
