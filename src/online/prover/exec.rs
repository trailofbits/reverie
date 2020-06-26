use super::*;

use crate::algebra::{Domain, RingModule, Serializable, Sharing};
use crate::consts::{LABEL_RNG_BEAVER, LABEL_RNG_MASKS};
use crate::pp::ProverOnlinePreprocessing;

use std::io::Write;

pub trait Transcript<T> {
    fn append(&mut self, message: T);
}

pub struct Execution<
    'a,
    'b,
    D: Domain,                 // algebraic domain
    W: Write,                  // writer for player 0 shares
    T: Transcript<D::Sharing>, // transcript for public channel
    const N: usize,
    const NT: usize,
> {
    output: Vec<<D::Sharing as RingModule>::Scalar>,
    preprocessing: ProverOnlinePreprocessing<'a, D, W, ViewRNG, N>,
    transcript: &'b mut T,
    mask: SharingRng<D, ViewRNG, N>,
    wire: Vec<(<D::Sharing as RingModule>::Scalar, D::Sharing)>,
}

impl<'a, 'b, D: Domain, W: Write, T: Transcript<D::Sharing>, const N: usize, const NT: usize>
    Execution<'a, 'b, D, W, T, N, NT>
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
        // create just-in-time pre-processing instance

        let views: Box<[View; N]> = arr_map!(keys, |key| View::new_keyed(key));
        let preprocessing = ProverOnlinePreprocessing::new(
            arr_map!(&views, |view| { view.rng(LABEL_RNG_BEAVER) }),
            zero,
        );

        // encrypt the inputs

        let mut mask = SharingRng::new(arr_map!(&views, |view| { view.rng(LABEL_RNG_MASKS) }));
        let mut wire: Vec<(<D::Sharing as RingModule>::Scalar, D::Sharing)> =
            Vec::with_capacity(inputs.len());

        for input in inputs {
            let m: D::Sharing = mask.gen();
            wire.push((*input - m.reconstruct(), m));
        }

        Execution {
            output: Vec::new(),
            preprocessing,
            transcript,
            mask,
            wire,
        }
    }

    ///
    pub fn step(&mut self, ins: &Instruction<<D::Sharing as RingModule>::Scalar>) {
        match ins {
            Instruction::AddConst(dst, src, c) => {
                let sw = self.wire[*src];
                self.wire[*dst] = (sw.0 + (*c), sw.1);
            }

            Instruction::MulConst(dst, src, c) => {
                let sw = self.wire[*src];
                self.wire[*dst] = (sw.0 * (*c), sw.1.action(*c));
            }
            Instruction::Add(dst, src1, src2) => {
                let sw1 = self.wire[*src1];
                let sw2 = self.wire[*src2];
                self.wire[*dst] = (sw1.0 + sw2.0, sw1.1 + sw2.1);
            }
            Instruction::Mul(dst, src1, src2) => {
                let sw1 = self.wire[*src1];
                let sw2 = self.wire[*src2];

                // generate the next beaver triple
                let (a, b, ab) = self.preprocessing.next();

                // generate new mask to mask reconstruction (and result)
                let m = self.mask.gen();

                // calculate reconstruction shares for every player
                let r = a.action(sw1.0) + b.action(sw2.0) + ab + m;

                // append messages from all players to transcript
                self.transcript.append(r);

                // reconstruct and correct share
                self.wire[*dst] = (r.reconstruct() + sw1.0 * sw2.0, m);
            }

            Instruction::Output(src) => {
                let sw = self.wire[*src];

                // reconstruct the mask and decrypt the masked wire
                self.output.push(sw.0 + sw.1.reconstruct())
            }
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
