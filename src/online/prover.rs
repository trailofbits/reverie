use super::*;

use crate::algebra::{Domain, RingModule, Serializable, Sharing};
use crate::pp::ProverOnlinePreprocessing;

use super::SharingRng;

use std::io::Write;

use rayon::prelude::*;

pub trait Transcript<T> {
    fn append(&mut self, message: T);
}

impl<T> Transcript<T> for RingHasher<T>
where
    T: Serializable,
{
    fn append(&mut self, message: T) {
        self.update(message)
    }
}

pub struct Execution<
    'a,
    D: Domain,                 // algebraic domain
    W: Write,                  // writer for player 0 shares
    T: Transcript<D::Sharing>, // transcript for public channel
    const N: usize,
    const NT: usize,
> {
    preprocessing: ProverOnlinePreprocessing<D, W, ViewRNG, N>,
    transcript: &'a mut T,
    mask: SharingRng<D, ViewRNG, N>,
    wire: Vec<(<D::Sharing as RingModule>::Scalar, D::Sharing)>,
}

impl<'a, D: Domain, W: Write, T: Transcript<D::Sharing>, const N: usize, const NT: usize>
    Execution<'a, D, W, T, N, NT>
{
    /// Takes the seed for the random tapes (used for pre-processing and input masking)
    ///
    ///
    fn new(
        keys: &[[u8; KEY_SIZE]; N],
        zero: W,
        inputs: &[<D::Sharing as RingModule>::Scalar],
        transcript: &'a mut T,
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

            Instruction::Output(src) => {}
        }
    }
}

/*
impl<B: RingBatch, const N: usize, const NT: usize> Proof<B, N, NT> {
    ///
    /// - seeds: A list of PRNG seeds used for every execution (of both pre-processing an online).
    pub fn new(
        seeds: &[[u8; KEY_SIZE]],
        program: &[Instruction<B::Element>],
        inputs: &RingVector<B>,
    ) -> Proof<B, N, NT> {
        // expand keys for every player
        let keys: Vec<Box<[[u8; KEY_SIZE]; N]>> = seeds
            .par_iter()
            .map(|seed| {
                let tree: TreePRF<NT> = TreePRF::new(*seed);
                arr_map!(&tree.expand(), |x: &Option<[u8; KEY_SIZE]>| x.unwrap())
            })
            .collect();

        // first execution to obtain challenges
        let hashes: Vec<Hash> = keys
            .par_iter()
            .map(|keys| {
                let mut transcript = ElementHasher::<B>::new();
                let mut exec = Execution::<B, ElementHasher<B>, N, NT>::new(
                    keys,
                    &mut transcript,
                    inputs,
                    1024,
                );
                for ins in program {
                    exec.step(ins);
                }
                transcript.finalize()
            })
            .collect();

        // extract which players to open
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for hash in hashes.iter() {
                scope.join(hash);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        let mut hidden: Vec<usize> = Vec::with_capacity(seeds.len());
        for _ in 0..seeds.len() {
            hidden.push(random_usize::<_, N>(&mut rng));
        }

        // second execution to obtain proof
        let jobs: Vec<(&usize, &Box<[[u8; KEY_SIZE]; N]>)> =
            hidden.iter().zip(keys.iter()).collect();
        let transcripts: Vec<RingVector<B>> = jobs
            .par_iter()
            .map(|(hide, keys)| {
                let mut transcript = SavedTranscript::new(**hide);
                let mut exec = Execution::<B, SavedTranscript<B, N>, N, NT>::new(
                    keys,
                    &mut transcript,
                    inputs,
                    1024,
                );
                for ins in program {
                    exec.step(ins);
                }
                transcript.inner()
            })
            .collect();

        Proof {
            _ph: PhantomData,
            transcripts,
        }
    }
}
*/

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::*;

    use crate::algebra::gf2p8::GF2P8;

    use rayon::prelude::*;

    use std::io::{sink, Sink};

    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    use test::{black_box, Bencher};

    const MULTIPLICATIONS: u64 = 1_000_000;

    fn bench_online_execution<const N: usize, const NT: usize, const R: usize>(b: &mut Bencher) {
        let one = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ONE;
        let zero = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ZERO;
        let mut inputs: Vec<<<GF2P8 as Domain>::Sharing as RingModule>::Scalar> =
            vec![one, one, one];

        b.iter(|| {
            let _: Vec<()> = vec![0u8; R]
                .par_iter()
                .map(|_| {
                    let keys: [[u8; 16]; 8] = [[0u8; 16]; 8];

                    let mut transcript: RingHasher<<GF2P8 as Domain>::Sharing> = RingHasher::new();

                    let mut exec: Execution<GF2P8, Sink, _, 8, 8> =
                        Execution::new(&keys, sink(), &inputs[..], &mut transcript);

                    for _ in 0..MULTIPLICATIONS {
                        exec.step(&Instruction::Mul(2, 0, 1));
                    }
                })
                .collect();
        });
    }

    #[bench]
    fn bench_online_execution_n8(b: &mut Bencher) {
        bench_online_execution::<8, 8, 44>(b);
    }

    /*
    #[bench]
    fn bench_online_execution_n64(b: &mut Bencher) {
        bench_online_execution::<BitBatch, 64, 64, 23>(b);
    }

    */
}
