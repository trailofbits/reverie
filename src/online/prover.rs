use super::*;

use std::marker::PhantomData;

use rayon::prelude::*;

pub trait Transcript<B: RingBatch> {
    fn write(&mut self, elem: B::Element);
}


struct PublicState<'a, B: RingBatch, T: Transcript<B>> {
    wires: RingVector<B>,

    // we write to the transcript in "round-robin"
    transcript: &'a mut T
}

struct SavedTranscript<B: RingBatch, const N: usize> {
    save: usize,
    next: usize,
    transcript: RingVector<B>,
}

impl <B: RingBatch, const N: usize> SavedTranscript<B, N> {
    fn new(save: usize) -> Self {
        Self {
            next: 0,
            save,
            transcript: RingVector::new(),
        }
    }

    fn inner(self) -> RingVector<B> {
        self.transcript
    }
}

impl<B: RingBatch> Transcript<B> for ElementHasher<B> {
    fn write(&mut self, elem: B::Element) {
        self.update(elem)
    }
}

impl<B: RingBatch, const N: usize> Transcript<B> for SavedTranscript<B, N> {
   
    fn write(&mut self, elem: B::Element) {
        if self.save == 0 {
            // save the current element
            self.transcript.set(self.next, elem);
            self.next += 1;

            // save next element in N invocations
            self.save = N; 
        } else {
            self.save -= 1;
        }
    }
}

struct PlayerState<B: RingBatch, > {
    // view transcript for player
    view: View,

    // mask generator
    mask_rng: ElementRNG<B, ViewRNG>,

    // shares of wire masks (initially holds the masks for the inputs)
    masks: RingVector<B>,
}

pub struct Execution<'a, B: RingBatch, T: Transcript<B>, const N: usize, const NT: usize> {
    beaver: PreprocessingFull<B, ViewRNG, N, true>,
    public: PublicState<'a, B, T>,
    players: Box<[PlayerState<B>; N]>,
}

pub struct Proof<B: RingBatch, const N: usize, const NT: usize> {
    transcripts: Vec<RingVector<B>>,
    _ph: PhantomData<B>,
}

impl<B: RingBatch, const N: usize, const NT: usize> Proof<B, N, NT> {
    /// 
    /// - seeds: A list of PRNG seeds used for every execution (of both pre-processing an online).
    pub fn new(seeds: &[[u8; KEY_SIZE]], program: &[Instruction<B::Element>], inputs: &RingVector<B>) -> Proof<B, N, NT> {

        // expand keys for every player
        let keys: Vec<Box<[[u8; KEY_SIZE]; N]>> = seeds.par_iter().map(|seed| {
            let tree: TreePRF<NT> = TreePRF::new(*seed);
            arr_map!(&tree.expand(), |x: &Option<[u8; KEY_SIZE]>| x.unwrap())
        }).collect();

        println!("first");

        // first execution to obtain challenges
        let hashes: Vec<Hash> = keys.par_iter().map(|keys| {
            let mut transcript = ElementHasher::<B>::new();
            let mut exec = Execution::<B, ElementHasher<B>, N, NT>::new(keys, &mut transcript, inputs, 1024);
            for ins in program {
                exec.step(ins);
            }
            transcript.finalize()
        }).collect();

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
        
        println!("second");


        // second execution to obtain proof
        let jobs: Vec<(&usize, &Box<[[u8; KEY_SIZE]; N]>)> = hidden.iter().zip(keys.iter()).collect();
        let transcripts: Vec<RingVector<B>> = jobs.par_iter().map(|(hide, keys)| {
            let mut transcript = SavedTranscript::new(**hide);
            let mut exec = Execution::<B, SavedTranscript<B, N>, N, NT>::new(keys, &mut transcript, inputs, 1024);
            for ins in program {
                exec.step(ins);
            }
            transcript.inner()
        }).collect();

        Proof{
            _ph: PhantomData,
            transcripts
        }

        
    }
}

impl<'a, B: RingBatch, T: Transcript<B>, const N: usize, const NT: usize> Execution<'a, B, T, N, NT> {
    /// Takes the seed for the random tapes (used for pre-processing and input masking)
    ///
    ///
    fn new(keys: &[[u8; KEY_SIZE]; N], transcript: &'a mut T, inputs: &RingVector<B>, capacity: usize) -> Self {
        // generate initial player states
        // TODO: this runs out of stack memory
        let mut players: Box<[PlayerState<B>; N]> = arr_map!(keys, |key| {
            let view = View::new_keyed(key);
            let mask_rng = ElementRNG::new(view.rng(LABEL_RNG_MASKS));
            PlayerState {
                view,
                mask_rng,
                masks: RingVector::with_capacity(capacity),
            }
        });

        // create pre-processing instance
        let beaver: PreprocessingFull<B, ViewRNG, N, true> =
            PreprocessingFull::new(arr_map!(&*players, |player| {
                player.view.rng(LABEL_RNG_BEAVER)
            }));

        // create the global channel
        let mut public: PublicState<'a, B, T> = PublicState {
            transcript,
            wires: RingVector::with_capacity(inputs.len()),
        };

        // TODO: consider packing as detailed in the paper
        // (allowing parallel operation on all shares, but makes the generic interface harder)
        //
        // This code is not exactly efficient: it operates bitwise for GF(2)
        for i in 0..inputs.len() {
            let mut masked = inputs.get(i).unwrap();
            for player in players.iter_mut() {
                let mask = player.mask_rng.gen();
                masked = masked - mask;
                player.masks.set(i, mask)
            }
            public.wires.set(i, masked);
        }

        // bundle up the initial state for the interpreter
        Execution {
            beaver,
            public,
            players,
        }
    }

    ///
    pub fn step(&mut self, ins: &Instruction<B::Element>) -> Option<()> {
        match ins {
            Instruction::AddConst(dst, src, c) => {
                let w = self.public.wires.get(*src)?;
                self.public.wires.set(*dst, *c + w);
            }

            Instruction::MulConst(dst, src, c) => {
                let w = self.public.wires.get(*src)?;
                self.public.wires.set(*dst, *c * w);

                for player in self.players.iter_mut() {
                    let w = player.masks.get(*src)?;
                    player.masks.set(*dst, *c * w);
                }
            }
            Instruction::Add(dst, src1, src2) => {
                let w1 = self.public.wires.get(*src1)?;
                let w2 = self.public.wires.get(*src2)?;
                self.public.wires.set(*dst, w1 + w2);

                for player in self.players.iter_mut() {
                    let w1 = player.masks.get(*src1)?;
                    let w2 = player.masks.get(*src2)?;
                    player.masks.set(*dst, w1 + w2);
                }
            }
            Instruction::Mul(dst, src1, src2) => {
                let w1 = self.public.wires.get(*src1)?;
                let w2 = self.public.wires.get(*src2)?;

                // generate the next beaver triple
                let tp = self.beaver.next();

                // compute the reconstructed value
                let mut s: B::Element = B::Element::zero();

                // locally compute shares
                for (share, player) in tp.iter().zip(self.players.iter_mut()) {
                    // generate new mask to mask reconstruction (and result)
                    let mask = player.mask_rng.gen();

                    // compute local share
                    let share = w1 * share.0 + w2 * share.1 + share.2 + mask;

                    // store the new mask
                    player.masks.set(*dst, mask);

                    // add the share (broadcast message) to the transcript
                    self.public.transcript.write(share);

                    s = s + share;
                }

                // reconstruct
                self.public.wires.set(*dst, s + w1 * w2);
            }

            Instruction::Output(src) => {}
        }
        Some(())
    }

}

#[cfg(test)]
#[cfg(not(debug_assertions))] // omit for testing
mod benchmark {
    use super::*;
    use crate::algebra::gf2::{Bit, BitBatch};

    use rayon::prelude::*;

    use test::Bencher;

    const MULTIPLICATIONS: u64 = 100_000;

    /*
    fn bench_online_execution<B: RingBatch, const N: usize, const NT: usize, const R: usize>(
        b: &mut Bencher,
    ) {
        let mut inputs: RingVector<BitBatch> = RingVector::new();

        inputs.set(0, Bit::new(1));
        inputs.set(1, Bit::new(1));

        b.iter(|| {
            let _: Vec<()> = vec![0u8; R]
                .par_iter()
                .map(|_| {
                    let mut exec: Execution<BitBatch, ElementHasher<BitBatch>, N, NT> =
                        Execution::new(Box<[0u8; 16]>, arr_from_iter!((0..N).map(|_| ElementHasher<BitBatch>::new())), &inputs, 1024);

                    for _ in 0..MULTIPLICATIONS {
                        exec.step(&Instruction::Mul(3, 0, 1));
                    }
                })
                .collect();
        });
    }

    #[bench]
    fn bench_online_execution_n64(b: &mut Bencher) {
        bench_online_execution::<BitBatch, 64, 64, 23>(b);
    }

    #[bench]
    fn bench_online_execution_n8(b: &mut Bencher) {
        bench_online_execution::<BitBatch, 8, 8, 44>(b);
    }
    */
}
