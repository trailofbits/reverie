use super::*;

struct PublicState<B: RingBatch> {
    wires: RingVector<B>,
}

pub trait Transcript<B: RingBatch> {
    fn new() -> Self;
    fn write(&mut self, elem: B::Element);
}

impl<B: RingBatch> Transcript<B> for ElementHasher<B> {
    fn new() -> Self {
        ElementHasher::new()
    }

    fn write(&mut self, elem: B::Element) {
        self.update(elem)
    }
}

struct SavedTranscript<B: RingBatch> {
    vec: RingVector<B>,
    next: usize,
}

impl<B: RingBatch> Transcript<B> for SavedTranscript<B> {
    fn new() -> Self {
        SavedTranscript {
            vec: RingVector::new(),
            next: 0,
        }
    }

    fn write(&mut self, elem: B::Element) {
        self.vec.set(self.next, elem);
        self.next += 1;
    }
}

struct PlayerState<B: RingBatch, T: Transcript<B>> {
    // view transcript for player
    view: View,

    // all messages broadcast by the player
    sent: T,

    // mask generator
    mask_rng: ElementRNG<B, ViewRNG>,

    // shares of wire masks (initially holds the masks for the inputs)
    masks: RingVector<B>,
}

pub struct Execution<B: RingBatch, T: Transcript<B>, const N: usize, const NT: usize> {
    random: TreePRF<NT>,
    beaver: PreprocessingFull<B, ViewRNG, N, true>,
    public: PublicState<B>,
    players: Box<[PlayerState<B, T>; N]>,
}

struct Proof<const N: usize, const NT: usize> {
    random: TreePRF<NT>,
}

impl<B: RingBatch, T: Transcript<B>, const N: usize, const NT: usize> Execution<B, T, N, NT> {
    /// Takes the seed for the random tapes (used for pre-processing and input masking)
    ///
    ///
    pub fn new(seed: [u8; KEY_SIZE], inputs: &RingVector<B>, capacity: usize) -> Self {
        let tree: TreePRF<NT> = TreePRF::new(seed);
        let keys: [_; N] = tree.expand();

        // generate initial player states
        // TODO: this runs out of stack memory
        let mut players: Box<[PlayerState<B, T>; N]> = arr_map_box!(&keys, |key| {
            let view = View::new_keyed(key.unwrap());
            let mask_rng = ElementRNG::new(view.rng(LABEL_RNG_MASKS));
            PlayerState {
                view,
                sent: T::new(),
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
        let mut public: PublicState<B> = PublicState {
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
            random: tree,
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

                    // add the share (broadcast message) to the players view
                    player.sent.write(share);

                    s = s + share;
                }

                // reconstruct
                self.public.wires.set(*dst, s + w1 * w2);
            }

            Instruction::Output(src) => {}
        }
        Some(())
    }

    pub fn end(self) -> [T; N] {
        arr_map_owned(*self.players, |player| player.sent)
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
                        Execution::new([0u8; 16], &inputs, 1024);

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
}
