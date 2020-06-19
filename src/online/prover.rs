use super::*;

struct RingTranscript<B: RingBatch, const S: bool> {
    next: usize,
    store: bool,
    hasher: ElementHasher<B>,
    messages: RingVector<B>,
}

impl<B: RingBatch, const S: bool> RingTranscript<B, S> {
    fn new() -> Self {
        Self {
            next: 0,
            store: false,
            messages: RingVector::new(),
            hasher: ElementHasher::new(),
        }
    }

    fn store(&mut self) {
        self.store = true;
    }

    fn write(&mut self, elem: B::Element) {
        // add to transcript buffer
        if S && self.store {
            self.messages.set(self.next, elem);
            self.next += 1;
        }

        // add to transcript hash
        self.hasher.update(elem);
    }
}

/// To save memory we execute the online phase twice:
///
/// 1. To compute the inputs to the random oracle without saving the full trace for every player.
/// 2. To extract the trace only for the player that was omitted.
///
/// For a factor 2 in compute time, we get a ~ 64 times saving in memory.
///
/// The S generic denotes wether to save the messages broadcasted by the "omit" player.
struct PublicState<B: RingBatch, const S: bool> {
    wires: RingVector<B>,
}

struct PlayerState<B: RingBatch, const S: bool> {
    // view transcript for player
    view: View,

    //
    sent: RingTranscript<B, S>,

    // mask generator
    mask_rng: ElementRNG<B, ViewRNG>,

    // shares of wire masks (initially holds the masks for the inputs)
    masks: RingVector<B>,
}

struct ExecutionFull<B: RingBatch, const N: usize, const NT: usize, const S: bool> {
    random: TreePRF<NT>,
    beaver: PreprocessingFull<B, ViewRNG, N, S>,
    public: PublicState<B, S>,
    players: [PlayerState<B, S>; N],
    omitted: usize,
}

struct Proof<B: RingBatch, const N: usize, const NT: usize> {
    random: TreePRF<NT>,
    omitted: RingArray<B>,
}

impl<B: RingBatch, const N: usize, const NT: usize, const S: bool> ExecutionFull<B, N, NT, S> {
    /// Takes the seed for the random tapes (used for pre-processing and input masking)
    ///
    ///
    fn new(seed: [u8; KEY_SIZE], inputs: &RingVector<B>, omit: usize) -> Self {
        let tree: TreePRF<NT> = TreePRF::new(seed);
        let keys: [_; N] = tree.expand();

        // generate initial player states
        let mut players: [PlayerState<B, S>; N] = arr_map(&keys, |key| {
            let view = View::new_keyed(key.unwrap());
            let mask_rng = ElementRNG::new(view.rng(LABEL_RNG_MASKS));
            PlayerState {
                view,
                sent: RingTranscript::new(),
                mask_rng,
                masks: RingVector::with_capacity(inputs.len()),
            }
        });

        // store the messages of the omitted player
        players[omit].sent.store();

        // create pre-processing instance
        let beaver: PreprocessingFull<B, ViewRNG, N, S> =
            PreprocessingFull::new(arr_map(&players, |player| {
                player.view.rng(LABEL_RNG_BEAVER)
            }));

        // create the global channel
        let mut public: PublicState<B, S> = PublicState {
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
        ExecutionFull {
            omitted: omit,
            random: tree,
            beaver,
            public,
            players,
        }
    }

    ///
    fn step(&mut self, ins: Instruction<B::Element>) -> Option<()> {
        match ins {
            Instruction::AddConst(dst, src, c) => {
                let w = self.public.wires.get(src)?;
                self.public.wires.set(dst, c + w);
            }

            Instruction::MulConst(dst, src, c) => {
                let w = self.public.wires.get(src)?;
                self.public.wires.set(dst, c * w);

                for player in self.players.iter_mut() {
                    let w = player.masks.get(src)?;
                    player.masks.set(dst, c * w);
                }
            }
            Instruction::Add(dst, src1, src2) => {
                let w1 = self.public.wires.get(src1)?;
                let w2 = self.public.wires.get(src2)?;
                self.public.wires.set(dst, w1 + w2);

                for player in self.players.iter_mut() {
                    let w1 = player.masks.get(src1)?;
                    let w2 = player.masks.get(src2)?;
                    player.masks.set(dst, w1 + w2);
                }
            }
            Instruction::Mul(dst, src1, src2) => {
                let w1 = self.public.wires.get(src1)?;
                let w2 = self.public.wires.get(src2)?;

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
                    player.masks.set(dst, mask);

                    // add the share (broadcast message) to the players view
                    player.sent.write(share);

                    s = s + share;
                }

                // reconstruct
                self.public.wires.set(dst, s + w1 * w2);
            }

            _ => unimplemented!(),
        }
        Some(())
    }
}

#[cfg(test)]
mod benchmark {
    use super::*;
    use crate::algebra::gf2::{Bit, BitBatch};

    use rayon::prelude::*;

    use test::Bencher;

    const MULTIPLICATIONS: u64 = 100_000;
    const ADDITIONS: u64 = 0;

    fn bench_online_execution<B: RingBatch, const N: usize, const NT: usize, const R: usize>(
        b: &mut Bencher,
    ) {
        let mut inputs: RingVector<BitBatch> = RingVector::new();

        inputs.set(0, Bit::new(1));
        inputs.set(1, Bit::new(1));

        b.iter(|| {
            let _: Vec<()> = vec![0u8; 44]
                .par_iter()
                .map(|_| {
                    let mut exec: ExecutionFull<BitBatch, N, NT, false> =
                        ExecutionFull::new([0u8; 16], &inputs, 0);

                    for _ in 0..MULTIPLICATIONS {
                        exec.step(Instruction::Mul(3, 0, 1));
                    }
                    for _ in 0..ADDITIONS {
                        exec.step(Instruction::Add(3, 0, 1));
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
