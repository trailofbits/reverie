use super::*;

struct RingTranscript<B: RingBatch> {
    next: usize,
    messages: RingVector<B>,
}

impl<B: RingBatch> RingTranscript<B> {
    fn new() -> Self {
        Self {
            next: 0,
            messages: RingVector::new(),
        }
    }

    fn write(&mut self, elem: B::Element) {
        self.messages.set(self.next, elem);
        self.next += 1;
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
    // View transcript for global channel
    view: View,

    // Masked wire values (initially holds the masked inputs)
    wires: RingVector<B>,

    // Broadcast messages from the omitted player.
    // These are provided to the verifier during proof verification to allow him to re-compute the public channel.
    // These fields are only used when S = true
    omit: usize,
    messages: RingTranscript<B>,
}

struct PlayerState<B: RingBatch> {
    // view transcript for player
    view: View,

    // messages
    sent: ElementHasher<B>,

    // shares of wire masks (initially holds the masks for the inputs)
    masks: RingVector<B>,
}

struct ExecutionFull<B: RingBatch, const N: usize, const NT: usize, const S: bool> {
    beaver: PreprocessingFull<B, ViewRNG, N, S>,
    public: PublicState<B, S>,
    players: [PlayerState<B>; N],
}

impl<'a, B: RingBatch, const N: usize, const NT: usize, const S: bool> ExecutionFull<B, N, NT, S> {
    /// Takes the seed for the random tapes (used for pre-processing and input masking)
    ///
    /// The number of inputs is assumed to be a multiple of the batch size.
    /// If it is not, the remaining "input wires" will hold junk values,
    /// which should have no effect since any sound program should never read from them.
    ///
    ///
    fn new(seed: [u8; KEY_SIZE], inputs: &RingVector<B>, omit: usize) -> Self {
        let tree: TreePRF<NT> = TreePRF::new(seed);
        let keys: [_; N] = tree.expand();

        // generate initial player states
        let mut players: [PlayerState<B>; N] = arr_map(&keys, |key| PlayerState {
            sent: ElementHasher::new(),
            view: View::new_keyed(key.unwrap()),
            masks: RingVector::with_capacity(inputs.len()),
        });

        // create pre-processing instance
        let beaver: PreprocessingFull<B, ViewRNG, N, S> =
            PreprocessingFull::new(arr_map(&players, |player| {
                player.view.rng(LABEL_RNG_BEAVER)
            }));

        // create the global channel
        let mut public: PublicState<B, S> = PublicState {
            omit,
            view: View::new(),
            wires: RingVector::with_capacity(inputs.len()),
            messages: RingTranscript::new(),
        };

        // generate masked inputs
        let mut prngs = arr_map(&players, |player| player.view.rng(LABEL_RNG_INPUT));
        for input in inputs.batch_iter() {
            let mut masked: B = *input;
            for (prng, player) in prngs.iter_mut().zip(players.iter_mut()) {
                let elem = B::gen(prng);
                masked = masked - elem;
                player.masks.batch_push(elem);
            }
            public.wires.batch_push(masked)
        }

        // bundle up the initial state for the interpreter
        ExecutionFull {
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
                let s: B::Element = B::Element::zero();

                // locally compute shares
                for (i, (share, player)) in tp.iter().zip(self.players.iter_mut()).enumerate() {
                    let mn = unimplemented!();
                    let m1 = player.masks.get(src1)?;
                    let m2 = player.masks.get(src2)?;

                    // compute local share
                    let share = w1 * share.0 + w2 * share.1 + share.2 + mn;

                    // check if we should store this players message
                    if S && i == self.public.omit {
                        self.public.messages.write(share);
                    }

                    // add the share (broadcast message) to the players view
                    player.sent.update(share);

                    s = s + share;
                }

                // reconstruct
                self.public.wires.set(dst, s);
            }

            _ => unimplemented!(),
        }
        Some(())
    }
}
