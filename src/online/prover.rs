use super::*;

use typenum::{PowerOfTwo, Unsigned};

struct PublicState<B: RingBatch> {
    // view transcript for global channel
    view: View,

    // masked wire values (initially holds the masked inputs)
    wires: RingVector<B>,
}

struct PlayerState<B: RingBatch> {
    // view transcript for player
    view: View,

    // shares of wire masks (initially holds the masks for the inputs)
    masks: RingVector<B>,
}

struct Execution<B: RingBatch, R: RngCore, const N: usize, const NT: usize> {
    beaver: PreprocessingFull<B, R, N, true>,
    public: PublicState<B>,
    players: [PlayerState<B>; N],
}

impl<B: RingBatch, R: RngCore, const N: usize, const NT: usize> Execution<B, R, N, NT> {
    /// Takes the seed for the random tapes (used for pre-processing and input masking)
    ///
    /// The number of inputs is assumed to be a multiple of the batch size.
    /// If it is not, the remaining "input wires" will hold junk values,
    /// which should have no effect since any sound program should never read from them.
    ///
    ///
    fn new(seed: [u8; KEY_SIZE], inputs: RingVector<B>) {
        let tree: TreePRF<NT> = TreePRF::new(seed);
        let keys: [_; N] = tree.expand();

        // generate initial player states
        let mut players: [PlayerState<B>; N] = arr_map(&keys, |key| PlayerState {
            view: View::new_keyed(key.unwrap()),
            masks: RingVector::with_capacity(inputs.len()),
        });

        // create pre-processing instance
        let beaver: PreprocessingFull<B, ViewRNG, N, true> =
            PreprocessingFull::new(arr_map(&players, |player| {
                player.view.rng(LABEL_RNG_BEAVER)
            }));

        // create the global channel
        let mut public: PublicState<B> = PublicState {
            view: View::new(),
            wires: RingVector::with_capacity(inputs.len()),
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
    }
}
