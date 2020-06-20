use super::*;

use std::io::{Seek, SeekFrom};
use std::mem;

use blake3::Hash;
use rand_core::RngCore;

pub struct State<B: RingBatch, R: RngCore> {
    rng: R,
    share_a: B,
    share_b: B,
    share_c: B,
}

impl<B: RingBatch, R: RngCore> State<B, R> {
    fn replenish(&mut self) {
        self.share_a = B::gen(&mut self.rng);
        self.share_b = B::gen(&mut self.rng);
        self.share_c = B::gen(&mut self.rng);
    }
}

/// Provides an execution of the pre-processing phase where every player state is know,
/// hence shares can be computed completely Just-In-Time, whenever the prover needs them.
///
/// - N: Number of players.
/// - S: Should the player 0 c shares be saved?
///
/// This is used for proving/verifying correct executions of the pre-processing phase (where S = false).
/// As well as proving during the online phase (where S = true),
/// where the c shares for player 0 must be included in the transcript.
pub struct PreprocessingFull<B: RingBatch, R: RngCore, const N: usize, const S: bool> {
    used: usize,            // elements used from current batch
    stat: [State<B, R>; N], // state of every player
    zero: RingVector<B>,    // corrected c shares for player 0
}

impl<B: RingBatch, R: RngCore, const N: usize, const S: bool> PreprocessingFull<B, R, N, S> {
    pub fn new(rngs: [R; N]) -> Self {
        // initialize the state for every player
        let mut stat: [State<B, R>; N] = arr_map_owned(rngs, |rng| State {
            rng,
            share_a: B::zero(),
            share_b: B::zero(),
            share_c: B::zero(),
        });

        // join into pre-processing context for entire protocol
        PreprocessingFull {
            used: B::BATCH_SIZE,
            zero: RingVector::new(),
            stat,
        }
    }

    pub fn next(&mut self) -> [(B::Element, B::Element, B::Element); N] {
        // check if every multiplication in batch has been used
        if self.used >= B::BATCH_SIZE {
            self.replenish();
            self.used = 0;
        }

        // extract the next single element from current batch
        let beavers: [(B::Element, B::Element, B::Element); N] = arr_map!(&self.stat, |s| {
            (
                s.share_a.get(self.used),
                s.share_b.get(self.used),
                s.share_c.get(self.used),
            )
        });

        // return shares for each player
        self.used += 1;
        beavers
    }

    /// Generate a the next batch of Beaver triples.
    fn replenish(&mut self) {
        debug_assert_eq!(self.used, B::BATCH_SIZE);

        // generate shares for players
        for i in 0..N {
            self.stat[i].replenish();
        }

        // calculate the shared elements
        let mut a = self.stat[0].share_a;
        let mut b = self.stat[0].share_b;
        let mut c = self.stat[0].share_c;
        for i in 1..N {
            a = a + self.stat[i].share_a;
            b = b + self.stat[i].share_b;
            c = c + self.stat[i].share_c;
        }

        // correct the share for player 0
        self.stat[0].share_c = c - a * b;

        // optionally save the pre-processing output
        if S {
            self.zero.batch_push(self.stat[0].share_c);
        }

        // assert correctness in debug builds
        #[cfg(debug)]
        {
            let mut a = B::zero();
            let mut b = B::zero();
            let mut c = B::zero();
            for i in 0..N {
                a = a + self.stat[i].share_a;
                b = b + self.stat[i].share_b;
                c = c + self.stat[i].share_c;
            }
            assert_eq!(a * b, c);
        }
    }

    pub fn hash(&mut self, batches: u64) -> Hash {
        let mut hasher: BatchHasher = BatchHasher::new();
        for _ in 0..batches {
            self.replenish();
            hasher.update(self.stat[0].share_c);
        }
        hasher.finalize()
    }

    pub fn zero(self) -> RingArray<B> {
        assert!(S, "shares not saved, invalid use");
        self.zero.into()
    }
}

/// Provides an execution of the pre-processing phase where the state of all-but-one of the players is known.
/// Shares for every player except player 0 can be computed completely Just-In-Time as before and immediately discarded.
///
/// - N: Number of players.
/// - S: Should the player 0 c shares be saved?
///
/// This is used for verification in the online phase.
///
/// Ths constructor takes an array of rngs, the index of the player omitted,
/// and the c shares for player 0 in case player 0 is not omitted.
///
pub struct PreprocessingPartial<B: RingBatch, R: RngCore, const N: usize> {
    used: usize,            // elements used from current batch
    omit: usize,            // index of player omitted
    bidx: usize,            // current batch index
    stat: [State<B, R>; N], // state of every player
    zero: RingArray<B>,     // corrected c shares for player 0 (if not omitted)
}

impl<B: RingBatch, R: RngCore, const N: usize> PreprocessingPartial<B, R, N> {
    /// rngs[omit] is a dummy.
    pub fn new(rngs: [R; N], omit: usize, zero: RingArray<B>) -> Self {
        // check that omit is a valid player
        debug_assert!(omit < N, "omitted player does not exist");

        // check that zero.len() > 0 => omit != 0
        debug_assert!(
            if zero.len() > 0 { omit != 0 } else { true },
            "omit = {}, zero.len() = {}",
            omit,
            zero.len()
        );

        // initialize the state for every player
        let mut stat: [State<B, R>; N] = arr_map_owned(rngs, |rng| State {
            rng,
            share_a: B::zero(),
            share_b: B::zero(),
            share_c: B::zero(),
        });

        // join into pre-processing context for entire protocol
        PreprocessingPartial {
            used: B::BATCH_SIZE,
            zero,
            omit,
            stat,
            bidx: 0,
        }
    }

    /// Extract a the next batch of partial shares for Beaver triples.
    ///
    /// This function can fail is there is insufficient corrected multiplication shares
    /// left for player 0: if the pre-processing was too short for the online phase.
    fn replenish(&mut self) -> Option<()> {
        debug_assert_eq!(self.used, B::BATCH_SIZE);

        // generate shares for players
        for (i, stat) in self.stat.iter_mut().enumerate() {
            if i != self.omit {
                stat.replenish();
            }
        }

        // if player zero is opened replace share with correction
        if self.omit != 0 {
            self.stat[0].share_c = self.zero.get_batch(self.bidx)?;
            self.bidx += 1;
        }

        // replenished successfully
        Some(())
    }

    /// Obtain the next partial shares for a single Beaver triple (single ring elements).
    ///
    /// For the omitted player it always returns zero (a dummy value).
    ///
    /// This function can fail is there is insufficient corrected multiplication shares
    /// left for player 0: if the pre-processing was too short for the online phase.
    pub fn next(&mut self) -> Option<[(B::Element, B::Element, B::Element); N]> {
        // check if every multiplication in batch has been used
        if self.used == B::BATCH_SIZE {
            self.replenish()?;
            self.used = 0;
        }

        // extract the next single element from current batch
        let beavers: [(B::Element, B::Element, B::Element); N] = arr_map!(&self.stat, |s| {
            (
                s.share_a.get(self.used),
                s.share_b.get(self.used),
                s.share_c.get(self.used),
            )
        });

        // return shares for each player
        self.used += 1;
        Some(beavers)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::algebra::gf2::*;
    use super::super::super::algebra::*;
    use super::*;

    use rand::Rng;

    #[test]
    fn test_full_partial_equal() {
        const PLAYERS: usize = 16;
        const BEAVERS: usize = 50_000;

        for _ in 0..32 {
            let mut rng = rand::thread_rng();

            let omit: usize = rng.gen::<usize>() % PLAYERS;
            let beavers: usize = rng.gen::<usize>() & BEAVERS;

            // get distinct player RNGS
            let rngs: [_; PLAYERS] = arr_from_iter(&mut (0..PLAYERS).into_iter().map(|i| {
                let mut k = [0u8; KEY_SIZE];
                k[0] = i as u8;
                View::new_keyed(k).rng("test".as_bytes())
            }));

            // create backup of initial state
            let mut orig = rngs.clone();

            // create preprocessing
            let mut full: PreprocessingFull<BitBatch, ViewRNG, PLAYERS, true> =
                PreprocessingFull::new(rngs);

            // get a bunch of shares
            let mut shares: Vec<_> = vec![];
            for _ in 0..beavers {
                shares.push(full.next());
            }

            // now dummy one of the rngs and run the partial pre-processing
            orig[omit] = View::new_keyed([1u8; KEY_SIZE]).rng("test".as_bytes());

            let mut partial: PreprocessingPartial<BitBatch, ViewRNG, PLAYERS> =
                PreprocessingPartial::new(
                    orig,
                    omit,
                    if omit == 0 {
                        RingVector::new().into()
                    } else {
                        full.zero()
                    },
                );

            for mut s_full in shares {
                let s_partial = partial.next().unwrap();

                assert_eq!(s_partial[omit].0, Bit::zero());
                assert_eq!(s_partial[omit].1, Bit::zero());
                assert_eq!(s_partial[omit].2, Bit::zero());

                s_full[omit].0 = Bit::zero();
                s_full[omit].1 = Bit::zero();
                s_full[omit].2 = Bit::zero();

                assert_eq!(s_full, s_partial);
            }
        }
    }
}
