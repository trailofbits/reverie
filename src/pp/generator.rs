use super::RingBatch;
use super::Scope;

use std::mem;

use blake3::Hash;
use rand_core::RngCore;

pub struct State<B: RingBatch, R: RngCore> {
    rng: R,
    share_a: B,
    share_b: B,
    share_c: B,
}

pub struct Preprocessing<B: RingBatch, R: RngCore, const N: usize> {
    used: usize,
    stat: [State<B, R>; N],
}

impl<B: RingBatch, R: RngCore> State<B, R> {
    fn replenish(&mut self) {
        self.share_a = B::gen(&mut self.rng);
        self.share_b = B::gen(&mut self.rng);
        self.share_c = B::gen(&mut self.rng);
    }
}

impl<B: RingBatch, R: RngCore, const N: usize> Preprocessing<B, R, N> {
    pub fn new(rngs: Vec<R>) -> Self {
        assert_eq!(rngs.len(), N);

        // initialize the state for every player
        let mut stat: [State<B, R>; N] = unsafe { mem::MaybeUninit::zeroed().assume_init() };
        for (i, rng) in rngs.into_iter().enumerate() {
            stat[i].rng = rng;
            stat[i].share_a = B::zero();
            stat[i].share_b = B::zero();
            stat[i].share_c = B::zero();
        }

        // join into pre-processing context for entire protocol
        Preprocessing {
            used: B::BATCH_SIZE,
            stat,
        }
    }

    pub fn next(&mut self) -> [(B::Element, B::Element, B::Element); N] {
        // check if every multiplication in batch has been used
        if self.used == B::BATCH_SIZE {
            self.replenish();
            self.used = B::BATCH_SIZE;
        }

        // extract the next single element from current batch
        let mut beavers: [(B::Element, B::Element, B::Element); N] =
            unsafe { mem::MaybeUninit::zeroed().assume_init() };

        for i in 0..N {
            beavers[i] = (
                self.stat[i].share_a.get(self.used),
                self.stat[i].share_b.get(self.used),
                self.stat[i].share_c.get(self.used),
            );
        }

        // return shares for each player
        self.used += 1;
        beavers
    }

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

    pub fn preprocess_corrections(&mut self, mut scope: Scope, batches: u64) {
        for _ in 0..batches {
            self.replenish();
            scope.update(&self.stat[0].share_c.pack().to_le_bytes());
        }
    }
}
