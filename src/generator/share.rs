use super::*;
#[cfg(any(debug_assertions, test))]
#[allow(unused_imports)]
use crate::algebra::EqIndex;
#[cfg(any(debug_assertions, test))]
use crate::crypto::prg::KEY_SIZE;

pub struct ShareGen<D: Domain> {
    next_idx: usize,
    shares: [D::Share; BATCH_SIZE],
    batches: [[D::Batch; PLAYERS]; PACKED],
    gens: [BatchGen<D>; PACKED],
}

impl<D: Domain> ShareGen<D> {
    pub fn new(keys: &[[Key; PLAYERS]; PACKED], omit: [usize; PACKED]) -> Self {
        #[cfg(debug_assertions)]
        for i in 0..PACKED {
            debug_assert!(omit[i] <= PLAYERS);
            if omit[i] < PLAYERS {
                // key (unused) of omitted player should be set to default value (zero)
                debug_assert_eq!(keys[i][omit[i]], [0u8; KEY_SIZE]);
            }
        }

        Self::new_from_batch_gen([
            BatchGen::new(&keys[0], omit[0]), // generator for 1st repetition
            BatchGen::new(&keys[1], omit[1]), // generator for 2nd repetition
            BatchGen::new(&keys[2], omit[2]), // ...
            BatchGen::new(&keys[3], omit[3]),
            BatchGen::new(&keys[4], omit[4]),
            BatchGen::new(&keys[5], omit[5]),
            BatchGen::new(&keys[6], omit[6]),
            BatchGen::new(&keys[7], omit[7]),
        ])
    }

    pub fn new_from_batch_gen(gens: [BatchGen<D>; PACKED]) -> Self {
        let mut share_gen = ShareGen {
            next_idx: BATCH_SIZE,
            shares: unsafe { MaybeUninit::zeroed().assume_init() },
            batches: unsafe { MaybeUninit::zeroed().assume_init() },
            gens,
        };
        for i in 0..PACKED {
            for j in 0..PLAYERS {
                share_gen.batches[i][j] = Default::default();
            }
        }
        share_gen
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> D::Share {
        if self.next_idx >= BATCH_SIZE {
            for i in 0..PACKED {
                self.gens[i].gen(&mut self.batches[i]);
            }
            D::batches_to_shares(&mut self.shares, &self.batches);
            self.next_idx = 0;
        }
        let share = self.shares[self.next_idx];
        self.next_idx += 1;
        share
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::{Rng, RngCore};

    use super::*;
    use crate::algebra;

    fn share_generator<D: Domain>() {
        let mut keys = [[[0u8; KEY_SIZE]; PLAYERS]; PACKED];
        for i in 0..keys.len() {
            for j in 0..keys[i].len() {
                OsRng.fill_bytes(&mut keys[i][j]);
            }
        }

        // generate random shares
        let n: usize = OsRng.gen::<usize>() % 100_000;
        let mut gen = ShareGen::<D>::new(&keys, [PLAYERS; PACKED]);
        let mut shares: Vec<D::Share> = vec![];
        for _ in 0..n {
            shares.push(gen.next());
        }

        // pick players to omit
        let omit: [usize; PACKED] = [
            OsRng.gen::<usize>() % (PLAYERS + 1),
            OsRng.gen::<usize>() % (PLAYERS + 1),
            OsRng.gen::<usize>() % (PLAYERS + 1),
            OsRng.gen::<usize>() % (PLAYERS + 1),
            OsRng.gen::<usize>() % (PLAYERS + 1),
            OsRng.gen::<usize>() % (PLAYERS + 1),
            OsRng.gen::<usize>() % (PLAYERS + 1),
            OsRng.gen::<usize>() % (PLAYERS + 1),
        ];
        for i in 0..keys.len() {
            if omit[i] < PLAYERS {
                keys[i][omit[i]] = [0u8; KEY_SIZE];
            }
        }

        // generate the partial shares
        let mut gen = ShareGen::<D>::new(&keys, omit);
        let mut partial_shares: Vec<D::Share> = vec![];
        for _ in 0..n {
            partial_shares.push(gen.next());
        }

        let zero = D::Share::default();

        for m in 0..n {
            for i in 0..PACKED {
                for j in 0..PLAYERS {
                    if j == omit[i] {
                        debug_assert!(
                            D::Share::compare_index(i, j, &zero, i, j, &partial_shares[m]),
                            "partial_share[m] = {:?}, omit[i] = {}, rep = {}",
                            &partial_shares[m],
                            omit[i],
                            i
                        );
                    } else {
                        debug_assert!(D::Share::compare_index(
                            i,
                            j,
                            &shares[m],
                            i,
                            j,
                            &partial_shares[m]
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn share_generator_test() {
        share_generator::<algebra::gf2::Domain>();
    }
}
