use std::collections::HashSet;

use rand::RngCore;

use rand::seq::SliceRandom;

pub fn random_permutation<R: RngCore>(rng: &mut R, len: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..len).collect();
    perm.shuffle(rng);
    perm
}

#[inline(always)]
pub fn random_usize<R: RngCore>(rng: &mut R, m: usize) -> usize {
    // generate a 128-bit integer (to minimize statistical bias)
    let mut le_bytes: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut le_bytes);

    // reduce mod the number of repetitions
    let n: u128 = u128::from_le_bytes(le_bytes) % (m as u128);
    n as usize
}

pub fn random_vector<R: RngCore>(rng: &mut R, m: usize, len: usize) -> Vec<usize> {
    let mut samples: Vec<usize> = Vec::with_capacity(len);
    while samples.len() < len {
        samples.push(random_usize::<R>(rng, m));
    }
    samples
}

pub fn random_subset<R: RngCore>(rng: &mut R, m: usize, len: usize) -> Vec<usize> {
    let mut members: HashSet<usize> = HashSet::new();
    let mut samples: Vec<usize> = Vec::with_capacity(len);

    while samples.len() < len {
        // generate random usize
        let n = random_usize::<R>(rng, m);

        // if not in set, add to the vector
        if members.insert(n) {
            samples.push(n);
        }
    }

    // ensure a canonical ordering (smallest to largest)
    samples.sort_unstable();
    samples
}
