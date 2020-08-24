use std::collections::HashSet;

use rand::Rng;
use rand::RngCore;

/// pick a uniformly random usize using rejection sampling
#[inline(always)]
pub fn random_usize<R: RngCore>(rng: &mut R, m: usize) -> usize {
    let m: u64 = m as u64;
    let s: u32 = m.leading_zeros();
    loop {
        let n: u64 = u64::from_le_bytes(rng.gen());
        let n: u64 = n >> s;
        if n < m {
            break n as usize;
        }
    }
}

pub fn random_vector<R: RngCore>(rng: &mut R, m: usize, len: usize) -> Vec<usize> {
    let mut samples: Vec<usize> = Vec::with_capacity(len);
    while samples.len() < len {
        samples.push(random_usize::<R>(rng, m));
    }
    samples
}

pub fn random_subset<R: RngCore>(rng: &mut R, m: usize, len: usize) -> Vec<usize> {
    debug_assert!(m >= len);

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

    // ensure a canonical ordering (smallest to largest) to enable easy comparison
    samples.sort_unstable();
    samples
}
