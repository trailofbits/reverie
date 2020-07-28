use std::mem;

use rand::RngCore;

#[inline(always)]
pub fn random_usize<R: RngCore, const M: usize>(rng: &mut R) -> usize {
    // generate a 128-bit integer (to minimize statistical bias)
    let mut le_bytes: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut le_bytes);

    // reduce mod the number of repetitions
    let n: u128 = u128::from_le_bytes(le_bytes) % (M as u128);
    n as usize
}

pub fn random_subset<R: RngCore, const M: usize, const S: usize>(rng: &mut R) -> [usize; S] {
    let mut members: [bool; M] = [false; M];
    let mut samples: [usize; S] = unsafe { mem::MaybeUninit::zeroed().assume_init() };
    let mut collect: usize = 0;

    while collect < S {
        // generate random usize
        let n = random_usize::<R, M>(rng);

        // if not in set, add to the vector
        if !mem::replace(&mut members[n as usize], true) {
            samples[collect] = n;
            collect += 1;
        }
    }

    // ensure a canonical ordering (for comparisons)
    samples.sort();
    samples
}
