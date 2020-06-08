use super::{KEY_SIZE, PRF};

use std::cmp;

use rand_core::{impls, CryptoRng, Error, RngCore};

struct PRNG {
    prf: PRF,
    cnt: u128,
    used: usize,
    st: [u8; KEY_SIZE],
}

impl PRNG {
    pub fn new(prf: PRF) -> PRNG {
        PRNG {
            prf,
            cnt: 0,
            used: KEY_SIZE,
            st: [0u8; KEY_SIZE],
        }
    }
}

impl CryptoRng for PRNG {}

impl RngCore for PRNG {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        let mut remain = dest.len();
        while remain > 0 {
            // replenish the state
            if self.used == KEY_SIZE {
                self.st = self.prf.eval_u128(self.cnt);
                self.cnt += 1;
                self.used = 0;
            }

            // copy bytes and update used
            let old = self.used;
            let copy = cmp::min(KEY_SIZE - old, remain);
            self.used += copy;
            dest[offset..offset + copy].copy_from_slice(&self.st[old..self.used]);

            // decrement remaining
            offset += copy;
            remain -= copy;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }

    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::Rng;

    #[test]
    fn test_prng() {
        const BLOCKS: usize = 1024;
        let mut rng = rand::thread_rng();

        // create new prng
        let key = rng.gen();
        let prf = PRF::new(key);
        let mut prng = PRNG::new(prf);

        // read bytes (random splits)
        let mut acc = 0;
        let mut output = [0u8; KEY_SIZE * BLOCKS];

        while acc < output.len() {
            let n = rng.gen_range(1, output.len() - acc + 1);
            prng.fill_bytes(&mut output[acc..acc + n]);
            acc += n;
        }

        // check that it corresponds to sequential application of PRF
        let prf = PRF::new(key);
        for i in 0..BLOCKS {
            assert_eq!(
                output[i * KEY_SIZE..(i + 1) * KEY_SIZE],
                prf.eval_u128(i as u128)[..]
            )
        }
    }
}
