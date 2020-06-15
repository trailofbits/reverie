use std::io::{BufReader, Read};

use blake3::{Hasher, OutputReader};
use rand_core::{impls, CryptoRng, Error, RngCore};

pub struct ViewRNG {
    reader: BufReader<OutputReader>,
}

impl ViewRNG {
    pub fn new(hasher: &Hasher, label: &'static [u8]) -> Self {
        let mut hasher = hasher.clone();
        hasher.update(label);
        hasher.update(&(label.len() as u8).to_le_bytes());
        hasher.update(&[0]);
        ViewRNG {
            reader: BufReader::with_capacity(64, hasher.finalize_xof()),
        }
    }
}

impl CryptoRng for ViewRNG {}

impl RngCore for ViewRNG {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest).unwrap();
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
