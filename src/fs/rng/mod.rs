use std::io;
use std::io::{BufReader, Read, Seek, SeekFrom};

use blake3::{Hasher, OutputReader};
use rand_core::{impls, CryptoRng, Error, RngCore};

const RNG_BUFFER_CAPACITY: usize = 64;

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
            reader: BufReader::with_capacity(RNG_BUFFER_CAPACITY, hasher.finalize_xof()),
        }
    }
}

impl Seek for ViewRNG {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.reader.seek(pos)
    }
}

impl Clone for ViewRNG {
    fn clone(&self) -> Self {
        let rng = self.reader.get_ref().clone();
        ViewRNG {
            reader: BufReader::with_capacity(RNG_BUFFER_CAPACITY, rng),
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
