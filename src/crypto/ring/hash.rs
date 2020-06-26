use crate::algebra::Serializable;

use std::io;
use std::io::Write;
use std::marker::PhantomData;

use blake3::{Hash, Hasher};

const HASH_BUFFER_CAPACITY: usize = 8 * 1024;

pub struct RingHasher<R: Serializable> {
    length: u64,
    hasher: io::BufWriter<Hasher>,
    _ph: PhantomData<R>,
}

impl<R: Serializable> RingHasher<R> {
    pub fn new() -> Self {
        Self {
            length: 0,
            hasher: io::BufWriter::with_capacity(HASH_BUFFER_CAPACITY, Hasher::new()),
            _ph: PhantomData,
        }
    }

    pub fn update(&mut self, elem: &R) {
        let _ = elem.serialize(&mut self.hasher);
    }

    pub fn finalize(mut self) -> Hash {
        let _ = self.hasher.write(&self.length.to_le_bytes());
        let _ = self.hasher.flush();
        self.hasher.get_ref().finalize()
    }
}
