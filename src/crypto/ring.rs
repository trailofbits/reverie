use blake3::{Hash, Hasher};

use crate::algebra::{RingBatch, RingPacked};

#[cfg(target_feature = "avx2")]
const HASH_BUFFER_CAPACITY: usize = 8 * 1024;

#[cfg(target_feature = "avx512")]
const HASH_BUFFER_CAPACITY: usize = 16 * 1024;

#[cfg_attr(any(target_feature = "avx2", target_feature = "avx512"), buffered)]
#[cfg_attr(any(target_feature = "avx2", target_feature = "avx512"), buffered)]
#[cfg(buffered)]
use std::io::{BufWriter, Write};

pub struct BatchHasher {
    length: u64,

    // if AVX is there, use a buffered interface
    #[cfg(buffered)]
    hasher: BufWriter<Hasher>,

    // otherwise do not bother and minimize cache misses
    #[cfg(not(buffered))]
    hasher: Hasher,
}

impl BatchHasher {
    pub fn new() -> Self {
        Self {
            length: 0,

            #[cfg(not(buffered))]
            hasher: Hasher::new(),

            #[cfg(buffered)]
            hasher: BufWriter::with_capacity(HASH_BUFFER_CAPACITY, Hasher::new()),
        }
    }

    #[inline(always)]
    fn raw_update(&mut self, buf: &[u8], len: usize) {
        self.length += len as u64;

        #[cfg(not(buffered))]
        self.hasher.update(buf);

        #[cfg(buffered)]
        let _ = self.hasher.write(buf);
    }

    pub fn update<B: RingBatch>(&mut self, elem: B) {
        self.raw_update(elem.pack().as_bytes(), B::BATCH_SIZE);
    }

    pub fn finalize(mut self) -> Hash {
        #[cfg(buffered)]
        {
            self.hasher.write(self.length.to_le_bytes());
            self.hasher.flush();
            self.hasher.get_ref().finalize()
        }
        #[cfg(not(buffered))]
        {
            self.hasher.update(&self.length.to_le_bytes());
            self.hasher.finalize()
        }
    }
}

pub struct ElementHasher<B: RingBatch> {
    hasher: BatchHasher,
    used: usize,
    elem: B,
}

impl<B: RingBatch> Into<ElementHasher<B>> for BatchHasher {
    fn into(self) -> ElementHasher<B> {
        ElementHasher {
            hasher: self,
            used: 0,
            elem: B::zero(),
        }
    }
}

impl<B: RingBatch> ElementHasher<B> {
    pub fn new() -> Self {
        Self {
            hasher: BatchHasher::new(),
            used: 0,
            elem: B::zero(),
        }
    }

    pub fn update(&mut self, elem: B::Element) {
        // if the batch is full, flush to the scope
        if self.used == B::BATCH_SIZE {
            self.hasher.update(self.elem);
            self.used = 0;
        }

        // add the ring element to the batch
        self.elem.set(self.used, elem);
        self.used += 1;
    }

    pub fn finalize(mut self) -> Hash {
        if self.used > 0 {
            self.hasher
                .raw_update(self.elem.pack().as_bytes(), self.used);
        }
        self.hasher.finalize()
    }
}
