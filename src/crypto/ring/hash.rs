use crate::algebra::{RingBatch, RingPacked, RingVector};

use std::io::{BufWriter, Write};

use blake3::{Hash, Hasher};

const HASH_BUFFER_CAPACITY: usize = 8 * 1024;

pub struct BatchHasher {
    length: u64,
    hasher: BufWriter<Hasher>,
}

pub struct ElementHasher<B: RingBatch> {
    hasher: BatchHasher,
    used: usize,
    elem: B,
}

pub fn hash_vector<B: RingBatch>(vec: &RingVector<B>) -> Hash {
    let mut hasher = BufWriter::with_capacity(HASH_BUFFER_CAPACITY, Hasher::new());
    for batch in vec.batch_iter() {
        let _ = hasher.write(batch.pack().as_bytes());
    }
    let _ = hasher.write(&(vec.len() as u64).to_le_bytes());
    let _ = hasher.flush();
    hasher.get_ref().finalize()
}

impl BatchHasher {
    pub fn new() -> Self {
        Self {
            length: 0,
            hasher: BufWriter::with_capacity(HASH_BUFFER_CAPACITY, Hasher::new()),
        }
    }

    #[inline(always)]
    fn raw_update(&mut self, buf: &[u8], len: usize) {
        self.length += len as u64;
        let _ = self.hasher.write(buf);
    }

    pub fn update<B: RingBatch>(&mut self, elem: B) {
        self.raw_update(elem.pack().as_bytes(), B::BATCH_SIZE);
    }

    pub fn finalize(mut self) -> Hash {
        let _ = self.hasher.write(&self.length.to_le_bytes());
        let _ = self.hasher.flush();
        self.hasher.get_ref().finalize()
    }
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
            // write residue batch and update the length
            self.hasher
                .raw_update(self.elem.pack().as_bytes(), self.used);
        }
        self.hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::algebra::gf2::BitBatch;

    use rand::Rng;

    fn equal_batch_element<B: RingBatch>() {
        let mut rng = rand::thread_rng();
        let mut hasher1: ElementHasher<B> = ElementHasher::new();
        let mut hasher2 = BatchHasher::new();

        let batches: usize = rng.gen::<usize>() % 10_000;

        for _ in 0..batches {
            let batch = B::gen(&mut rng);

            hasher2.update(batch);

            for i in 0..B::BATCH_SIZE {
                hasher1.update(batch.get(i))
            }
        }

        assert_eq!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn equal_batch_element_bits() {
        equal_batch_element::<BitBatch>();
    }
}
