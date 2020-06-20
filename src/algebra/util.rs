use super::RingBatch;

use std::cmp;
use std::slice::Iter;

/// Efficient implementation of an immutable array of ring elements
pub struct RingArray<B: RingBatch>(Vec<B>);

impl<B: RingBatch> RingArray<B> {
    pub fn new() -> RingArray<B> {
        RingArray(Vec::new())
    }

    pub fn get_batch(&self, batch: usize) -> Option<B> {
        self.0.get(batch).map(|b| *b)
    }

    pub fn len(&self) -> usize {
        return self.0.len() * B::BATCH_SIZE;
    }

    pub fn get(&self, label: usize) -> Option<B::Element> {
        let rem = label % B::BATCH_SIZE;
        let div = label / B::BATCH_SIZE;
        self.0.get(div).map(|b| b.get(rem))
    }
}

/// Efficient implementation of an expandable vector of ring elements.
pub struct RingVector<B: RingBatch> {
    vec: Vec<B>,
    len: usize,
}

impl<B: RingBatch> Into<RingArray<B>> for RingVector<B> {
    fn into(self) -> RingArray<B> {
        RingArray(self.vec)
    }
}

impl<B: RingBatch> RingVector<B> {
    pub fn new() -> RingVector<B> {
        RingVector {
            vec: Vec::new(),
            len: 0,
        }
    }

    pub fn with_capacity(cap: usize) -> RingVector<B> {
        let alloc = (cap + B::BATCH_SIZE - 1) / B::BATCH_SIZE;
        RingVector {
            vec: Vec::with_capacity(alloc),
            len: 0,
        }
    }

    pub fn get(&self, idx: usize) -> Option<B::Element> {
        if idx >= self.len {
            return None;
        }
        let rem = idx % B::BATCH_SIZE;
        let div = idx / B::BATCH_SIZE;
        Some(unsafe { self.vec.get_unchecked(div) }.get(rem))
    }

    pub fn set(&mut self, idx: usize, v: B::Element) {
        let rem = idx % B::BATCH_SIZE;
        let div = idx / B::BATCH_SIZE;

        // extend vector if index is outside
        if div >= self.vec.len() {
            self.vec.resize(div + 1, B::zero());
        }

        self.len = cmp::max(idx + 1, self.len);
        unsafe { self.vec.get_unchecked_mut(div) }.set(rem, v);
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn batch_len(&self) -> usize {
        self.vec.len()
    }

    pub fn batch_push(&mut self, batch: B) {
        self.vec.push(batch);
        self.len = self.vec.len() * B::BATCH_SIZE;
    }

    pub fn batch_iter<'a>(&'a self) -> Iter<'a, B> {
        self.vec.iter()
    }
}
