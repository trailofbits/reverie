use super::*;
use crate::algebra::{RingBatch, RingPacked};

/// Wrapper around a Scope which enables efficiently writing ring elements
/// directly into the scope.
pub struct ScopeRing<'a, B: RingBatch> {
    scope: Scope<'a>,
    used: usize,
    elem: B,
}

impl<'a, B: RingBatch> Into<ScopeRing<'a, B>> for Scope<'a> {
    fn into(self) -> ScopeRing<'a, B> {
        ScopeRing {
            scope: self,
            used: 0,
            elem: B::zero(),
        }
    }
}

impl<'a, B: RingBatch> ScopeRing<'a, B> {
    pub fn update(&mut self, elem: B::Element) {
        // if the batch is full, flush to the scope
        if self.used == B::BATCH_SIZE {
            self.scope.update(self.elem.pack().as_bytes());
            self.used = 0;
        }

        // add the ring element to the batch
        self.elem.set(self.used, elem);
        self.used += 1;
    }
}

impl<'a, B: RingBatch> Drop for ScopeRing<'a, B> {
    fn drop(&mut self) {
        self.scope.update(self.elem.pack().as_bytes());
        self.scope.update(&(self.used as u64).to_le_bytes());
    }
}
