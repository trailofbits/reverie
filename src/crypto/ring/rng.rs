use crate::algebra::RingBatch;

use rand::RngCore;

pub struct ElementRNG<B: RingBatch, R: RngCore> {
    used: usize,
    elem: B,
    rng: R,
}

impl<B: RingBatch, R: RngCore> ElementRNG<B, R> {
    pub fn new(rng: R) -> Self {
        Self {
            used: B::BATCH_SIZE,
            elem: B::zero(),
            rng,
        }
    }

    pub fn gen(&mut self) -> B::Element {
        if self.used == B::BATCH_SIZE {
            self.elem = B::gen(&mut self.rng);
            self.used = 0;
        }
        let e = self.elem.get(self.used);
        self.used += 1;
        e
    }
}
