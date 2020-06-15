use super::RingBatch;

/// Efficient implementation of an immutable array of ring elements
pub struct RingArray<B: RingBatch>(Vec<B>);

impl<B: RingBatch> RingArray<B> {
    pub fn new(&self, vec: Vec<B>) -> RingArray<B> {
        RingArray(vec)
    }

    pub fn get(&self, label: usize) -> Option<B::Element> {
        let rem = label % B::BATCH_SIZE;
        let div = label / B::BATCH_SIZE;
        self.0.get(div).map(|b| b.get(rem))
    }

    pub fn set(&mut self, label: usize, v: B::Element) {
        let rem = label % B::BATCH_SIZE;
        let div = label / B::BATCH_SIZE;
        self.0[div].set(rem, v)
    }
}
