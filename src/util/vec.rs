pub struct VecMap<T>(Vec<T>);

impl<T: Copy> From<Vec<T>> for VecMap<T> {
    fn from(vec: Vec<T>) -> VecMap<T> {
        VecMap(vec)
    }
}

impl<T: Copy> VecMap<T> {
    #[inline(always)]
    pub fn set(&mut self, idx: usize, val: T) {
        if idx >= self.0.len() {
            self.0.resize(idx + 1, val);
        }
        debug_assert!(idx < self.0.len());
        unsafe {
            *self.0.get_unchecked_mut(idx) = val;
        }
    }

    #[inline(always)]
    pub fn get(&self, idx: usize) -> T {
        self.0[idx]
    }
}
