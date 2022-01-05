#[cfg(test)]
use num_traits::Zero;

use super::*;

pub struct BatchGen<D: Domain> {
    omit: usize,
    prgs: [PRG; PLAYERS],
    _domain: PhantomData<D>,
}

impl<D: Domain> BatchGen<D> {
    pub fn new(keys: &[Key; PLAYERS], omit: usize) -> Self {
        Self {
            omit,
            prgs: [
                PRG::new(&keys[0]),
                PRG::new(&keys[1]),
                PRG::new(&keys[2]),
                PRG::new(&keys[3]),
                PRG::new(&keys[4]),
                PRG::new(&keys[5]),
                PRG::new(&keys[6]),
                PRG::new(&keys[7]),
            ],
            _domain: PhantomData,
        }
    }

    pub fn gen(&mut self, batches: &mut [D::Batch]) {
        for (i, batch) in batches.iter_mut().enumerate().take(PLAYERS) {
            if i != self.omit {
                batch.random(&mut self.prgs[i]);
            }
            #[cfg(test)]
            if i == self.omit {
                debug_assert!(batch.is_zero());
            }
        }
    }
}
