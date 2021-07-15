mod combine;
mod single;

use crate::algebra::Domain;

pub use combine::CombineInstance;
pub use single::Instance;

#[derive(Debug)]
pub struct Wire<D: Domain> {
    pub(crate) mask: D::Share,
    pub(crate) corr: D::Recon,
}

impl<D: Domain> Wire<D> {
    #[cfg(any(test, debug_assertions))]
    fn value(&self) -> D::Recon {
        D::reconstruct(&self.mask) + self.corr
    }
}

impl<D: Domain> Clone for Wire<D> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Wire {
            mask: self.mask,
            corr: self.corr,
        }
    }
}

impl<D: Domain> Default for Wire<D> {
    #[inline(always)]
    fn default() -> Self {
        Self {
            mask: Default::default(),
            corr: Default::default(),
        }
    }
}
