use std::mem;

use rand::RngCore;
use sysinfo::SystemExt;

pub use reader::*;
pub use subset::*;
pub use vec::VecMap;
pub use writer::*;

use crate::algebra::{Domain, RingElement, RingModule, Samplable};
use crate::consts::*;

mod reader;
mod subset;
mod vec;
mod writer;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

pub fn available_memory_bytes() -> i64 {
    let mut system = sysinfo::System::new();
    system.refresh_all();
    (system.get_available_memory() * 1000) as i64
}

pub fn ceil_divide(x: usize, divided_by: usize) -> usize {
    if divided_by == x {
        return 1;
    }
    ((x + divided_by) - 1) / divided_by
}

pub fn chunk_size(ngates: usize, ncopies: usize) -> usize {
    let estimated_bytes = BYTES_PER_GATE * (ngates as i64) - GATE_MEM_INTERCEPT;
    let available_bytes = available_memory_bytes();

    if available_bytes > estimated_bytes {
        return ncopies;
    }

    let split = ceil_divide(estimated_bytes as usize, available_bytes as usize);
    println!(
        "{} bytes of memory available, want {}. Breaking tasking into {} chunks",
        available_bytes, estimated_bytes, split
    );
    ceil_divide(ncopies, split)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(log2(1024), 10);
    }
}

pub fn random_scalar<D: Domain, R: RngCore>(rng: &mut R) -> D::Scalar {
    let mut share = vec![D::Sharing::ZERO; D::Batch::DIMENSION];
    let mut batch = vec![D::Batch::ZERO; D::Sharing::DIMENSION];
    batch[0] = D::Batch::gen(rng);
    D::convert(&mut share[..], &batch[..]);
    share[0].get(0)
}
