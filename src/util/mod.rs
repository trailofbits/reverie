mod reader;
mod subset;
mod vec;
mod writer;

pub use reader::*;
pub use subset::*;
pub use vec::VecMap;
pub use writer::*;

use std::mem;

use std::cmp::max;
use sysinfo::SystemExt;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

pub fn read_n<T, I: Iterator<Item = T>>(src: &mut I, n: usize) -> Vec<T> {
    src.take(n).collect()
}

pub fn wait_for_mem() {
    unimplemented!("Use chunks_to_fit_in_memory instead!");
}

pub fn chunks_to_fit_in_memory(ngates: Option<usize>, ncopies: usize) -> usize {
    let ngate: i64;
    match ngates {
        None => {
            return 1;
        }
        Some(n) => {
            ngate = n as i64;
        }
    }
    let mut system = sysinfo::System::new();
    system.refresh_all();
    let available_bytes = (system.get_available_memory() * 1000) as i64;
    let estimated_bytes = max(
        available_bytes,
        (ncopies as i64) * (300 * ngate - 38_400_000),
    );
    ((estimated_bytes + available_bytes - 1) / available_bytes) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(log2(1024), 10);
    }
}
