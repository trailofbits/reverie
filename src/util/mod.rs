mod reader;
mod subset;
mod vec;
mod writer;

pub use reader::*;
pub use subset::*;
pub use vec::VecMap;
pub use writer::*;

use std::mem;

use sysinfo::SystemExt;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

pub fn ceil_divide(x: usize, divided_by: usize) -> usize {
    ((x + divided_by) - 1) / divided_by
}

pub fn chunks_to_fit_in_memory(ngates: usize, ncopies: usize) -> usize {
    let mut system = sysinfo::System::new();
    system.refresh_all();
    let available_bytes = (system.get_available_memory() * 1000) as i64;
    let estimated_bytes = (ncopies as i64) * (300 * (ngates as i64) - 38_400_000);
    if available_bytes > estimated_bytes{
        return 1;
    }
    ceil_divide(estimated_bytes as usize, available_bytes as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(log2(1024), 10);
    }
}
