mod reader;
mod subset;
mod vec;
mod writer;

pub use reader::*;
pub use subset::*;
pub use vec::VecMap;
pub use writer::*;

use std::mem;
use std::time::Duration;

use sysinfo::SystemExt;

const SLEEP_TIME: Duration = Duration::from_millis(2000);
const FREE_MB: u64 = 512;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

pub fn read_n<T, I: Iterator<Item = T>>(src: &mut I, n: usize) -> Vec<T> {
    src.take(n).collect()
}

pub fn wait_for_mem() {
    let mut printed: bool = false;
    let mut system = sysinfo::System::new();
    loop {
        system.refresh_all();
        let available_mem = system.get_available_memory();
        if available_mem > (FREE_MB * 1000) {
            break;
        }
        if !printed {
            println!("System only has {} kB of memory available. Waiting until {} MB is available before scheduling more tasks...", available_mem, FREE_MB);
            printed = true;
        }
        std::thread::sleep(SLEEP_TIME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(log2(1024), 10);
    }
}
