mod array;
mod reader;
mod subset;
mod vec;
mod writer;

pub use array::*;
pub use reader::*;
pub use subset::*;
pub use vec::VecMap;
pub use writer::*;

use std::mem;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

pub fn take_n<T, I: Iterator<Item = T>>(dst: &mut Vec<T>, src: &mut I, n: usize) {
    for _ in 0..n {
        match src.next() {
            Some(e) => dst.push(e),
            None => return,
        }
    }
}

pub fn read_n<T, I: Iterator<Item = T>>(src: &mut I, n: usize) -> Vec<T> {
    let mut res = Vec::with_capacity(n);
    take_n(&mut res, src, n);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(log2(1024), 10);
    }
}
