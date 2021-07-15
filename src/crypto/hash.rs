use crate::PACKED;
use blake3;

const BUFFER_SIZE: usize = 1 << 16;
const BUFFER_SLACK: usize = 128;

pub const HASH_SIZE: usize = 32;

use std::convert::AsMut;
use std::ops::{Index, IndexMut};

pub type Hasher = BufferedHasher;
pub type Hash = blake3::Hash;

#[derive(Debug)]
pub struct BufferedHasher {
    hasher: blake3::Hasher,
    buffer: Vec<u8>,
}

impl Default for BufferedHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl BufferedHasher {
    pub fn new() -> Self {
        BufferedHasher {
            hasher: blake3::Hasher::new(),
            buffer: Vec::with_capacity(BUFFER_SIZE + BUFFER_SLACK),
        }
    }

    pub fn push(&mut self, val: u8) {
        self.buffer.push(val);
        if self.buffer.len() >= BUFFER_SIZE {
            self.hasher.update(&self.buffer);
            self.buffer.clear();
        }
    }

    pub fn update(&mut self, buf: &[u8]) {
        debug_assert!(buf.len() < BUFFER_SLACK);
        self.buffer.extend_from_slice(buf);
        if self.buffer.len() >= BUFFER_SIZE {
            self.hasher.update(&self.buffer);
            self.buffer.clear();
        }
    }

    pub fn finalize(&self) -> Hash {
        let mut hasher = self.hasher.clone();
        hasher.update(&self.buffer);
        hasher.finalize()
    }
}

#[derive(Debug)]
pub struct PackedHasher([Hasher; PACKED]);

impl Index<usize> for PackedHasher {
    type Output = Hasher;

    fn index(&self, index: usize) -> &Hasher {
        &self.0[index]
    }
}

impl IndexMut<usize> for PackedHasher {
    fn index_mut(&mut self, index: usize) -> &mut Hasher {
        &mut self.0[index]
    }
}

impl PackedHasher {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self([
            Hasher::new(),
            Hasher::new(),
            Hasher::new(),
            Hasher::new(),
            Hasher::new(),
            Hasher::new(),
            Hasher::new(),
            Hasher::new(),
        ])
    }

    pub fn finalize(&self) -> [Hash; PACKED] {
        [
            self.0[0].finalize(),
            self.0[1].finalize(),
            self.0[2].finalize(),
            self.0[3].finalize(),
            self.0[4].finalize(),
            self.0[5].finalize(),
            self.0[6].finalize(),
            self.0[7].finalize(),
        ]
    }
}

impl AsMut<[Hasher; PACKED]> for PackedHasher {
    fn as_mut(&mut self) -> &mut [Hasher; PACKED] {
        &mut self.0
    }
}

impl AsRef<[Hasher; PACKED]> for PackedHasher {
    fn as_ref(&self) -> &[Hasher; PACKED] {
        &self.0
    }
}

#[macro_export]
macro_rules! HASH {
    ( $($input:expr),* ) => {{
        let mut h = blake3::Hasher::new();
        $(
            h.update($input);
        )*
        h.finalize()
    }};
}
