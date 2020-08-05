use super::{Hash, Hasher, HASH_SIZE};

use blake3;

use merkletree::hash;
use merkletree::merkle::{self, Element};
use merkletree::store::VecStore;

use std::cmp::Ordering;
use std::hash::Hasher as StdHasher;

impl Default for Hash {
    fn default() -> Self {
        Self(blake3::Hash::from([0u8; HASH_SIZE]))
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.0.as_bytes().cmp(other.0.as_bytes()))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl Element for Hash {
    fn byte_len() -> usize {
        HASH_SIZE
    }

    fn from_slice(bytes: &[u8]) -> Self {
        let mut hsh = [0u8; HASH_SIZE];
        hsh.copy_from_slice(bytes);
        Hash(blake3::Hash::from(hsh))
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.0.as_bytes())
    }
}

impl StdHasher for Hasher {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl<H: StdHasher> hash::Hashable<H> for Hash {
    fn hash(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl hash::Algorithm<Hash> for Hasher {
    #[inline]
    fn hash(&mut self) -> Hash {
        Hash(self.0.finalize())
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}

pub type MerkleTree = merkle::MerkleTree<Hash, Hasher, VecStore<Hash>>;
