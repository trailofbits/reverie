use super::{Hash, Hasher, HASH_SIZE};
use crate::crypto::{KEY_SIZE, PRG};

use std::cmp::Ordering;
use std::hash::Hasher as StdHasher;
use std::sync::Arc;

use rand::prelude::SliceRandom;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum MerkleTree {
    Leaf(Hash),
    Internal(usize, Hash, Arc<MerkleTree>, Arc<MerkleTree>),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleProof {
    path: u32, // only supports up to 2^32 leafs
    leafs: Vec<Hash>,
}

/// A cryptographic accumulator which additionally hides the unopened elements
#[derive(Debug, Clone)]
pub struct MerkleSet {
    perm: Vec<usize>, // permutation of input elements
    tree: MerkleTree,
}

impl MerkleSet {
    pub fn new(seed: [u8; KEY_SIZE], elems: &[Hash]) -> MerkleSet {
        // generate a pseudorandom permutation
        let mut rng = PRG::new(seed);
        let mut perm: Vec<usize> = (0..elems.len()).collect();
        perm.shuffle(&mut rng);

        // permute the elements
        let mut elems_perm: Vec<Hash> = vec![Hash::default(); elems.len()];
        for i in 0..elems.len() {
            elems_perm[perm[i]] = elems[i].clone();
        }

        // compute Merkle tree over permuted elements
        MerkleSet {
            perm,
            tree: MerkleTree::new(&elems_perm[..]),
        }
    }

    pub fn prove(&self, index: usize) -> MerkleProof {
        self.tree.prove(self.perm[index])
    }

    pub fn root(&self) -> &Hash {
        self.tree.root()
    }
}

mod tests {
    use super::*;
    use crate::crypto::hash;

    #[test]
    fn test_merkle_set() {
        let elems: Vec<Hash> = vec![hash(&[]), hash(&[1]), hash(&[2])];
        let set: MerkleSet = MerkleSet::new([1u8; KEY_SIZE], &elems[..]);
        let proof: MerkleProof = set.prove(1);
        assert_eq!(set.root().clone(), proof.verify(elems[1].clone()));
    }
}

fn merkle_internal(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(&[0u8]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

impl MerkleProof {
    // provide the leaf and compute the root of the corresponding Merkle tree from the membership proof
    pub fn verify(&self, leaf: Hash) -> Hash {
        let mut hash = leaf;
        let mut path = self.path;
        for elem in self.leafs.iter() {
            let bit = path & 1;
            path = path >> 1;
            match bit {
                0 => {
                    hash = merkle_internal(&hash, elem);
                }
                1 => {
                    hash = merkle_internal(elem, &hash);
                }
                _ => unreachable!(),
            }
        }
        hash
    }
}

impl MerkleTree {
    pub fn new(elems: &[Hash]) -> MerkleTree {
        assert!(elems.len() > 0);
        assert!(elems.len() < (1 << 31));
        if elems.len() == 1 {
            MerkleTree::Leaf(elems[0].clone())
        } else {
            // recursively construct subtrees
            let mid = elems.len() / 2;
            let left = Arc::new(MerkleTree::new(&elems[..mid]));
            let right = Arc::new(MerkleTree::new(&elems[mid..]));

            // compute root
            MerkleTree::Internal(
                elems.len(),
                merkle_internal(left.root(), right.root()),
                left,
                right,
            )
        }
    }

    fn size(&self) -> usize {
        match self {
            MerkleTree::Leaf(hash) => 1,
            MerkleTree::Internal(size, _, _, _) => *size,
        }
    }

    pub fn root(&self) -> &Hash {
        match self {
            MerkleTree::Leaf(hash) => hash,
            MerkleTree::Internal(_, root, _, _) => root,
        }
    }

    pub fn prove(&self, index: usize) -> MerkleProof {
        fn prove_internal(tree: &MerkleTree, index: usize, proof: &mut MerkleProof) {
            match tree {
                MerkleTree::Leaf(hash) => (),
                MerkleTree::Internal(_, _, left, right) => {
                    let left_size = left.size();
                    match index < left_size {
                        true => {
                            proof.path <<= 1;
                            proof.leafs.push(right.root().clone());
                            prove_internal(left, index, proof);
                        }
                        false => {
                            proof.path <<= 1;
                            proof.path |= 1;
                            proof.leafs.push(left.root().clone());
                            prove_internal(right, index - left_size, proof);
                        }
                    }
                }
            }
        }
        let mut proof = MerkleProof {
            path: 0,
            leafs: Vec::with_capacity(32),
        };
        prove_internal(self, index, &mut proof);
        proof
    }
}

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