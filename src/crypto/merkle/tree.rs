use crate::crypto::{Hash, Hasher};

use std::sync::Arc;

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

fn merkle_internal(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(&[0u8]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

impl MerkleProof {
    // provide the leaf and compute the root of the corresponding Merkle tree from the membership proof
    pub fn verify(&self, mut hash: Hash) -> Hash {
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
            let len = elems.len();
            let mid = (len >> 1) + (len & 1);
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
            MerkleTree::Leaf(_) => 1,
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
            debug_assert!(index < tree.size(), "index not in bounds");
            match tree {
                MerkleTree::Leaf(_) => (),
                MerkleTree::Internal(_, _, left, right) => {
                    let left_size = left.size();
                    proof.path <<= 1;
                    match index < left_size {
                        true => {
                            prove_internal(left, index, proof);
                            proof.leafs.push(right.root().clone());
                        }
                        false => {
                            proof.path |= 1;
                            debug_assert!(right.size() > index - left_size);
                            prove_internal(right, index - left_size, proof);
                            proof.leafs.push(left.root().clone());
                        }
                    }
                }
            }
        }
        let mut proof = MerkleProof {
            path: 0,
            leafs: Vec::with_capacity(32),
        };
        assert!(index < self.size(), "index not in tree");
        prove_internal(self, index, &mut proof);
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash, KEY_SIZE};

    use rand::{thread_rng, Rng};

    #[test]
    fn test_merkle_tree() {
        let mut rng = thread_rng();

        let lengths = vec![
            1,
            2,
            3,
            4,
            10,
            32,
            31,
            64,
            534,
            1 + rng.gen::<usize>() % 1024,
            1 + rng.gen::<usize>() % 1024,
            1 + rng.gen::<usize>() % 1024,
            1 + rng.gen::<usize>() % 1024,
            1 + rng.gen::<usize>() % 1024,
            1 + rng.gen::<usize>() % 1024,
        ];

        for len in lengths {
            // pick random elements
            let mut elems: Vec<Hash> = Vec::with_capacity(len);
            for _ in 0..len {
                let v: [u8; KEY_SIZE] = rng.gen();
                elems.push(hash(&v));
            }

            // check opening of every index
            let tree = MerkleTree::new(&elems[..]);
            for index in 0..len {
                let proof = tree.prove(index);
                assert_eq!(
                    proof.verify(elems[index].clone()),
                    tree.root().clone(),
                    "index = {}, tree = {:?}, proof = {:?}, elem = {:?}",
                    index,
                    tree,
                    proof,
                    &elems[index],
                )
            }
        }
    }
}
