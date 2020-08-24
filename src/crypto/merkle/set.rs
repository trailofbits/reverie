use super::tree::{MerkleProof, MerkleTree};
use crate::crypto::{commit, Hash, KEY_SIZE, PRG};

use rand::prelude::SliceRandom;
use rand::Rng;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleSetProof {
    proof: MerkleProof,   // Merkle-tree membership proof
    rand: [u8; KEY_SIZE], // commitment randomness
}

/// A cryptographic accumulator which additionally hides the unopened elements
///
/// A MerkleSet is a randomized MerkleTree which ameliorates the Merkle tree,
/// by committing to every leaf and permuting the leafs randomly.
///
/// This provides hiding of the unopened leafs.
#[derive(Debug, Clone)]
pub struct MerkleSet {
    rand: Vec<[u8; KEY_SIZE]>,
    perm: Vec<usize>, // permutation of input elements
    tree: MerkleTree,
}

impl MerkleSetProof {
    pub fn verify(&self, leaf: &Hash) -> Hash {
        let comm = commit(&self.rand, leaf.as_bytes());
        self.proof.verify(comm)
    }
}

impl MerkleSet {
    pub fn new(seed: [u8; KEY_SIZE], elems: &[Hash]) -> MerkleSet {
        let mut rng = PRG::new(seed);

        // generate commitment randomness
        let mut rand = Vec::with_capacity(elems.len());
        for _ in 0..elems.len() {
            rand.push(rng.gen())
        }

        // generate a pseudorandom permutation
        let mut perm: Vec<usize> = (0..elems.len()).collect();
        perm.shuffle(&mut rng);

        // compute inverse permutation
        let mut perm_inv: Vec<usize> = vec![0; perm.len()];
        for (i, j) in perm.iter().cloned().enumerate() {
            perm_inv[j] = i;
        }

        // commit to and permute the elements
        let mut elems_perm: Vec<Hash> = Vec::with_capacity(elems.len());
        for i in 0..elems.len() {
            debug_assert_eq!(perm_inv[perm[i]], i);
            let comm = commit(&rand[i], elems[perm_inv[i]].as_bytes());
            elems_perm.push(comm);
        }

        // compute Merkle tree over permuted elements
        MerkleSet {
            rand,
            perm,
            tree: MerkleTree::new(&elems_perm[..]),
        }
    }

    pub fn prove(&self, index: usize) -> MerkleSetProof {
        let perm_index = self.perm[index];
        MerkleSetProof {
            rand: self.rand[perm_index],
            proof: self.tree.prove(perm_index),
        }
    }

    pub fn root(&self) -> &Hash {
        self.tree.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash, KEY_SIZE};

    use rand::{thread_rng, Rng};

    #[test]
    fn test_merkle_set() {
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

            // pick random seed
            let key: [u8; KEY_SIZE] = rng.gen();
            let set = MerkleSet::new(key, &elems[..]);

            // check that all indexes open correctly
            for index in 0..len {
                let proof = set.prove(index);
                assert_eq!(
                    set.root().clone(),
                    proof.verify(&elems[index]),
                    "index = {}, set = {:?}, proof = {:?}, elem = {:?}",
                    index,
                    set,
                    proof,
                    elems[index]
                );
            }
        }
    }
}
