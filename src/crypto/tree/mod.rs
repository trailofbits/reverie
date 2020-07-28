use super::*;

use std::sync::Arc;

use blake3::Hasher;

mod serde;

/// Since we have no additional overhead from assuming that the tree is always complete.
/// We assume that the number of elements in the tree is a power of two for simplicity.
#[derive(Debug, Clone)]
pub enum TreePRF<const N: usize> {
    Punctured,                                  // child has been punctured
    Leaf([u8; KEY_SIZE]),                       // used for leaf nodes and full sub-trees
    Internal(Arc<TreePRF<N>>, Arc<TreePRF<N>>), // used for punctured children
}

// The length-doubling prng used for the PRF tree
fn doubling_prng(key: &[u8; KEY_SIZE]) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    // seed and obtain PRG
    let mut rng = {
        let mut k = [0u8; 32];
        k[..KEY_SIZE].copy_from_slice(&key[..]);
        Hasher::new_keyed(&k).finalize_xof()
    };

    // read 2 x 128-bit from the PRG
    let mut left = [0u8; KEY_SIZE];
    let mut right = [0u8; KEY_SIZE];
    rng.fill(&mut left);
    rng.fill(&mut right);
    (left, right)
}

impl<const N: usize> TreePRF<N> {
    pub fn new(key: [u8; KEY_SIZE]) -> TreePRF<N> {
        assert!(N.is_power_of_two());
        TreePRF::Leaf(key)
    }

    fn puncture_internal(&self, idx: usize, level: usize) -> TreePRF<N> {
        debug_assert!(level <= log2(N));

        match self {
            TreePRF::Leaf(key) => {
                if level == 0 {
                    // this is the leaf we are looking for
                    TreePRF::Punctured
                } else {
                    // compute left and right trees
                    let (left, right) = doubling_prng(key);
                    let (left, right) = (Self::new(left), Self::new(right));

                    // puncture recursively
                    if (idx >> level) & 1 == 0 {
                        TreePRF::Internal(
                            Arc::new(left.puncture_internal(idx, level - 1)),
                            Arc::new(right),
                        )
                    } else {
                        TreePRF::Internal(
                            Arc::new(left),
                            Arc::new(right.puncture_internal(idx, level - 1)),
                        )
                    }
                }
            }
            TreePRF::Internal(left, right) => {
                // we should not be at a leaf
                debug_assert!(level > 0);

                // puncture recursively
                let res = if (idx >> level) & 1 == 0 {
                    (
                        Arc::new(left.puncture_internal(idx, level - 1)),
                        Arc::clone(right),
                    )
                } else {
                    (
                        Arc::clone(left),
                        Arc::new(right.puncture_internal(idx, level - 1)),
                    )
                };

                // check if both children are punctured (in which case we can remove the level)
                let punctured_left =
                    std::mem::discriminant(&*res.0) == std::mem::discriminant(&TreePRF::Punctured);
                let punctured_right =
                    std::mem::discriminant(&*res.1) == std::mem::discriminant(&TreePRF::Punctured);
                if punctured_left && punctured_right {
                    TreePRF::Punctured
                } else {
                    TreePRF::Internal(res.0, res.1)
                }
            }
            TreePRF::Punctured => TreePRF::Punctured, // place already punctured
        }
    }

    /// Puncture the PRF at the provided index:
    pub fn puncture(&self, idx: usize) -> TreePRF<N> {
        assert!(idx < N, "puncturing outside domain");
        self.puncture_internal(idx << 1, log2(N))
    }

    fn expand_internal<'a>(
        &self,
        result: &'a mut [Option<[u8; KEY_SIZE]>],
        level: usize,
    ) -> &'a mut [Option<[u8; KEY_SIZE]>] {
        // check if we have extracted the required number of leafs
        debug_assert!(level <= log2(N));
        if result.len() == 0 {
            return result;
        }

        // otherwise descend
        match self {
            TreePRF::Punctured => {
                // all the 2^level children of a punctured node are also punctured
                let length = std::cmp::min(1 << level, result.len());
                for i in 0..length {
                    result[i] = None;
                }
                &mut result[length..]
            }
            TreePRF::Internal(left, right) => {
                debug_assert!(level > 0);

                // expand the left child
                let result = left.expand_internal(result, level - 1);

                // fill the remainder from the right child
                right.expand_internal(result, level - 1)
            }
            TreePRF::Leaf(key) => {
                if level == 0 {
                    // we are in a leaf
                    result[0] = Some(*key);
                    &mut result[1..]
                } else {
                    // compute left and right trees
                    let (left, right) = doubling_prng(key);
                    let (left, right) = (Self::new(left), Self::new(right));

                    // expand the left child
                    let result = left.expand_internal(result, level - 1);

                    // fill the remainder from the right child
                    right.expand_internal(result, level - 1)
                }
            }
        }
    }

    /// Expand a TreePRF into an array of PRFs (one for every leaf).
    /// Does an in-order traversal on the tree to extract the first "leafs" nodes.
    pub fn expand<const L: usize>(&self) -> Array<Option<[u8; KEY_SIZE]>, L> {
        assert!(L <= N); // should be optimized out
        let mut result: Array<Option<[u8; KEY_SIZE]>, L> = Array::new(None);
        self.expand_internal(&mut result[..], log2(N));
        result
    }

    /// Expand a TreePRF into an array of PRFs (one for every leaf).
    /// Does an in-order traversal on the tree to extract the first "leafs" nodes.
    pub fn expand_vec(&self, len: usize) -> Vec<Option<[u8; KEY_SIZE]>> {
        let mut result = vec![None; len];
        self.expand_internal(&mut result[..], log2(N));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::Rng;
    use std::collections::HashSet;

    #[test]
    fn test_puncture16() {
        for _ in 0..100 {
            test_puncture::<16>();
        }
    }

    #[test]
    fn test_puncture32() {
        for _ in 0..100 {
            test_puncture::<32>();
        }
    }

    #[test]
    fn test_puncture64() {
        test_puncture::<64>();
    }

    #[test]
    fn test_puncture256() {
        test_puncture::<256>();
    }

    #[test]
    fn test_puncture512() {
        test_puncture::<512>();
    }

    fn test_puncture<const N: usize>() {
        // original tree
        let mut rng = rand::thread_rng();
        let tree: TreePRF<N> = TreePRF::new(rng.gen());

        // generate punctured tree
        let mut p_tree = tree.clone();
        let mut punctured: HashSet<usize> = HashSet::new();
        for i in 0..N {
            if rng.gen() {
                p_tree = p_tree.puncture(i);
                punctured.insert(i);
            }
        }

        // check that the new tree agree with the original on every non-punctured index
        let expand: Array<_, N> = tree.expand();
        let p_expand: Array<_, N> = p_tree.expand();
        for i in 0..N {
            assert!(expand[i].is_some());
            if punctured.contains(&i) {
                assert_eq!(p_expand[i], None);
            } else {
                assert_eq!(expand[i], p_expand[i]);
            }
        }
    }
}

#[cfg(test)]
mod benchmark {
    use super::*;

    use test::Bencher;

    #[bench]
    fn bench_tree_expand64(b: &mut Bencher) {
        let seed = test::black_box([0u8; KEY_SIZE]);
        b.iter(|| {
            let tree: TreePRF<64> = TreePRF::new(seed);
            let _: Array<_, 64> = tree.expand();
        });
    }
}
