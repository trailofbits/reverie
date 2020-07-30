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

const fn num_levels(n: usize) -> usize {
    if n & (n - 1) == 0 {
        log2(n)
    } else {
        log2(n) + 1
    }
}

// The length-doubling prng used for the PRF tree
fn doubling_prg(key: [u8; KEY_SIZE]) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let mut rng = PRG::new(key);
    let mut left = [0u8; KEY_SIZE];
    let mut right = [0u8; KEY_SIZE];
    let _ = rng.fill_bytes(&mut left);
    let _ = rng.fill_bytes(&mut right);
    (left, right)
}

impl<const N: usize> TreePRF<N> {
    pub fn new(key: [u8; KEY_SIZE]) -> TreePRF<N> {
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
                    let (left, right) = doubling_prg(*key);
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
        self.puncture_internal(idx << 1, num_levels(N))
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
                    let (left, right) = doubling_prg(*key);
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
    pub fn expand(&self, dst: &mut [Option<[u8; KEY_SIZE]>; N]) {
        self.expand_internal(&mut dst[..], num_levels(N));
    }

    pub fn expand_full(result: &mut [[u8; KEY_SIZE]; N], root: &[u8; KEY_SIZE]) {
        fn expand_full_internal<'a>(
            result: &'a mut [[u8; KEY_SIZE]],
            root: [u8; KEY_SIZE],
            levels: usize,
        ) -> &'a mut [[u8; KEY_SIZE]] {
            if result.len() == 0 {
                // destination full
                result
            } else if levels == 0 {
                // leaf
                result[0] = root;
                &mut result[1..]
            } else {
                // internal
                let (left, right) = doubling_prg(root);
                let result = expand_full_internal(result, left, levels - 1);
                expand_full_internal(result, right, levels - 1)
            }
        }
        expand_full_internal(
            result,
            *root,
            if N & (N - 1) == 0 {
                log2(N)
            } else {
                log2(N) + 1
            },
        );
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
        let mut expand: Array<_, N> = Array::new(None);
        let mut p_expand: Array<_, N> = Array::new(None);
        tree.expand(&mut expand);
        p_tree.expand(&mut p_expand);
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
        let mut dst: Array<_, 64> = Array::new(None);
        b.iter(|| {
            let tree: TreePRF<64> = TreePRF::new(seed);
            tree.expand(&mut dst);
        });
    }
}
