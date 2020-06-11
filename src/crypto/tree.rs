use super::KEY_SIZE;

use std::marker::PhantomData;
use std::mem;
use std::rc::Rc;

use blake3::Hasher;

use typenum::{PowerOfTwo, Unsigned};

const PRF_LEFT: [u8; 16] = [0; 16];
const PRF_RIGHT: [u8; 16] = [1; 16];

/// Since we have no additional overhead from assuming that the tree is always complete.
/// We assume that the number of elements in the tree is a power of two for simplicity.
#[derive(Debug, Clone)]
pub enum TreePRF<N: PowerOfTwo + Unsigned> {
    Punctured,                                // child has been punctured
    Leaf([u8; KEY_SIZE], PhantomData<N>),     // used for leaf nodes and full sub-trees
    Internal(Rc<TreePRF<N>>, Rc<TreePRF<N>>), // used for punctured children
}

const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

fn double_prng(key: &[u8; KEY_SIZE]) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let mut k = [0u8; 32];
    let mut left = [0u8; KEY_SIZE];
    let mut right = [0u8; KEY_SIZE];
    k[..KEY_SIZE].copy_from_slice(&key[..]);

    let hasher = Hasher::new_keyed(&k);
    let result = hasher.finalize();
    left[..].copy_from_slice(&result.as_bytes()[..KEY_SIZE]);
    right[..].copy_from_slice(&result.as_bytes()[KEY_SIZE..]);
    (left, right)
}

impl<N: PowerOfTwo + Unsigned> TreePRF<N> {
    pub fn new(key: [u8; KEY_SIZE]) -> TreePRF<N> {
        TreePRF::Leaf(key, PhantomData)
    }

    fn puncture_internal(&self, idx: usize, level: usize) -> TreePRF<N> {
        assert!(level <= log2(N::to_usize()));
        match self {
            TreePRF::Leaf(key, _) => {
                if level == 0 {
                    // this is the leaf we are looking for
                    TreePRF::Punctured
                } else {
                    // compute left and right trees
                    let (left, right) = double_prng(key);
                    let (left, right) = (Self::new(left), Self::new(right));

                    // puncture recursively
                    if (idx >> level) & 1 == 0 {
                        TreePRF::Internal(
                            Rc::new(left.puncture_internal(idx, level - 1)),
                            Rc::new(right),
                        )
                    } else {
                        TreePRF::Internal(
                            Rc::new(left),
                            Rc::new(right.puncture_internal(idx, level - 1)),
                        )
                    }
                }
            }
            TreePRF::Internal(left, right) => {
                // we should not be at a leaf
                debug_assert!(level > 0);

                // puncture recursively
                if (idx >> level) & 1 == 0 {
                    TreePRF::Internal(
                        Rc::new(left.puncture_internal(idx, level - 1)),
                        Rc::clone(right),
                    )
                } else {
                    TreePRF::Internal(
                        Rc::clone(left),
                        Rc::new(right.puncture_internal(idx, level - 1)),
                    )
                }
            }
            TreePRF::Punctured => TreePRF::Punctured,
        }
    }

    /// Puncture the PRF at the provided index:
    pub fn puncture(&self, idx: usize) -> TreePRF<N> {
        assert!(idx < N::to_usize(), "puncturing outside domain");
        self.puncture_internal(idx << 1, log2(N::to_usize()))
    }

    pub fn expand_internal(
        &self,
        result: &mut Vec<Option<[u8; KEY_SIZE]>>,
        leafs: usize,
        level: usize,
    ) {
        // check if we have extracted the required number of leafs
        assert!(level <= log2(N::to_usize()));
        if result.len() >= leafs {
            return;
        }

        // otherwise descend
        match self {
            TreePRF::Punctured => {
                result.push(None);
            }
            TreePRF::Internal(left, right) => {
                left.expand_internal(result, leafs, level - 1);
                right.expand_internal(result, leafs, level - 1);
            }
            TreePRF::Leaf(key, _) => {
                if level == 0 {
                    // we are in a leaf
                    result.push(Some(*key));
                } else {
                    // compute left and right trees
                    let (left, right) = double_prng(key);
                    let (left, right) = (Self::new(left), Self::new(right));

                    left.expand_internal(result, leafs, level - 1);
                    right.expand_internal(result, leafs, level - 1);
                }
            }
        }
    }

    /// Expand a TreePRF into an array of PRFs (one for every leaf).
    /// Does an in-order traversal on the tree to extract the first "leafs" nodes.
    pub fn expand(&self, leafs: usize) -> Vec<Option<[u8; KEY_SIZE]>> {
        assert!(
            leafs <= N::to_usize(),
            "the tree does not have sufficient leafs"
        );
        let mut result = Vec::with_capacity(leafs);
        self.expand_internal(&mut result, leafs, log2(N::to_usize()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use rand::Rng;
    use typenum::consts::*;

    #[test]
    fn test_puncture16() {
        for _ in 0..100 {
            test_puncture::<U16>();
        }
    }

    #[test]
    fn test_puncture32() {
        for _ in 0..100 {
            test_puncture::<U32>();
        }
    }

    #[test]
    fn test_puncture64() {
        test_puncture::<U64>();
    }

    #[test]
    fn test_puncture256() {
        test_puncture::<U256>();
    }

    #[test]
    fn test_puncture512() {
        test_puncture::<U512>();
    }

    fn test_puncture<N: Unsigned + PowerOfTwo>() {
        // original tree
        let mut rng = rand::thread_rng();
        let tree: TreePRF<N> = TreePRF::new(rng.gen());

        // generate punctured tree
        let mut p_tree = tree.clone();
        let mut punctured: HashSet<usize> = HashSet::new();
        for i in 0..N::to_usize() {
            if rng.gen() {
                p_tree = p_tree.puncture(i);
                punctured.insert(i);
            }
        }

        // check that the new tree agree with the original on every non-punctured index
        let expand = tree.expand(N::to_usize());
        let p_expand = p_tree.expand(N::to_usize());
        for i in 0..N::to_usize() {
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
#[cfg(feature = "unstable")]
mod benchmark {
    use super::*;

    use test::Bencher;
    use typenum::consts::*;

    #[bench]
    fn bench_tree_expand64(b: &mut Bencher) {
        let seed = test::black_box([0u8; KEY_SIZE]);
        b.iter(|| {
            let tree: TreePRF<U64> = TreePRF::new(seed);
            tree.expand(64);
        });
    }
}
