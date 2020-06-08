use super::*;

use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::rc::Rc;

use typenum::{PowerOfTwo, Unsigned};

const PRF_LEFT: [u8; 16] = [0; 16];
const PRF_RIGHT: [u8; 16] = [1; 16];

/// Since we have no additional overhead from assuming that the tree is always complete.
/// We assume that the number of elements in the tree is a power of two for simplicity.
#[derive(Debug, Clone)]
pub enum TreePRF<N: PowerOfTwo + Unsigned> {
    Punctured,                                // child has been punctured
    Leaf(PRF, PhantomData<N>),                // used for leaf nodes and full sub-trees
    Internal(Rc<TreePRF<N>>, Rc<TreePRF<N>>), // used for punctured children
}

const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

impl<N: PowerOfTwo + Unsigned> fmt::Display for TreePRF<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TreePRF::Punctured => write!(f, "none"),
            TreePRF::Leaf(prf, _) => write!(f, "{}", prf),
            TreePRF::Internal(left, right) => write!(f, "({}, {})", left, right),
        }
    }
}

impl<N: PowerOfTwo + Unsigned> TreePRF<N> {
    pub fn new(key: [u8; 16]) -> TreePRF<N> {
        TreePRF::Leaf(PRF::new(key), PhantomData)
    }

    fn puncture_internal(&self, idx: usize, level: usize) -> TreePRF<N> {
        assert!(level <= log2(N::to_usize()));
        match self {
            TreePRF::Leaf(prf, _) => {
                if level == 0 {
                    // this is the leaf we are looking for
                    TreePRF::Punctured
                } else {
                    // compute left and right trees
                    let left = TreePRF::Leaf(PRF::new(prf.eval(&PRF_LEFT)), PhantomData);
                    let right = TreePRF::Leaf(PRF::new(prf.eval(&PRF_RIGHT)), PhantomData);

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

    pub fn expand_internal(&self, result: &mut Vec<Option<PRF>>, leafs: usize, level: usize) {
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
            TreePRF::Leaf(prf, _) => {
                if level == 0 {
                    // we are in a leaf
                    result.push(Some(prf.clone()));
                } else {
                    // compute left and right trees
                    let left: TreePRF<N> =
                        TreePRF::Leaf(PRF::new(prf.eval(&PRF_LEFT)), PhantomData);
                    let right: TreePRF<N> =
                        TreePRF::Leaf(PRF::new(prf.eval(&PRF_RIGHT)), PhantomData);

                    left.expand_internal(result, leafs, level - 1);
                    right.expand_internal(result, leafs, level - 1);
                }
            }
        }
    }

    /// Expand a TreePRF into an array of PRFs (one for every leaf).
    /// Does an in-order traversal on the tree to extract the first "leafs" nodes.
    pub fn expand(&self, leafs: usize) -> Vec<Option<PRF>> {
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
        for _ in 0..100 {
            test_puncture::<U64>();
        }
    }

    #[test]
    fn test_puncture256() {
        for _ in 0..100 {
            test_puncture::<U256>();
        }
    }

    #[test]
    fn test_puncture512() {
        for _ in 0..100 {
            test_puncture::<U512>();
        }
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
