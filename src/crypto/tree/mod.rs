use super::*;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

mod serialize;

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct TreePrf {
    size: usize,
    root: Node,
}

#[derive(Eq, PartialEq, Debug, Clone)]
enum Node {
    Punctured,                      // child has been punctured
    Leaf([u8; KEY_SIZE]),           // used for leaf nodes and full sub-trees
    Internal(Arc<Node>, Arc<Node>), // used for punctured children
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
    let mut rng = Prg::new(key);
    let mut left = [0u8; KEY_SIZE];
    let mut right = [0u8; KEY_SIZE];
    let _ = rng.fill_bytes(&mut left);
    let _ = rng.fill_bytes(&mut right);
    (left, right)
}

impl Node {
    fn puncture(&self, idx: usize, level: usize) -> Self {
        match self {
            Node::Leaf(key) => {
                if level == 0 {
                    // this is the leaf we are looking for
                    Node::Punctured
                } else {
                    // compute left and right trees
                    let (left, right) = doubling_prg(*key);
                    let (left, right) = (Node::Leaf(left), Node::Leaf(right));

                    // puncture recursively
                    if (idx >> level) & 1 == 0 {
                        Node::Internal(Arc::new(left.puncture(idx, level - 1)), Arc::new(right))
                    } else {
                        Node::Internal(Arc::new(left), Arc::new(right.puncture(idx, level - 1)))
                    }
                }
            }
            Node::Internal(left, right) => {
                // we should not be at a leaf
                debug_assert!(level > 0);

                // puncture recursively
                let res = if (idx >> level) & 1 == 0 {
                    (Arc::new(left.puncture(idx, level - 1)), Arc::clone(right))
                } else {
                    (Arc::clone(left), Arc::new(right.puncture(idx, level - 1)))
                };

                // check if both children are punctured (in which case we can remove the level)
                let punctured_left =
                    std::mem::discriminant(&*res.0) == std::mem::discriminant(&Node::Punctured);
                let punctured_right =
                    std::mem::discriminant(&*res.1) == std::mem::discriminant(&Node::Punctured);
                if punctured_left && punctured_right {
                    Node::Punctured
                } else {
                    Node::Internal(res.0, res.1)
                }
            }
            Node::Punctured => Node::Punctured, // place already punctured
        }
    }

    fn expand<'a>(
        &self,
        result: &'a mut [Option<[u8; KEY_SIZE]>],
        level: usize,
    ) -> &'a mut [Option<[u8; KEY_SIZE]>] {
        // check if we have extracted the required number of leafs
        if result.is_empty() {
            return result;
        }

        // otherwise descend
        match self {
            Node::Punctured => {
                // all the 2^level children of a punctured node are also punctured
                let length = std::cmp::min(1 << level, result.len());
                for child in result.iter_mut().take(length) {
                    *child = None;
                }
                &mut result[length..]
            }
            Node::Internal(left, right) => {
                debug_assert!(level > 0);

                // expand the left child
                let result = left.expand(result, level - 1);

                // fill the remainder from the right child
                right.expand(result, level - 1)
            }
            Node::Leaf(key) => {
                if level == 0 {
                    // we are in a leaf
                    result[0] = Some(*key);
                    &mut result[1..]
                } else {
                    // compute left and right trees
                    let (left, right) = doubling_prg(*key);
                    let (left, right) = (Node::Leaf(left), Node::Leaf(right));

                    // expand the left child
                    let result = left.expand(result, level - 1);

                    // fill the remainder from the right child
                    right.expand(result, level - 1)
                }
            }
        }
    }
}

impl TreePrf {
    pub fn new(size: usize, key: [u8; KEY_SIZE]) -> TreePrf {
        TreePrf {
            size,
            root: Node::Leaf(key),
        }
    }

    /// Puncture the PRF at the provided index:
    pub fn puncture(&self, idx: usize) -> TreePrf {
        assert!(idx < self.size);
        Self {
            size: self.size,
            root: self.root.puncture(idx << 1, num_levels(self.size)),
        }
    }

    /// Expand a TreePRF into an array of PRFs (one for every leaf).
    /// Does an in-order traversal on the tree to extract the first "leafs" nodes.
    pub fn expand(&self, dst: &mut [Option<[u8; KEY_SIZE]>]) {
        assert_eq!(dst.len(), self.size);
        self.root.expand(dst, num_levels(self.size));
    }

    pub fn expand_full(result: &mut [[u8; KEY_SIZE]], root: [u8; KEY_SIZE]) {
        fn expand_full_internal(
            result: &mut [[u8; KEY_SIZE]],
            root: [u8; KEY_SIZE],
            levels: usize,
        ) -> &mut [[u8; KEY_SIZE]] {
            if result.is_empty() {
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
        let size = result.len();
        expand_full_internal(result, root, num_levels(size));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::Rng;
    use std::collections::HashSet;

    #[test]
    fn test_expand_full() {
        let size = 324;
        let mut rng = rand::thread_rng();
        let seed: [u8; KEY_SIZE] = rng.gen();
        let tree: TreePrf = TreePrf::new(size, seed);
        let mut results_full = vec![[0u8; KEY_SIZE]; size];
        let mut results = vec![None; size];
        TreePrf::expand_full(&mut results_full, seed);
        tree.expand(&mut results);
        for (a, b) in results.iter().zip(results_full.iter()) {
            debug_assert_eq!(a.unwrap(), *b);
        }
    }

    #[test]
    fn test_puncture() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let size: usize = (rng.gen::<usize>() % 2048) + 1;
            rnd_puncture(size);
        }
    }

    fn rnd_puncture(size: usize) {
        // original tree
        let mut rng = rand::thread_rng();
        let tree: TreePrf = TreePrf::new(size, rng.gen());

        // generate punctured tree
        let mut p_tree = tree.clone();
        let mut punctured: HashSet<usize> = HashSet::new();
        for i in 0..size {
            if rng.gen() {
                p_tree = p_tree.puncture(i);
                punctured.insert(i);
            }
        }

        // check that the new tree agree with the original on every non-punctured index
        let mut expand = vec![None; size];
        let mut p_expand = vec![None; size];
        tree.expand(&mut expand);
        p_tree.expand(&mut p_expand);
        for i in 0..size {
            assert!(expand[i].is_some());
            if punctured.contains(&i) {
                assert_eq!(p_expand[i], None);
            } else {
                assert_eq!(expand[i], p_expand[i]);
            }
        }
    }
}
