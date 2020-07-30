use ::serde::de::{Error, SeqAccess, Unexpected, Visitor};
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::fmt;

use super::*;

const MAX_SIZE: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
struct FlatTree {
    size: u16,
    nodes: Vec<FlatNode>,
}

#[derive(Debug, Serialize, Deserialize)]
enum FlatNode {
    Punctured,
    Internal,
    Leaf([u8; KEY_SIZE]),
}

struct TreeVistor();

impl<'de> Visitor<'de> for TreeVistor {
    type Value = Node;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a sequence of flat nodes")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // read into vector
        let mut res: Vec<FlatNode> = Vec::with_capacity(MAX_SIZE);
        while let Some(v) = seq.next_element()? {
            if res.len() >= MAX_SIZE {
                break;
            }
            res.push(v);
        }

        // unflatten vector into tree
        match unflatten(&res[..]) {
            None => Err(A::Error::invalid_value(Unexpected::Seq, &self)),
            Some((rest, tree)) => {
                if rest.len() == 0 {
                    Ok(tree)
                } else {
                    Err(A::Error::invalid_value(Unexpected::Seq, &self))
                }
            }
        }
    }
}

fn flatten(dst: &mut Vec<FlatNode>, node: &Node) {
    match node {
        Node::Punctured => dst.push(FlatNode::Punctured),
        Node::Leaf(key) => dst.push(FlatNode::Leaf(*key)),
        Node::Internal(left, right) => {
            dst.push(FlatNode::Internal);
            flatten(dst, left);
            flatten(dst, right);
        }
    }
}

fn unflatten(src: &[FlatNode]) -> Option<(&[FlatNode], Node)> {
    match src.get(0)? {
        FlatNode::Punctured => Some((&src[1..], Node::Punctured)),
        FlatNode::Leaf(key) => Some((&src[1..], Node::Leaf(*key))),
        FlatNode::Internal => {
            let src = &src[1..];
            let (src, left) = unflatten(src)?;
            let (src, right) = unflatten(src)?;
            Some((src, Node::Internal(Arc::new(left), Arc::new(right))))
        }
    }
}

impl Serialize for Node {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut flat: Vec<FlatNode> = Vec::new();
        flatten(&mut flat, self);
        Serialize::serialize(&flat, serializer)
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> Result<Node, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(TreeVistor())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bincode;
    #[test]
    fn serde_tree() {
        let tree: TreePRF = TreePRF::new(256, [7u8; KEY_SIZE]);
        let serialized = bincode::serialize(&tree).unwrap();
        let tree_new: TreePRF = bincode::deserialize(&serialized[..]).unwrap();
        assert_eq!(tree, tree_new);
    }
}
