use ::serde::de::{Error, SeqAccess, Unexpected, Visitor};
use ::serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::fmt;

use super::*;

#[derive(Debug, Serialize, Deserialize)]
enum FlatNode {
    Punctured,
    Internal,
    Leaf([u8; KEY_SIZE]),
}

struct TreeVistor<const N: usize>();

impl<'de, const N: usize> Visitor<'de> for TreeVistor<N> {
    type Value = TreePRF<N>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a sequence of flat nodes")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // read into vector
        let mut res: Vec<FlatNode> = Vec::with_capacity(2 * N);
        while let Some(v) = seq.next_element()? {
            if res.len() >= 2 * N {
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

fn flatten<const N: usize>(dst: &mut Vec<FlatNode>, tree: &TreePRF<N>) {
    match tree {
        TreePRF::Punctured => dst.push(FlatNode::Punctured),
        TreePRF::Leaf(key) => dst.push(FlatNode::Leaf(*key)),
        TreePRF::Internal(left, right) => {
            dst.push(FlatNode::Internal);
            flatten(dst, left);
            flatten(dst, right);
        }
    }
}

fn unflatten<const N: usize>(src: &[FlatNode]) -> Option<(&[FlatNode], TreePRF<N>)> {
    match src.get(0)? {
        FlatNode::Punctured => Some((&src[1..], TreePRF::Punctured)),
        FlatNode::Leaf(key) => Some((&src[1..], TreePRF::Leaf(*key))),
        FlatNode::Internal => {
            let src = &src[1..];
            let (src, left) = unflatten(src)?;
            let (src, right) = unflatten(src)?;
            Some((src, TreePRF::Internal(Arc::new(left), Arc::new(right))))
        }
    }
}

impl<const N: usize> Serialize for TreePRF<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut flat: Vec<FlatNode> = Vec::new();
        flatten(&mut flat, self);
        Serialize::serialize(&flat, serializer)
    }
}

impl<'de, const N: usize> Deserialize<'de> for TreePRF<N> {
    fn deserialize<D>(deserializer: D) -> Result<TreePRF<N>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(TreeVistor::<N>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bincode;

    #[test]
    fn serde_tree() {
        let tree: TreePRF<32> = TreePRF::new([7u8; KEY_SIZE]);

        let serialized = bincode::serialize(&tree).unwrap();

        let tree_new: TreePRF<32> = bincode::deserialize(&serialized[..]).unwrap();

        println!("{:?} {:?}", &serialized[..], tree_new);
    }
}
