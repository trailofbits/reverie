use super::*;

use std::marker::PhantomData;

use aes::block_cipher_trait::generic_array::{ArrayLength, GenericArray};

const PRF_LEFT: [u8; 16] = [0; 16];
const PRF_RIGHT: [u8; 16] = [1; 16];

#[derive(Serialize, Debug)]
enum Direction {
    Left,
    Right,
}

///
#[derive(Serialize, Debug)]
pub enum TreePRF<N: ArrayLength<Option<PRF>>> {
    Leaf(PRF, PhantomData<N>),
    Internal(PRF, Direction),
}

impl<N: ArrayLength<Option<PRF>>> TreePRF<N> {
    fn puncture_internal(&mut self, idx: usize) {
        match self {
            TreePRF::Leaf(prf, _) => {}

            TreePRF::Internal(prf, dir) => {}
        }
    }

    /// Puncture the PRF at the provided index:
    pub fn puncture(&mut self, idx: usize) {
        assert!(idx < N::to_usize(), "puncturing outside domain");
        if idx == 0 {}

        let rec = idx >> 1;
    }

    /// Expand a TreePRF into an array of PRFs (one for every leaf)
    pub fn expand(&self) -> GenericArray<Option<PRF>, N> {
        unimplemented!()
    }

    pub fn get(&self, idx: usize) -> PRF {
        unimplemented!()
    }
}
