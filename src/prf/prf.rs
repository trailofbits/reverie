use super::*;

use std::fmt;

use hex;

use subtle::ConstantTimeEq;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

#[derive(Debug, Clone)]
pub struct PRF {
    key: [u8; 16],
    bc: Aes128,
}

/// Defines the PRF used throughout the project:
///
/// PRF(k, v) = AES-128(k, v)
impl PRF {
    pub fn new(k: [u8; 16]) -> PRF {
        PRF {
            key: k,
            bc: Aes128::new(GenericArray::from_slice(&k[..])),
        }
    }

    pub fn eval(&self, v: &[u8; 16]) -> [u8; 16] {
        let mut blk = v.clone();
        let mut slc = GenericArray::from_mut_slice(&mut blk);
        self.bc.encrypt_block(&mut slc);
        blk
    }
}

impl fmt::Display for PRF {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AES-128({}, *)", hex::encode(self.key))
    }
}

impl PartialEq for PRF {
    fn eq(&self, other: &Self) -> bool {
        self.key.ct_eq(&other.key).into()
    }
}

/// A PRF is serialized as its key
impl Serialize for PRF {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(16))?;
        for b in self.key.iter() {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}
