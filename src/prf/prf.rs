use super::*;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

#[derive(Debug)]
pub struct PRF {
    key: [u8; 16],
    bc: Aes128,
}

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

/*
/// A key can be deserialized into a PRF
impl Deserialize for PRF {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!()
    }
}
*/
