use aesni::cipher::generic_array::GenericArray;
use aesni::cipher::NewBlockCipher;
use aesni::stream::{FromBlockCipher, SyncStreamCipher};
use aesni::Aes128Ctr;

const BLOCK_SIZE: usize = 16;

pub const KEY_SIZE: usize = 16;

pub type Key = [u8; KEY_SIZE];

pub struct PRG(Aes128Ctr);

impl PRG {
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(&[0u8; 16]);
        PRG(Aes128Ctr::from_block_cipher(aesni::Aes128::new(key), nonce))
    }

    pub fn xor_bytes(&mut self, dst: &mut [u8]) {
        debug_assert_eq!(dst.len() % BLOCK_SIZE, 0);
        self.0.apply_keystream(dst);
    }

    pub fn gen(&mut self, dst: &mut [u8]) {
        {
            let (_prefix, aligned, _suffix) = unsafe { dst.align_to_mut::<u128>() };
            debug_assert_eq!(_prefix.len(), 0);
            debug_assert_eq!(_suffix.len(), 0);
            for word in aligned.iter_mut() {
                *word = 0;
            }
        }
        self.xor_bytes(dst);
    }
}
