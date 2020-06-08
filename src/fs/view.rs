use super::*;

use blake3::{Hash, Hasher, OutputReader};
use rand_core::{impls, CryptoRng, Error, RngCore};

pub struct View {
    hasher: Hasher,
}

pub struct ViewRNG {
    /// TODO: buffer to improve performance
    /// https://docs.rs/blake3/0.3.4/src/blake3/lib.rs.html#1199-1201
    reader: OutputReader,
}

pub struct Scope<'a> {
    view: &'a mut View,
    length: u64,
}

impl CryptoRng for ViewRNG {}

impl RngCore for ViewRNG {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.fill(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }

    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }
}

impl<'a> Scope<'a> {
    pub fn update(&mut self, message: &[u8]) {
        self.view.hasher.update(message);
        self.length += message.len() as u64;
    }
}

impl<'a> Drop for Scope<'a> {
    fn drop(&mut self) {
        self.view.hasher.update(&self.length.to_le_bytes());
    }
}

impl View {
    /// Produce a new view with randomness extracted from the seed
    pub fn new(seed: [u8; KEY_SIZE]) -> View {
        // create keyed hasher
        let mut key: [u8; 32] = [0u8; 32];
        key[..16].copy_from_slice(&seed[..]);
        let hasher = Hasher::new_keyed(&key);

        View {
            hasher,
            #[cfg(debug)]
            transcript: vec![],
        }
    }

    /// Return the PRNG bound to the present view
    pub fn rng(&self) -> ViewRNG {
        let mut reader = self.hasher.finalize_xof();
        reader.set_position(32);
        ViewRNG { reader }
    }

    /// Produce a hash of the view.
    /// If the seed has high min-entropy then the hash serves as a commitment.
    pub fn commit(&self) -> Hash {
        self.hasher.finalize()
    }

    /// Returns a new labelled scope.
    /// Scopes are used to add messages to the view.
    pub fn scope<'a>(&'a mut self, label: &'static [u8]) -> Scope<'a> {
        self.hasher.update(label);
        self.hasher.update(&(label.len() as u8).to_le_bytes());
        Scope {
            length: 0,
            view: self,
        }
    }
}
