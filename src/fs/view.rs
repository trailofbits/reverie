use super::*;

use blake3::{Hash, Hasher, OutputReader};
use rand_core::{impls, CryptoRng, Error, RngCore};

pub struct View {
    hasher: Hasher,
}

pub struct Scope<'a> {
    view: &'a mut View,
    length: u64,
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
    ///
    /// This is used to simulate parties (in-the-head) with secret random tapes.
    pub fn new_keyed(seed: [u8; KEY_SIZE]) -> View {
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

    /// Produce a new unseeded view
    ///
    /// This can be used for simulate public coin verifiers (Fiat-Shamir).
    pub fn new() -> View {
        View {
            hasher: Hasher::new(),
            #[cfg(debug)]
            transcript: vec![],
        }
    }

    /// Return the PRNG bound to the present view
    pub fn rng(&self, label: &'static [u8]) -> ViewRNG {
        ViewRNG::new(&self.hasher, label)
    }

    /// Produce a hash of the view.
    /// If the initial seed has high min-entropy then
    /// the hash additionally serves as a blinding commitment.
    pub fn hash(&self) -> Hash {
        self.hasher.finalize()
    }

    /// Returns a new labelled scope.
    /// Scopes are used to add messages to the view.
    ///
    /// The type system ensure that at most one scope can be live for any view at any time.
    /// The scope is automatically serialized into the view when it is dropped,
    /// while only consuming a constant amount of memory.
    pub fn scope<'a>(&'a mut self, label: &'static [u8]) -> Scope<'a> {
        self.hasher.update(label);
        self.hasher.update(&(label.len() as u8).to_le_bytes());
        self.hasher.update(&[1]);
        Scope {
            length: 0,
            view: self,
        }
    }
}
