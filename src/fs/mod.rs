use crate::crypto::{Hash, Hasher, KEY_SIZE, PRG};

use std::io::Write;

mod rng;
mod scope;

pub use rng::ViewRNG;
pub use scope::Scope;

pub struct View {
    hasher: Hasher,
}

impl View {
    /// Produce a new view with randomness extracted from the seed
    ///
    /// This is used to simulate parties (in-the-head) with secret random tapes.
    pub fn new_keyed(key: &[u8; KEY_SIZE]) -> View {
        View {
            hasher: Hasher::new_keyed(&key),
        }
    }

    /// Produce a new unseeded view
    ///
    /// This can be used for simulate public coin verifiers (Fiat-Shamir).
    pub fn new() -> View {
        View {
            hasher: Hasher::new(),
        }
    }

    /// Return the PRNG bound to the present view
    pub fn prg(&self, label: &'static [u8]) -> PRG {
        let mut hasher = self.hasher.clone();
        hasher.update(label);
        hasher.update(&(label.len() as u8).to_le_bytes());
        hasher.update(&[0]);
        PRG::new(*hasher.finalize().as_bytes())
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
        // when scope is dropped it flushes the content to the hash.
    }
}

pub fn union_views<'a, I: Iterator<Item = &'a View>>(views: I) -> Hash {
    let mut hasher = Hasher::new();
    for view in views {
        hasher.update(view.hash().as_bytes());
    }
    hasher.finalize()
}
