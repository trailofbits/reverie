use super::*;

use blake3::Hash;

/// Represents a labelled Scope, enabling use to write (key, value) pairs
/// to the transcript, without needing to hold all of "value" in memory.
///
/// The Scope takes a mutable pointer of the view,
/// which ensures a unique ordering of scopes inside the view.
pub struct Scope<'a> {
    pub(super) view: &'a mut View,
    pub(super) length: u64,
}

impl<'a> Scope<'a> {
    pub fn update(&mut self, message: &[u8]) {
        let _ = self.view.hasher.write(message);
        self.length += message.len() as u64;
    }

    pub fn join(&mut self, hash: &Hash) {
        self.update(hash.as_bytes());
    }
}

impl<'a> Drop for Scope<'a> {
    fn drop(&mut self) {
        let _ = self.view.hasher.write(&self.length.to_le_bytes());
        let _ = self.view.hasher.flush();
    }
}
