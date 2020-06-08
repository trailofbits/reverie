use blake3::Hasher;

pub struct Transcript {
    hasher: Hasher,

    #[cfg(debug)]
    transcript: Vec<u8>,
}

impl Transcript {
    // appends a message to the transcript
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {}

    /// Returns an CSPRNG used for generating verifier challenges
    fn challenge(&self, label: &'static [u8]) {}
}
