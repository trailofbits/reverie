use crate::crypto::{kdf, Hasher, PRG};

#[derive(Clone)]
pub struct RandomOracle(Hasher);

impl RandomOracle {
    pub fn new(context: &'static str, bind: Option<&[u8]>) -> Self {
        let key = kdf(context, bind.unwrap_or(&[]));
        RandomOracle(Hasher::new_keyed(&key))
    }

    pub fn feed(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    pub fn query(self) -> PRG {
        PRG::new(*self.0.finalize().as_bytes())
    }
}
