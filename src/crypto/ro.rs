use blake3;

pub struct RandomOracle {
    reader: blake3::OutputReader,
}

impl RandomOracle {
    pub fn new(ctx: &'static str, input: &[u8]) -> RandomOracle {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ctx.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(input);
        RandomOracle {
            reader: hasher.finalize_xof(),
        }
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        self.reader.fill(buf)
    }
}
