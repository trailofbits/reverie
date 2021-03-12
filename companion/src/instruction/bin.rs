use super::Parser;

use std::fs::File;
use std::io::{self, BufReader};

use reverie::algebra::gf2::BitScalar;
use reverie::Instruction;

/// Load from bincode-encoded list of gates
pub struct InsParser {
    instructions: Vec<Instruction<BitScalar>>,
}

impl Parser<Instruction<BitScalar>> for InsParser {
    fn new(reader: BufReader<File>) -> io::Result<Self> {
        let mut instructions: Vec<Instruction<BitScalar>> = bincode::deserialize_from(reader).unwrap();
        instructions.reverse();
        Ok(InsParser { instructions })
    }

    fn next(&mut self) -> io::Result<Option<Instruction<BitScalar>>> {
        Ok(self.instructions.pop())
    }
}
