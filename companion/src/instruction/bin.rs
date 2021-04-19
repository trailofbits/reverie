use super::Parser;

use std::fs::File;
use std::io::{self, BufReader};

use reverie::algebra::gf2::BitScalar;
use reverie::algebra::z64::Scalar;

use reverie::algebra::RingElement;
use reverie::Instruction;

/// Load from bincode-encoded list of gates
pub struct InsParser<T: RingElement> {
    instructions: Vec<Instruction<T>>,
}

impl Parser<Instruction<BitScalar>> for InsParser<BitScalar> {
    fn new(reader: BufReader<File>) -> io::Result<Self> {
        let mut instructions: Vec<Instruction<BitScalar>> =
            bincode::deserialize_from(reader).unwrap();
        instructions.reverse();
        Ok(InsParser { instructions })
    }

    fn next(&mut self) -> io::Result<Option<Instruction<BitScalar>>> {
        Ok(self.instructions.pop())
    }
}

impl Parser<Instruction<Scalar>> for InsParser<Scalar> {
    fn new(reader: BufReader<File>) -> io::Result<Self> {
        let mut instructions: Vec<Instruction<Scalar>> = bincode::deserialize_from(reader).unwrap();
        instructions.reverse();
        Ok(InsParser { instructions })
    }

    fn next(&mut self) -> io::Result<Option<Instruction<Scalar>>> {
        Ok(self.instructions.pop())
    }
}