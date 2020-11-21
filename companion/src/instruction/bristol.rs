use std::fs::File;
use std::io::{self, prelude::*, BufReader};

use reverie::algebra::gf2::BitScalar;
use reverie::algebra::RingElement;
use reverie::Instruction;

use super::Parser;

pub struct InsParser {
    line: String,
    reader: BufReader<File>,
}

impl Parser<Instruction<BitScalar>> for InsParser {
    fn new(mut reader: BufReader<File>) -> io::Result<Self> {
        let mut line = String::with_capacity(128);
        reader.read_line(&mut line)?;
        reader.read_line(&mut line)?;
        line.clear();
        Ok(InsParser { line, reader })
    }

    fn next(&mut self) -> io::Result<Option<Instruction<BitScalar>>> {
        self.line.clear();
        self.reader.read_line(&mut self.line)?;
        if self.line.len() == 0 {
            return Ok(None);
        }
        let mut parts = self.line.split(' ');
        parts.next().unwrap();
        parts.next().unwrap();
        let ins: Vec<&str> = parts.collect();

        let op = ins[ins.len() - 1];
        match &op[..op.len() - 1] {
            "XOR" => {
                let src_1 = ins[0].parse().unwrap();
                let src_2 = ins[1].parse().unwrap();
                let dst = ins[2].parse().unwrap();
                Ok(Some(Instruction::Add(dst, src_1, src_2)))
            }
            "AND" => {
                let src_1 = ins[0].parse().unwrap();
                let src_2 = ins[1].parse().unwrap();
                let dst = ins[2].parse().unwrap();
                Ok(Some(Instruction::Mul(dst, src_1, src_2)))
            }
            "INV" => {
                let src = ins[0].parse().unwrap();
                let dst = ins[1].parse().unwrap();
                Ok(Some(Instruction::AddConst(dst, src, BitScalar::ONE)))
            }
            "INPUT" => {
                let dst = ins[0].parse().unwrap();
                Ok(Some(Instruction::Input(dst)))
            }
            "OUTPUT" => {
                let src = ins[0].parse().unwrap();
                Ok(Some(Instruction::Output(src)))
            }
            "BRANCH" => {
                let dst = ins[0].parse().unwrap();
                Ok(Some(Instruction::Branch(dst)))
            }
            "BUF" => {
                let src = ins[0].parse().unwrap();
                let dst = ins[1].parse().unwrap();
                Ok(Some(Instruction::AddConst(dst, src, BitScalar::ZERO)))
            }
            _unk => unimplemented!("Parse error on token:: {}", _unk),
        }
    }
}
