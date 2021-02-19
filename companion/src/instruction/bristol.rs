use std::fs::File;
use std::io::{self, prelude::*, BufReader};

use reverie::algebra::gf2::BitScalar;
use reverie::algebra::RingElement;
use reverie::Instruction;

use super::Parser;
use std::str::FromStr;

use thiserror::Error;

pub struct BristolHeader {
    pub n_gate: usize,
    pub n_wire: usize,
    pub n_input: usize,
    pub n_output: usize,
    pub pending_input: usize,
    pub pending_output: usize,
}

#[derive(Error, Debug)]
pub enum BristolHeaderError {
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    #[error("Integer Conversion Error")]
    ParseError(#[from] std::num::ParseIntError),
}

impl BristolHeader {
    fn add_input(&mut self) {
        self.pending_input -= 1;
        self.n_input += 1;
    }

    fn add_output(&mut self) {
        self.pending_output -= 1;
        self.n_output += 1;
    }
}

impl FromStr for BristolHeader {
    type Err = BristolHeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.trim().split('\n');
        let mut parts = lines.next().unwrap().split(' ');

        let n_gate: usize = parts.next().unwrap().trim().parse()?;
        let n_wire: usize = parts.next().unwrap().trim().parse()?;

        parts = lines.next().unwrap().split(' ');
        let mut n_input = 0;
        let n_input_wires = parts.next().unwrap().trim().parse()?;
        for i in 0..n_input_wires {
            let vec_size: usize = parts
                .next()
                .unwrap_or_else(|| {
                    panic!(
                        "Expected {} input vectors, only found {}",
                        n_input_wires,
                        i + 1
                    )
                })
                .trim()
                .parse()
                .unwrap();
            n_input += vec_size;
        }

        parts = lines.next().unwrap().split(' ');
        let mut n_output = 0;
        let n_output_wires = parts.next().unwrap().trim().parse()?;
        for i in 0..n_output_wires {
            let vec_size: usize = parts
                .next()
                .unwrap_or_else(|| {
                    panic!(
                        "Expected {} output vectors, only found {}",
                        n_output_wires,
                        i + 1
                    )
                })
                .trim()
                .parse()
                .unwrap();
            n_output += vec_size;
        }

        Ok(BristolHeader {
            n_gate,
            n_wire,
            n_input: 0,
            n_output: 0,
            pending_input: n_input,
            pending_output: n_output,
        })
    }
}

pub struct InsParser {
    line: String,
    reader: BufReader<File>,
    pub header: BristolHeader,
}

impl Parser<Instruction<BitScalar>> for InsParser {
    fn new(mut reader: BufReader<File>) -> io::Result<Self> {
        let mut header_raw = String::with_capacity(2048);
        reader.read_line(&mut header_raw)?;
        reader.read_line(&mut header_raw)?;
        reader.read_line(&mut header_raw)?;

        let header: BristolHeader = header_raw.parse().expect("Failed to parse header");

        Ok(InsParser {
            line: String::with_capacity(128),
            reader,
            header,
        })
    }

    fn next(&mut self) -> io::Result<Option<Instruction<BitScalar>>> {
        // Add input gates at the beginning of the circuit
        if self.header.pending_input > 0 {
            let idx = self.header.n_input;
            self.header.add_input();
            return Ok(Some(Instruction::Input(idx)));
        }

        self.line.clear();
        self.reader.read_line(&mut self.line)?;

        // Add output gates at the end of the circuit
        if self.line.is_empty() {
            if self.header.pending_output > 0 {
                let idx = self.header.n_output;
                let total_outputs = self.header.n_output + self.header.pending_output;
                self.header.add_output();
                return Ok(Some(Instruction::Output(
                    self.header.n_wire - total_outputs + idx,
                )));
            }
            return Ok(None);
        }

        // Add all the other gates in the middle
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
            "BUF" | "EQW" => {
                let src = ins[0].parse().unwrap();
                let dst = ins[1].parse().unwrap();
                Ok(Some(Instruction::AddConst(dst, src, BitScalar::ZERO)))
            }
            "EQ" => {
                let src = ins[0].parse().unwrap();
                let dst = ins[1].parse().unwrap();
                Ok(Some(Instruction::Const(
                    dst,
                    match src {
                        0 => BitScalar::ZERO,
                        1 => BitScalar::ONE,
                        _ => unimplemented!("Only 0 and 1 are valid constant values"),
                    },
                )))
            }
            _unk => unimplemented!("Parse error on token:: {}", _unk),
        }
    }
}
