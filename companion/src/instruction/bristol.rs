use std::fs::File;
use std::io::{self, prelude::*, BufReader};

use reverie::algebra::gf2::BitScalar;
use reverie::algebra::RingElement;
use reverie::Instruction;

use super::Parser;

pub struct InsParser {
    line: String,
    reader: BufReader<File>,
    pub n_gate: usize,
    pub n_wire: usize,
    pub n_input: usize,
    pub n_output: usize,
    pending_input: usize,
}

fn parse_header(l1: String, l2: String, l3: String) -> (usize, usize, usize, usize) {
    let mut parts = l1.split(' ');
    let n_gate: usize = parts.next().unwrap().trim().parse().unwrap();
    let n_wire: usize = parts.next().unwrap().trim().parse().unwrap();

    parts = l2.split(' ');
    let mut n_input = 0;
    let n_input_wires = parts.next().unwrap().trim().parse().unwrap();
    for i in 0..n_input_wires {
        let vec_size: usize = parts
            .next()
            .expect(
                format!(
                    "Expected {} input vectors, only found {}",
                    n_input_wires,
                    i + 1
                )
                .as_str(),
            )
            .trim()
            .parse()
            .unwrap();
        n_input += vec_size;
    }

    parts = l3.split(' ');
    let mut n_output = 0;
    let n_output_wires = parts.next().trim().unwrap().parse().unwrap();
    for i in 0..n_output_wires {
        let vec_size: usize = parts
            .next()
            .expect(
                format!(
                    "Expected {} output vectors, only found {}",
                    n_output_wires,
                    i + 1
                )
                .as_str(),
            )
            .trim()
            .parse()
            .unwrap();
        n_output += vec_size;
    }

    (n_gate, n_wire, n_input, n_output)
}

fn check_dst(dst: usize) -> usize {
    match dst {
        0 => panic!("Input 0 is reserved for the Zero constant value."),
        1 => panic!("Input 1 is reserved for the One constant value."),
        any => any,
    }
}

impl Parser<Instruction<BitScalar>> for InsParser {
    fn new(mut reader: BufReader<File>) -> io::Result<Self> {
        let mut l1 = String::with_capacity(128);
        reader.read_line(&mut l1)?;

        let mut l2 = String::with_capacity(512);
        reader.read_line(&mut l2)?;

        let mut l3 = String::with_capacity(512);
        reader.read_line(&mut l3)?;

        let (n_gate, n_wire, n_input, n_output) = parse_header(l1, l2, l3);
        Ok(InsParser {
            line: String::with_capacity(128),
            reader,
            n_gate,
            n_wire,
            n_input: 0,
            n_output,
            pending_input: n_input + 2,
        })
    }

    fn next(&mut self) -> io::Result<Option<Instruction<BitScalar>>> {
        if self.pending_input > 0 {
            let idx = self.n_input;
            self.n_input += 1;
            self.pending_input -= 1;
            return Ok(Some(Instruction::Input(idx)));
        }

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
                let dst = check_dst(ins[2].parse().unwrap());
                Ok(Some(Instruction::Add(dst, src_1, src_2)))
            }
            "AND" => {
                let src_1 = ins[0].parse().unwrap();
                let src_2 = ins[1].parse().unwrap();
                let dst = check_dst(ins[2].parse().unwrap());
                Ok(Some(Instruction::Mul(dst, src_1, src_2)))
            }
            "INV" => {
                let src = ins[0].parse().unwrap();
                let dst = check_dst(ins[1].parse().unwrap());
                Ok(Some(Instruction::AddConst(dst, src, BitScalar::ONE)))
            }
            "INPUT" => {
                let dst = check_dst(ins[0].parse().unwrap());
                Ok(Some(Instruction::Input(dst)))
            }
            "OUTPUT" => {
                let src = ins[0].parse().unwrap();
                Ok(Some(Instruction::Output(src)))
            }
            "BRANCH" => {
                let dst = check_dst(ins[0].parse().unwrap());
                Ok(Some(Instruction::Branch(dst)))
            }
            "BUF" => {
                let src = ins[0].parse().unwrap();
                let dst = check_dst(ins[1].parse().unwrap());
                Ok(Some(Instruction::AddConst(dst, src, BitScalar::ZERO)))
            }
            _unk => unimplemented!("Parse error on token:: {}", _unk),
        }
    }
}
