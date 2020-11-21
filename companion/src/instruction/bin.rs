use super::Parser;

use std::fs::File;
use std::io::{self, prelude::*, BufReader, ErrorKind};

use reverie::algebra::gf2::BitScalar;
use reverie::algebra::RingElement;
use reverie::Instruction;

/// Simple relatively compact binary format

const CODE_ADD: u8 = 0;
const CODE_MUL: u8 = 1;
const CODE_INPUT: u8 = 2;
const CODE_BRANCH: u8 = 3;
const CODE_ADD_CONST: u8 = 4;
const CODE_MUL_CONST: u8 = 5;
const CODE_OUTPUT: u8 = 6;
const CODE_LOCAL: u8 = 7;

pub struct InsParser {
    reader: BufReader<File>,
}

fn read_index(reader: &mut BufReader<File>) -> io::Result<usize> {
    let mut bytes: [u8; 4] = [0u8; 4];
    reader.read_exact(&mut bytes[..])?;
    Ok(u32::from_le_bytes(bytes) as usize)
}

impl Parser<Instruction<BitScalar>> for InsParser {
    fn new(reader: BufReader<File>) -> io::Result<Self> {
        Ok(InsParser { reader })
    }

    fn next(&mut self) -> io::Result<Option<Instruction<BitScalar>>> {
        // read instruction type
        let mut op: [u8; 1] = [0; 1];
        match self.reader.read_exact(&mut op[..]) {
            Ok(()) => (),
            Err(e) => {
                if e.kind() == ErrorKind::UnexpectedEof {
                    // no more instructions
                    return Ok(None);
                } else {
                    return Err(e);
                }
            }
        };

        match op[0] {
            CODE_ADD => {
                let dst = read_index(&mut self.reader)?;
                let src_1 = read_index(&mut self.reader)?;
                let src_2 = read_index(&mut self.reader)?;
                Ok(Some(Instruction::Add(dst, src_1, src_2)))
            }
            CODE_ADD_CONST => {
                let dst = read_index(&mut self.reader)?;
                let src = read_index(&mut self.reader)?;
                Ok(Some(Instruction::AddConst(dst, src, BitScalar::ONE)))
            }
            CODE_MUL => {
                let dst = read_index(&mut self.reader)?;
                let src_1 = read_index(&mut self.reader)?;
                let src_2 = read_index(&mut self.reader)?;
                Ok(Some(Instruction::Mul(dst, src_1, src_2)))
            }
            CODE_MUL_CONST => {
                let dst = read_index(&mut self.reader)?;
                let src = read_index(&mut self.reader)?;
                Ok(Some(Instruction::MulConst(dst, src, BitScalar::ZERO)))
            }
            CODE_INPUT => {
                let dst = read_index(&mut self.reader)?;
                Ok(Some(Instruction::Input(dst)))
            }
            CODE_BRANCH => {
                let dst = read_index(&mut self.reader)?;
                Ok(Some(Instruction::Input(dst)))
            }
            CODE_OUTPUT => {
                let src = read_index(&mut self.reader)?;
                Ok(Some(Instruction::Output(src)))
            }
            CODE_LOCAL => {
                let dst = read_index(&mut self.reader)?;
                let src = read_index(&mut self.reader)?;
                Ok(Some(Instruction::LocalOp(dst, src)))
            }
            _ => unimplemented!("unknown operation: {:?}", op[0]),
        }
    }
}
