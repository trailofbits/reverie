use std::fs::File;
use std::io::{self, prelude::*, BufReader};

use reverie::algebra::gf2::BitScalar;
use reverie::algebra::RingElement;

use super::Parser;

pub struct WitParser {
    reader: BufReader<File>,
}

impl Parser<BitScalar> for WitParser {
    fn new(reader: BufReader<File>) -> io::Result<Self> {
        Ok(WitParser { reader })
    }

    fn next(&mut self) -> io::Result<Option<BitScalar>> {
        loop {
            let mut buf: [u8; 1] = [0];
            let n = self.reader.read(&mut buf)?;
            if n == 0 {
                return Ok(None);
            }
            match buf[0] as char {
                '0' => {
                    return Ok(Some(BitScalar::ZERO));
                }
                '1' => {
                    return Ok(Some(BitScalar::ONE));
                }
                _ => (),
            }
        }
    }
}
