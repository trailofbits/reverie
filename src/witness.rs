use std::fs::File;
use std::io::{self, prelude::*, BufReader};

use reverie::algebra::gf2;

use super::Parser;

pub struct WitParser {
    reader: BufReader<File>,
}

impl Parser<bool> for WitParser {
    fn new(reader: BufReader<File>) -> io::Result<Self> {
        Ok(WitParser { reader })
    }

    fn next(&mut self) -> io::Result<Option<bool>> {
        loop {
            let mut buf: [u8; 1] = [0];
            let n = self.reader.read(&mut buf)?;
            if n == 0 {
                return Ok(None);
            }
            match buf[0] as char {
                '0' => {
                    return Ok(Some(false));
                }
                '1' => {
                    return Ok(Some(true));
                }
                _ => (),
            }
        }
    }
}

impl Parser<gf2::Recon> for WitParser {
    fn new(reader: BufReader<File>) -> io::Result<Self> {
        Ok(WitParser { reader })
    }

    fn next(&mut self) -> io::Result<Option<gf2::Recon>> {
        loop {
            let mut buf: [u8; 1] = [0];
            let n = self.reader.read(&mut buf)?;
            if n == 0 {
                return Ok(None);
            }
            match buf[0] as char {
                '0' => {
                    return Ok(Some(false.into()));
                }
                '1' => {
                    return Ok(Some(true.into()));
                }
                _ => (),
            }
        }
    }
}
