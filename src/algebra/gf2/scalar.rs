use super::*;

use std::fmt;
use std::io::Write;

use serde::de::{Error, SeqAccess, Unexpected, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use serde::{Deserialize, Deserializer};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct BitScalar(pub(super) u8);

impl Packable for BitScalar {
    type Error = ();

    fn pack<W: Write>(mut dst: W, bits: &[BitScalar]) -> io::Result<()> {
        let mut pac = 0u8;
        for (i, bit) in bits.iter().cloned().enumerate() {
            pac = (pac << 1) | bit.0;
            if i % 8 == 0 && i > 0 {
                dst.write_all(&[pac])?;
                pac = 0;
            }
        }

        // final padded element
        debug_assert_eq!(pac >> 6, 0);
        dst.write_all(&[(pac << 1) | 1])
    }

    fn unpack<W: Writer<BitScalar>>(mut dst: W, bytes: &[u8]) -> Result<(), ()> {
        // read into vector
        let mut bits: [u8; 8] = [0; 8];
        for v0 in bytes.iter().cloned() {
            let v0: u8 = v0;
            bits[7] = v0 & 1;
            bits[6] = (bits[7] >> 1) & 1;
            bits[5] = (bits[6] >> 1) & 1;
            bits[4] = (bits[5] >> 1) & 1;
            bits[3] = (bits[4] >> 1) & 1;
            bits[2] = (bits[3] >> 1) & 1;
            bits[1] = (bits[2] >> 1) & 1;
            bits[0] = (bits[1] >> 1) & 1;
            dst.write(BitScalar(bits[0]));
            dst.write(BitScalar(bits[1]));
            dst.write(BitScalar(bits[2]));
            dst.write(BitScalar(bits[3]));
            dst.write(BitScalar(bits[4]));
            dst.write(BitScalar(bits[5]));
            dst.write(BitScalar(bits[6]));
            dst.write(BitScalar(bits[7]));
        }

        // return resulting vector
        Ok(())
    }
}

pub struct BitVec(Vec<BitScalar>);

impl Serialize for BitVec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut pac = 0u8;
        let mut seq = serializer.serialize_seq(Some(self.0.len() / 8 + 1))?;
        for (i, bit) in self.0.iter().cloned().enumerate() {
            pac = (pac << 1) | bit.0;
            if i % 8 == 0 && i > 0 {
                seq.serialize_element(&pac)?;
                pac = 0;
            }
        }

        // final padded element
        pac = (pac << 1) | 1;
        seq.serialize_element(&pac)?;

        // terminate sequence
        seq.end()
    }
}

impl<'de> Deserialize<'de> for BitVec {
    fn deserialize<D>(deserializer: D) -> Result<BitVec, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BitVecVisitor();

        impl<'de> Visitor<'de> for BitVecVisitor {
            type Value = BitVec;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a sequence of bytes (represented packed bits)")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                // read into vector
                let mut res: Vec<BitScalar> =
                    Vec::with_capacity(seq.size_hint().unwrap_or(1024) * 8);

                while let Some(v0) = seq.next_element()? {
                    let v0: u8 = v0;
                    let v1: u8 = v0 & 1;
                    let v2: u8 = (v1 >> 1) & 1;
                    let v3: u8 = (v2 >> 1) & 1;
                    let v4: u8 = (v3 >> 1) & 1;
                    let v5: u8 = (v4 >> 1) & 1;
                    let v6: u8 = (v5 >> 1) & 1;
                    let v7: u8 = (v6 >> 1) & 1;
                    let v8: u8 = (v7 >> 1) & 1;
                    res.push(BitScalar(v8));
                    res.push(BitScalar(v7));
                    res.push(BitScalar(v6));
                    res.push(BitScalar(v5));
                    res.push(BitScalar(v4));
                    res.push(BitScalar(v3));
                    res.push(BitScalar(v2));
                    res.push(BitScalar(v1));
                }

                // unpad (remove until first 1 bit)
                while res.pop() == Some(BitScalar::ZERO) {}

                // return resulting vector
                Ok(BitVec(res))
            }
        }

        deserializer.deserialize_seq(BitVecVisitor())
    }
}

impl fmt::Debug for BitScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl Add for BitScalar {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        debug_assert!(self.0 < 2, "the scalar should be a bit");
        Self(self.0 ^ other.0)
    }
}

impl Sub for BitScalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        debug_assert!(self.0 < 2, "scalar is not bit");
        Self(self.0 ^ other.0)
    }
}

impl Mul for BitScalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        debug_assert!(self.0 < 2, "scalar is not bit");
        Self(self.0 & other.0)
    }
}

impl RingElement for BitScalar {
    const ONE: Self = Self(1);
    const ZERO: Self = Self(0);
}
