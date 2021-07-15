use std::convert::{From, TryFrom};
use std::fmt;
use std::ops::{Add, Mul, Sub};

use num_traits::Zero;
use serde;

use crate::algebra::{EqIndex, Hashable, Pack, Recon};
use crate::crypto::hash::PackedHasher;
use crate::PACKED;

#[derive(Copy, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReconGF2 {
    pub(crate) pack: u64,
}

impl EqIndex for ReconGF2 {
    fn compare_index(rep1: usize, p1: usize, v1: &Self, rep2: usize, p2: usize, v2: &Self) -> bool {
        debug_assert!(v1.valid());
        debug_assert!(v2.valid());
        debug_assert_eq!(p1, 0);
        debug_assert_eq!(p2, 0);
        let s1 = 8 * (7 - rep1);
        let s2 = 8 * (7 - rep2);
        (v1.pack >> s1) & 0xff == (v2.pack >> s2) & 0xff
    }
}

impl From<&str> for ReconGF2 {
    fn from(bits: &str) -> Self {
        let mut pack = 0;
        for b in bits.chars() {
            match b {
                '1' => {
                    pack <<= 8;
                    pack |= 0xff;
                }
                '0' => {
                    pack <<= 8;
                }
                _ => (),
            }
        }
        Self { pack }
    }
}

// precompute lookup tables for deserializing
// TODO: in the future consider using intrinsics rather than lookup tables
const fn unpack_table() -> [[u8; 8]; 0x100] {
    const fn unpack_table_byte(byte_val: u64) -> [u8; 8] {
        const fn bit_to_mask(bit: u64) -> u8 {
            if bit == 0 {
                0x00
            } else {
                0xff
            }
        }
        [
            bit_to_mask((byte_val >> 7) & 1),
            bit_to_mask((byte_val >> 6) & 1),
            bit_to_mask((byte_val >> 5) & 1),
            bit_to_mask((byte_val >> 4) & 1),
            bit_to_mask((byte_val >> 3) & 1),
            bit_to_mask((byte_val >> 2) & 1),
            bit_to_mask((byte_val >> 1) & 1),
            bit_to_mask((byte_val >> 0) & 1),
        ]
    }
    const fn fill_table(mut t: [[u8; 8]; 0x100], byte_val: usize) -> [[u8; 8]; 0x100] {
        match byte_val {
            0x100 => t,
            _ => {
                t[byte_val] = unpack_table_byte(byte_val as u64);
                t[byte_val + 1] = unpack_table_byte((byte_val + 1) as u64);
                t[byte_val + 2] = unpack_table_byte((byte_val + 2) as u64);
                t[byte_val + 3] = unpack_table_byte((byte_val + 3) as u64);
                fill_table(t, byte_val + 4)
            }
        }
    }
    fill_table([[0; 8]; 0x100], 0x00)
}

// Table: u8 -> [u8; 8] with each byte containing a bit of the index (bit decomposition)
const UNPACK_TABLE: [[u8; 8]; 0x100] = unpack_table();

/// TODO: implement a custom Deserialize alongside this before we need to dump proofs
// impl serde::Serialize for ReconGF2 {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::ser::Serializer,
//     {
//         debug_assert!(self.valid());
//
//         // mask (first bit, second bit, ..., last bit)
//         let x: u64 = self.p<ack & 0x8040_2010_0804_0201;
//
//         // fold
//         let x = x ^ (x >> 32);
//         let x = x ^ (x >> 16);
//         let x = x ^ (x >> 8);
//         debug_assert_eq!(x & 0xff, x);
//
//         serializer.serialize_u8(x as u8)
//     }
// }

impl fmt::Debug for ReconGF2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        assert!(self.valid());
        let bits: [u8; PACKED] = (*self).into();
        for bit in bits.iter().copied() {
            if bit != 0 {
                f.write_str("1")?;
            } else {
                f.write_str("0")?;
            }
        }
        Ok(())
    }
}

impl Recon for ReconGF2 {}

#[inline(always)]
fn pack(shift: usize, src: &[ReconGF2; PACKED]) -> u8 {
    let shift = shift as u32;

    // handle first bit
    let mut res = (src[0].pack.wrapping_shr(shift) & 2) as u8;

    // handle sub-sequent bits
    res |= (src[1].pack.wrapping_shr(shift) & 1) as u8;
    res <<= 1;
    res |= (src[2].pack.wrapping_shr(shift) & 1) as u8;
    res <<= 1;
    res |= (src[3].pack.wrapping_shr(shift) & 1) as u8;
    res <<= 1;
    res |= (src[4].pack.wrapping_shr(shift) & 1) as u8;
    res <<= 1;
    res |= (src[5].pack.wrapping_shr(shift) & 1) as u8;
    res <<= 1;
    res |= (src[6].pack.wrapping_shr(shift) & 1) as u8;
    res <<= 1;
    res |= (src[7].pack.wrapping_shr(shift) & 1) as u8;
    res
}

#[inline(always)]
fn unpack(dst: &mut Vec<ReconGF2>, src: [u8; 8]) {
    let v0 = UNPACK_TABLE[src[0] as usize];
    let v1 = UNPACK_TABLE[src[1] as usize];
    let v2 = UNPACK_TABLE[src[2] as usize];
    let v3 = UNPACK_TABLE[src[3] as usize];
    let v4 = UNPACK_TABLE[src[4] as usize];
    let v5 = UNPACK_TABLE[src[5] as usize];
    let v6 = UNPACK_TABLE[src[6] as usize];
    let v7 = UNPACK_TABLE[src[7] as usize];
    for i in 0..8 {
        let pack = ReconGF2 {
            pack: u64::from_le_bytes([v7[i], v6[i], v5[i], v4[i], v3[i], v2[i], v1[i], v0[i]]),
        };
        debug_assert!(pack.valid());
        dst.push(pack);
    }
}

#[inline(always)]
fn pack_all(
    dst: &mut [Vec<u8>; PACKED],
    src: &[ReconGF2; PACKED],
    shifts: &[(usize, usize); PACKED],
) {
    // the zero index is always
    let (rep_0, s_0) = shifts[0];
    debug_assert!(rep_0 != PACKED);
    dst[rep_0].push(pack(s_0, src));

    // pack remaining indexes
    for i in 1..PACKED {
        let (rep_i, s_i) = shifts[i];
        if rep_i == PACKED {
            return;
        }
        dst[rep_i].push(pack(s_i, src));
    }
}

impl Pack for ReconGF2 {
    fn pack(dst: &mut [Vec<u8>; PACKED], src: &[Self], selected: &[bool; PACKED]) {
        // if there is nothing to extract return early (this occurs with good probability)
        if selected.iter().copied().all(|v| !v) {
            return;
        }

        // allocate destinations up-front to avoid later reallocations
        let cap = (src.len() + 7) / 8; // each element is 1-bit: cap = ceil(src.len() / 8)
        for i in 0..PACKED {
            if selected[i] {
                dst[i].reserve(cap);
            }
        }

        // compute shifts
        let shifts: [(usize, usize); PACKED] = {
            let mut nxt = 0;
            let mut shifts = [(PACKED, 0); PACKED];
            for i in 0..PACKED {
                if selected[i] {
                    shifts[nxt] = (i, 64 - (i + 1) * 8);
                    nxt += 1;
                }
            }
            shifts
        };

        // deal with multiples of 8
        let mut chunks_8 = src.chunks_exact(8);
        while let Some(chunk) = chunks_8.next() {
            let arr = <&[ReconGF2; PACKED]>::try_from(chunk).unwrap();
            pack_all(dst, arr, &shifts);
        }

        // deal with remainder
        let mut arr: [ReconGF2; 8] = [Default::default(); 8];
        for (i, elem) in chunks_8.remainder().iter().copied().enumerate() {
            arr[i] = elem;
        }
        pack_all(dst, &arr, &shifts);

        #[cfg(debug_assertions)]
        {
            for i in 0..PACKED {
                if !selected[i] {
                    debug_assert_eq!(dst[i].len(), 0);
                }
            }
        }
    }

    fn unpack(dst: &mut Vec<Self>, src: &[&[u8]; PACKED]) {
        let bytes = src[0].len();
        debug_assert_eq!(bytes, src[1].len());
        debug_assert_eq!(bytes, src[2].len());
        debug_assert_eq!(bytes, src[3].len());
        debug_assert_eq!(bytes, src[4].len());
        debug_assert_eq!(bytes, src[5].len());
        debug_assert_eq!(bytes, src[6].len());
        debug_assert_eq!(bytes, src[7].len());
        for i in 0..bytes {
            unpack(
                dst,
                [
                    src[0][i], src[1][i], src[2][i], src[3][i], //
                    src[4][i], src[5][i], src[6][i], src[7][i],
                ],
            )
        }
    }
}

impl ReconGF2 {
    // sanity check for debug mode
    pub(crate) fn valid(&self) -> bool {
        let mut valid: bool = true;
        let bits: [u8; PACKED] = self.pack.to_le_bytes();
        for i in 0..PACKED {
            valid &= bits[i] == 0xff || bits[i] == 0x00;
        }
        valid
    }
}

impl Default for ReconGF2 {
    fn default() -> Self {
        ReconGF2 { pack: 0 }
    }
}

impl From<bool> for ReconGF2 {
    #[inline(always)]
    fn from(bit: bool) -> Self {
        if bit {
            Self {
                pack: 0xffff_ffff_ffff_ffff,
            }
        } else {
            Self {
                pack: 0x0000_0000_0000_0000,
            }
        }
    }
}

impl Into<[u8; PACKED]> for ReconGF2 {
    #[inline(always)]
    fn into(self) -> [u8; PACKED] {
        (self.pack & 0x0101_0101_0101_0101).to_be_bytes()
    }
}

impl Into<bool> for ReconGF2 {
    #[inline(always)]
    fn into(self) -> bool {
        let bits: [u8; PACKED] = self.into();
        #[cfg(debug_assertions)]
        {
            // check that the same constant occurs across all repetitions.
            let val = bits[0];
            for i in 0..PACKED {
                debug_assert_eq!(val, bits[i]);
            }
        }
        bits[0] != 0
    }
}

impl Hashable for ReconGF2 {
    fn hash(&self, hashers: &mut PackedHasher) {
        let bs: [u8; PACKED] = self.pack.to_be_bytes();
        for i in 0..PACKED {
            hashers[i].update(&[bs[i]]);
        }
    }
}

impl Zero for ReconGF2 {
    fn zero() -> Self {
        ReconGF2 { pack: 0 }
    }

    fn is_zero(&self) -> bool {
        self.pack == 0
    }
}

impl Mul for ReconGF2 {
    type Output = Self;

    fn mul(self, recon: Self) -> Self {
        debug_assert!(self.valid());
        Self {
            pack: self.pack & recon.pack,
        }
    }
}

impl Add for ReconGF2 {
    type Output = Self;

    fn add(self, recon: Self) -> Self {
        debug_assert!(self.valid());
        Self {
            pack: self.pack ^ recon.pack,
        }
    }
}

impl Sub for ReconGF2 {
    type Output = Self;

    fn sub(self, recon: Self) -> Self {
        debug_assert!(self.valid());
        self + recon
    }
}
