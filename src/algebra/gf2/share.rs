use std::fmt;
use std::ops::{Add, Sub};

use num_traits::Zero;

use crate::algebra::{EqIndex, Hashable, PackSelected, Share};
use crate::crypto::hash::PackedHasher;
use crate::{PACKED, PLAYERS};

use super::domain::byte_to_shares_x86;

use std::convert::TryFrom;

#[derive(Copy, Clone)]
pub struct ShareGF2 {
    pub(crate) pack: u64,
}

impl EqIndex for ShareGF2 {
    fn compare_index(rep1: usize, p1: usize, v1: &Self, rep2: usize, p2: usize, v2: &Self) -> bool {
        assert!(rep1 < PACKED);
        assert!(p1 < PLAYERS);
        assert!(rep2 < PACKED);
        assert!(p2 < PLAYERS);
        let idx1 = (PACKED - 1 - rep1) * PLAYERS + PLAYERS - 1 - p1;
        let idx2 = (PACKED - 1 - rep2) * PLAYERS + PLAYERS - 1 - p2;
        (v1.pack >> idx1) & 1 == (v2.pack >> idx2) & 1
    }
}

impl From<&str> for ShareGF2 {
    fn from(bits: &str) -> Self {
        let mut pack = 0;
        for b in bits.chars() {
            match b {
                '1' => {
                    pack <<= 1;
                    pack |= 1
                }
                '0' => {
                    pack <<= 8;
                }
                _ => (), // all other characters are ignored (used for spacing)
            }
        }
        Self { pack }
    }
}

impl fmt::Debug for ShareGF2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v: [u64; 8] = [0; 8];
        for (i, as_u64) in v.iter_mut().enumerate() {
            *as_u64 = (self.pack >> (8 * i)) & 0xff;
        }
        for i in 0..8 {
            f.write_fmt(format_args!(
                "[{:04b} {:04b}]",
                (v[7 - i] & 0xf0) >> 4, // upper nibble
                v[7 - i] & 0xf          // lower nibble
            ))?;
        }
        Ok(())
    }
}

#[inline(always)]
fn pack(shift: usize, src: &[ShareGF2; 8]) -> u8 {
    let mut res: u64 = 0;
    res |= (src[0].pack >> shift) & 1;
    res <<= 1;
    res |= (src[1].pack >> shift) & 1;
    res <<= 1;
    res |= (src[2].pack >> shift) & 1;
    res <<= 1;
    res |= (src[3].pack >> shift) & 1;
    res <<= 1;
    res |= (src[4].pack >> shift) & 1;
    res <<= 1;
    res |= (src[5].pack >> shift) & 1;
    res <<= 1;
    res |= (src[6].pack >> shift) & 1;
    res <<= 1;
    res |= (src[7].pack >> shift) & 1;
    debug_assert!(res < 0x100);
    res as u8
}

impl PackSelected for ShareGF2 {
    fn pack_selected(
        dst: &mut [Vec<u8>; PACKED], // serialized / packed bytes
        src: &[Self],                // source share
        selected: [usize; PACKED],   // player shares to extract
    ) {
        // convert to bit shifts
        let ext = {
            let mut ext: [(usize, usize); PACKED] = [(PLAYERS, 0); PACKED];
            let mut nxt = 0;
            for (idx, player) in selected.iter().copied().enumerate() {
                if player < PLAYERS {
                    ext[nxt] = (idx, (PACKED - 1 - idx) * PLAYERS + (PLAYERS - 1 - player));
                    nxt += 1;
                }
            }
            ext
        };

        // if there is nothing to pack return early
        if ext[0].0 == PLAYERS {
            return;
        }

        #[inline(always)]
        fn extract(
            dst: &mut [Vec<u8>; PACKED],
            arr: &[ShareGF2; 8],
            ext: &[(usize, usize); PACKED],
        ) {
            for take in ext {
                if take.0 == PLAYERS {
                    break;
                }
                dst[take.0].push(pack(take.1, arr))
            }
        }

        // deal with multiples of 8
        let mut chunks_8 = src.chunks_exact(8);
        for chunk in &mut chunks_8 {
            extract(dst, <&[ShareGF2; 8]>::try_from(chunk).unwrap(), &ext);
        }

        // deal with residue
        {
            let mut arr: [ShareGF2; 8] = [Default::default(); 8];
            for (i, elem) in chunks_8.remainder().iter().copied().enumerate() {
                arr[i] = elem;
            }
            extract(dst, &arr, &ext);
        }

        // basic sanity check
        #[cfg(debug_assertions)]
        {
            for i in 0..PACKED {
                if selected[i] >= PLAYERS {
                    debug_assert_eq!(dst[i].len(), 0);
                }
            }
        }
    }

    fn unpack_selected(
        dst: &mut Vec<ShareGF2>,   // list of sharings
        src: &[&[u8]; PACKED],     // shares for a single player per instance
        selected: [usize; PACKED], // player shares to extract
    ) {
        // check same number of batches per packed instance
        let length = src[0].len();
        assert_eq!(length, src[1].len());
        assert_eq!(length, src[2].len());
        assert_eq!(length, src[3].len());
        assert_eq!(length, src[4].len());
        assert_eq!(length, src[5].len());
        assert_eq!(length, src[6].len());
        assert_eq!(length, src[7].len());

        // all player indexes should be in range
        debug_assert!(selected[0] < PLAYERS);
        debug_assert!(selected[1] < PLAYERS);
        debug_assert!(selected[2] < PLAYERS);
        debug_assert!(selected[3] < PLAYERS);
        debug_assert!(selected[4] < PLAYERS);
        debug_assert!(selected[5] < PLAYERS);
        debug_assert!(selected[6] < PLAYERS);
        debug_assert!(selected[7] < PLAYERS);

        // reserve all required space up-front
        dst.reserve(length * 8);

        // translate indexes
        let idx: [usize; PACKED] = [
            selected[0],
            selected[1] + PLAYERS,
            selected[2] + 2 * PLAYERS,
            selected[3] + 3 * PLAYERS,
            selected[4] + 4 * PLAYERS,
            selected[5] + 5 * PLAYERS,
            selected[6] + 6 * PLAYERS,
            selected[7] + 7 * PLAYERS,
        ];

        let mut tmp_dst: [ShareGF2; 8] = [Default::default(); 8];
        let mut tmp_src: [u8; PACKED * PLAYERS] = [0u8; PACKED * PLAYERS];

        for i in 0..length {
            // copy provided shares (all others are zero)
            for (j, k) in idx.iter().copied().enumerate() {
                unsafe {
                    *tmp_src.get_unchecked_mut(k) = *src.get_unchecked(j).get_unchecked(i);
                }
            }

            // transpose
            byte_to_shares_x86(&mut tmp_dst, tmp_src);

            // copy partial shares to destination
            dst.extend_from_slice(&tmp_dst);
        }
    }
}

impl Default for ShareGF2 {
    fn default() -> Self {
        ShareGF2 { pack: 0 }
    }
}

impl Hashable for ShareGF2 {
    fn hash(&self, hashers: &mut PackedHasher) {
        let bs: [u8; PACKED] = self.pack.to_be_bytes();
        for i in 0..PACKED {
            hashers[i].push(bs[i]);
        }
    }
}

impl Add for ShareGF2 {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            pack: self.pack ^ other.pack,
        }
    }
}

impl Sub for ShareGF2 {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self {
            pack: self.pack ^ other.pack,
        }
    }
}

impl Zero for ShareGF2 {
    fn zero() -> Self {
        ShareGF2 { pack: 0 }
    }

    fn is_zero(&self) -> bool {
        self.pack == 0
    }
}

impl Share for ShareGF2 {}
