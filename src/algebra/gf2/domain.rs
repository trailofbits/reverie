use super::*;

use core::arch::x86_64::*;

use crate::algebra::{Domain, BATCH_SIZE, PACKED, PLAYERS};

use std::convert::TryFrom;

#[derive(Copy, Clone, Debug)]
pub struct DomainGF2 {}

impl Mul<recon::ReconGF2> for share::ShareGF2 {
    type Output = Self;

    fn mul(self, recon: recon::ReconGF2) -> Self {
        share::ShareGF2 {
            pack: self.pack & recon.pack,
        }
    }
}

impl Add<recon::ReconGF2> for share::ShareGF2 {
    type Output = Self;

    #[inline(always)]
    fn add(self, recon: recon::ReconGF2) -> Self {
        let delta = recon.pack & 0x0101_0101_0101_0101;
        share::ShareGF2 {
            pack: self.pack ^ delta,
        }
    }
}

impl Sub<recon::ReconGF2> for share::ShareGF2 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, recon: recon::ReconGF2) -> Self {
        self + recon
    }
}

impl Domain for DomainGF2 {
    type Batch = batch::BatchGF2;
    type Recon = recon::ReconGF2;
    type Share = share::ShareGF2;
    type ConstType = bool;

    fn reconstruct(share: &Self::Share) -> Self::Recon {
        // reconstruct
        let t = share.pack;
        let t = t ^ (t >> 4);
        let t = t ^ (t >> 2);
        let t = t ^ (t >> 1);
        let t = t & 0x0101_0101_0101_0101;

        // fill byte
        let t = t | (t << 1);
        let t = t | (t << 2);
        let t = t | (t << 4);

        let r = Self::Recon { pack: t };
        debug_assert!(r.valid(), "recon = {:?}, share = 0x{:016x}", r, share.pack);
        r
    }

    // one share per player
    fn batches_to_shares(
        to: &mut [Self::Share; BATCH_SIZE],
        from: &[[Self::Batch; PLAYERS]; PACKED],
    ) {
        debug_assert_eq!(batch::BYTES * 8, BATCH_SIZE);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return unsafe { batches_to_shares_x86(to, from) };

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unimplemented!()
    }

    const ONE: Self::ConstType = true;
    const ZERO: Self::ConstType = false;
}

#[inline(always)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn batches_to_shares_x86(
    to: &mut [share::ShareGF2; BATCH_SIZE],
    from: &[[batch::BatchGF2; PLAYERS]; PACKED],
) {
    for i in 0..batch::BYTES {
        // convert next sub-slice into array point
        let arr: &mut [share::ShareGF2; 8] =
            <&mut [share::ShareGF2; 8]>::try_from(&mut to[i * 8..(i + 1) * 8]).unwrap();

        // transpose the next byte from each batch
        byte_to_shares_x86(
            arr,
            [
                // 1st instance
                from[0][0].pack[i],
                from[0][1].pack[i],
                from[0][2].pack[i],
                from[0][3].pack[i],
                from[0][4].pack[i],
                from[0][5].pack[i],
                from[0][6].pack[i],
                from[0][7].pack[i],
                // 2nd instance
                from[1][0].pack[i],
                from[1][1].pack[i],
                from[1][2].pack[i],
                from[1][3].pack[i],
                from[1][4].pack[i],
                from[1][5].pack[i],
                from[1][6].pack[i],
                from[1][7].pack[i],
                // 3rd instance
                from[2][0].pack[i],
                from[2][1].pack[i],
                from[2][2].pack[i],
                from[2][3].pack[i],
                from[2][4].pack[i],
                from[2][5].pack[i],
                from[2][6].pack[i],
                from[2][7].pack[i],
                // 4th instance
                from[3][0].pack[i],
                from[3][1].pack[i],
                from[3][2].pack[i],
                from[3][3].pack[i],
                from[3][4].pack[i],
                from[3][5].pack[i],
                from[3][6].pack[i],
                from[3][7].pack[i],
                // 5th instance
                from[4][0].pack[i],
                from[4][1].pack[i],
                from[4][2].pack[i],
                from[4][3].pack[i],
                from[4][4].pack[i],
                from[4][5].pack[i],
                from[4][6].pack[i],
                from[4][7].pack[i],
                // 6th instance
                from[5][0].pack[i],
                from[5][1].pack[i],
                from[5][2].pack[i],
                from[5][3].pack[i],
                from[5][4].pack[i],
                from[5][5].pack[i],
                from[5][6].pack[i],
                from[5][7].pack[i],
                // 7th instance
                from[6][0].pack[i],
                from[6][1].pack[i],
                from[6][2].pack[i],
                from[6][3].pack[i],
                from[6][4].pack[i],
                from[6][5].pack[i],
                from[6][6].pack[i],
                from[6][7].pack[i],
                // 8th instance
                from[7][0].pack[i],
                from[7][1].pack[i],
                from[7][2].pack[i],
                from[7][3].pack[i],
                from[7][4].pack[i],
                from[7][5].pack[i],
                from[7][6].pack[i],
                from[7][7].pack[i],
            ],
        )
    }
}

#[inline(always)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn byte_to_shares_x86(dst: &mut [share::ShareGF2; 8], src: [u8; PACKED * PLAYERS]) {
    #[cfg(target_feature = "avx2")]
    return unsafe { byte_to_shares_avx2(dst, src) };

    #[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
    return unsafe { byte_to_shares_sse2(dst, src) };

    #[cfg(not(any(target_feature = "sse2", target_feature = "avx2")))]
    unimplemented!()
}

#[inline(always)]
#[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
unsafe fn byte_to_shares_sse2(dst: &mut [share::ShareGF2; 8], src: [u8; PACKED * PLAYERS]) {
    let mut short_a = _mm_set_epi8(
        src[0x00] as i8,
        src[0x01] as i8,
        src[0x02] as i8,
        src[0x03] as i8,
        src[0x04] as i8,
        src[0x05] as i8,
        src[0x06] as i8,
        src[0x07] as i8,
        src[0x08] as i8,
        src[0x09] as i8,
        src[0x0a] as i8,
        src[0x0b] as i8,
        src[0x0c] as i8,
        src[0x0d] as i8,
        src[0x0e] as i8,
        src[0x0f] as i8,
    );

    let mut short_b = _mm_set_epi8(
        src[0x10] as i8,
        src[0x11] as i8,
        src[0x12] as i8,
        src[0x13] as i8,
        src[0x14] as i8,
        src[0x15] as i8,
        src[0x16] as i8,
        src[0x17] as i8,
        src[0x18] as i8,
        src[0x19] as i8,
        src[0x1a] as i8,
        src[0x1b] as i8,
        src[0x1c] as i8,
        src[0x1d] as i8,
        src[0x1e] as i8,
        src[0x1f] as i8,
    );

    let mut short_c = _mm_set_epi8(
        src[0x20] as i8,
        src[0x21] as i8,
        src[0x22] as i8,
        src[0x23] as i8,
        src[0x24] as i8,
        src[0x25] as i8,
        src[0x26] as i8,
        src[0x27] as i8,
        src[0x28] as i8,
        src[0x29] as i8,
        src[0x2a] as i8,
        src[0x2b] as i8,
        src[0x2c] as i8,
        src[0x2d] as i8,
        src[0x2e] as i8,
        src[0x2f] as i8,
    );

    let mut short_d = _mm_set_epi8(
        src[0x30] as i8,
        src[0x31] as i8,
        src[0x32] as i8,
        src[0x33] as i8,
        src[0x34] as i8,
        src[0x35] as i8,
        src[0x36] as i8,
        src[0x37] as i8,
        src[0x38] as i8,
        src[0x39] as i8,
        src[0x3a] as i8,
        src[0x3b] as i8,
        src[0x3c] as i8,
        src[0x3d] as i8,
        src[0x3e] as i8,
        src[0x3f] as i8,
    );

    // extract shares
    for j in 0..8 {
        // cast to type of same size first to avoid sign-extending
        let val_a = (_mm_movemask_epi8(short_a) as u16) as u64;
        let val_b = (_mm_movemask_epi8(short_b) as u16) as u64;
        let val_c = (_mm_movemask_epi8(short_c) as u16) as u64;
        let val_d = (_mm_movemask_epi8(short_d) as u16) as u64;

        debug_assert!(val_a < (1 << 16));
        debug_assert!(val_b < (1 << 16));
        debug_assert!(val_c < (1 << 16));
        debug_assert!(val_d < (1 << 16));

        // shift
        short_a = _mm_add_epi8(short_a, short_a);
        short_b = _mm_add_epi8(short_b, short_b);
        short_c = _mm_add_epi8(short_c, short_c);
        short_d = _mm_add_epi8(short_d, short_d);

        // write 8 packed instances back
        dst[j].pack = (val_a << 48) | (val_b << 32) | (val_c << 16) | val_d;
    }
}

#[inline(always)]
#[cfg(target_feature = "avx2")]
unsafe fn byte_to_shares_avx2(dst: &mut [share::ShareGF2; 8], src: [u8; PACKED * PLAYERS]) {
    // pack first 4 instances
    let mut fst = _mm256_set_epi8(
        src[0x00] as i8,
        src[0x01] as i8,
        src[0x02] as i8,
        src[0x03] as i8,
        src[0x04] as i8,
        src[0x05] as i8,
        src[0x06] as i8,
        src[0x07] as i8,
        src[0x08] as i8,
        src[0x09] as i8,
        src[0x0a] as i8,
        src[0x0b] as i8,
        src[0x0c] as i8,
        src[0x0d] as i8,
        src[0x0e] as i8,
        src[0x0f] as i8,
        src[0x10] as i8,
        src[0x11] as i8,
        src[0x12] as i8,
        src[0x13] as i8,
        src[0x14] as i8,
        src[0x15] as i8,
        src[0x16] as i8,
        src[0x17] as i8,
        src[0x18] as i8,
        src[0x19] as i8,
        src[0x1a] as i8,
        src[0x1b] as i8,
        src[0x1c] as i8,
        src[0x1d] as i8,
        src[0x1e] as i8,
        src[0x1f] as i8,
    );

    // pack last 4 instances
    let mut snd = _mm256_set_epi8(
        src[0x20] as i8,
        src[0x21] as i8,
        src[0x22] as i8,
        src[0x23] as i8,
        src[0x24] as i8,
        src[0x25] as i8,
        src[0x26] as i8,
        src[0x27] as i8,
        src[0x28] as i8,
        src[0x29] as i8,
        src[0x2a] as i8,
        src[0x2b] as i8,
        src[0x2c] as i8,
        src[0x2d] as i8,
        src[0x2e] as i8,
        src[0x2f] as i8,
        src[0x30] as i8,
        src[0x31] as i8,
        src[0x32] as i8,
        src[0x33] as i8,
        src[0x34] as i8,
        src[0x35] as i8,
        src[0x36] as i8,
        src[0x37] as i8,
        src[0x38] as i8,
        src[0x39] as i8,
        src[0x3a] as i8,
        src[0x3b] as i8,
        src[0x3c] as i8,
        src[0x3d] as i8,
        src[0x3e] as i8,
        src[0x3f] as i8,
    );

    for j in 0..8 {
        // cast to type of same size first to avoid sign-extending
        let top = (_mm256_movemask_epi8(fst) as u32) as u64;
        let bot = (_mm256_movemask_epi8(snd) as u32) as u64;

        // shift
        fst = _mm256_add_epi8(fst, fst);
        snd = _mm256_add_epi8(snd, snd);

        // write 8 packed instances back
        dst[j].pack = (top << 32) | bot;
    }
}
