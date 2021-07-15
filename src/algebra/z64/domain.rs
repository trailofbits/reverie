use super::*;

use crate::algebra::{Domain, BATCH_SIZE, PACKED, PLAYERS};

impl Mul<recon::ReconZ64> for share::ShareZ64 {
    type Output = Self;

    fn mul(self, recon: recon::ReconZ64) -> Self {
        let mut prod = share::ShareZ64::zero();
        for i in 0..PACKED {
            for j in 0..PLAYERS {
                prod.pack[i][j] = self.pack[i][j].wrapping_mul(recon.pack[i]);
            }
        }
        prod
    }
}

impl Add<recon::ReconZ64> for share::ShareZ64 {
    type Output = Self;

    #[inline(always)]
    fn add(self, recon: recon::ReconZ64) -> Self {
        let mut sum = self; // implicit copy
        for i in 0..PACKED {
            sum.pack[i][0] = self.pack[i][0].wrapping_add(recon.pack[i]);
        }
        sum
    }
}

impl Sub<recon::ReconZ64> for share::ShareZ64 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, recon: recon::ReconZ64) -> Self {
        let mut dif = self; // implicit copy
        for i in 0..PACKED {
            dif.pack[i][0] = self.pack[i][0].wrapping_sub(recon.pack[i]);
        }
        dif
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DomainZ64 {}

impl Domain for DomainZ64 {
    type Batch = batch::BatchZ64;
    type Recon = recon::ReconZ64;
    type Share = share::ShareZ64;
    type ConstType = u64;

    fn reconstruct(share: &Self::Share) -> Self::Recon {
        let mut recon = Self::Recon::zero();
        for i in 0..PACKED {
            for j in 0..PLAYERS {
                recon.pack[i] = recon.pack[i].wrapping_add(share.pack[i][j]);
            }
        }
        recon
    }

    // one share per player
    fn batches_to_shares(
        to: &mut [Self::Share; BATCH_SIZE],
        from: &[[Self::Batch; PLAYERS]; PACKED],
    ) {
        debug_assert_eq!(batch::NSHARES, BATCH_SIZE);
        {
            #[allow(clippy::needless_range_loop)]
            for i in 0..batch::NSHARES {
                let mut pack: [[u64; PLAYERS]; PACKED] = [[0; PLAYERS]; PACKED];
                for j in 0..PACKED {
                    for k in 0..PLAYERS {
                        pack[j][k] = from[j][k].pack[i];
                    }
                }

                // write packed instances back
                to[i].pack = pack;
            }
        }
    }

    const ONE: Self::ConstType = 1;
    const ZERO: Self::ConstType = 0;
}
