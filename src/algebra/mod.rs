use std::convert::{AsMut, AsRef};
use std::fmt::Debug;
use std::io;
use std::ops::{Add, Mul, Sub};

use mcircuit::WireValue;
use num_traits::identities::Zero;
use rand::RngCore;

use crate::crypto::hash;
use crate::crypto::prg::{Key, PRG};
use crate::generator::ShareGen;
use crate::{BATCH_SIZE, PACKED, PLAYERS};

#[allow(clippy::suspicious_arithmetic_impl)] // Clippy thinks GF2 arithmetic is suspicious
pub mod gf2;
pub mod z64;

pub trait Serialize {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
}

pub trait Deserialize {
    fn deserialize<R: io::Read>(&mut self, reader: &mut R) -> io::Result<()>;
}

impl<T: AsRef<[u8]>> Serialize for T {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(self.as_ref())
    }
}

impl<T: AsMut<[u8]>> Deserialize for T {
    fn deserialize<R: io::Read>(&mut self, reader: &mut R) -> io::Result<()> {
        reader.read_exact(self.as_mut())
    }
}

pub trait Hashable {
    fn hash(&self, hashers: &mut hash::PackedHasher);
}

pub trait Recon:
    Sized
    + Pack
    + Zero
    + Add<Output = Self>
    + Mul<Output = Self>
    + Sub<Output = Self>
    + Copy
    + Debug
    + Clone
    + Hashable
    + Default
    + PartialEq
    + Eq
    + EqIndex
{
}

pub trait Batch: Sized + Add + Zero + Default {
    fn random(&mut self, prg: &mut PRG);
}

pub trait Pack: Sized {
    fn pack(
        dst: &mut [Vec<u8>; PACKED], // serialized elements for each repetition
        src: &[Self],                // slice of packed elements
        selected: &[bool; PACKED],   // should the repetition be extracted?
    );

    #[allow(clippy::ptr_arg)]
    fn unpack(
        dst: &mut Vec<Self>,   // packed elements
        src: &[&[u8]; PACKED], // slice of bytes for each repetition
    );
}

pub trait PackSelected: Sized {
    /// Extract and save (to dst) the shares of the selected players from the sharings.
    /// E.g. given a 2 packed sharing between 4 players: `abcd|1234`
    /// Between players:
    ///
    /// - P_a
    /// - P_b
    /// - P_c
    /// - P_d
    ///
    /// - P_1
    /// - P_2
    /// - P_3
    /// - P_4
    ///
    /// And `selected = [1, 3]`, the destination vector will contain:
    ///
    /// - `dst[0] = [b, ...]`
    /// - `dst[1] = [1, ...]`
    ///
    /// # Arguments
    ///
    /// - `dst`: Individually serialized share for each player (one vector of results per instance).
    /// - `src`: The input sharings.
    /// - `selected`: The players whose shares should be extracted.
    ///               If `selected[i] >= PLAYERS` no share are extracted.
    ///
    fn pack_selected(dst: &mut [Vec<u8>; PACKED], src: &[Self], selected: [usize; PACKED]);

    #[allow(clippy::ptr_arg)]
    fn unpack_selected(dst: &mut Vec<Self>, src: &[&[u8]; PACKED], selected: [usize; PACKED]);
}

pub trait Share:
    Sized
    + PackSelected
    + Debug
    + Zero
    + Add<Output = Self>
    + Sub<Output = Self>
    + Default
    + Copy
    + Clone
    + Hashable
    + EqIndex
{
}

// Used in unit tests to compare individual coordinates.
pub trait EqIndex {
    fn compare_index(
        _rep1: usize,
        _p1: usize,
        _v1: &Self, // first index
        _rep2: usize,
        _p2: usize,
        _v2: &Self, // second index
    ) -> bool {
        true
    }
}

pub trait Domain: Copy + Clone + Debug {
    // per-player batch
    type Batch: Batch;

    // packed reconstruction
    type Recon: Recon;

    // packed shares of players
    type Share: Share
        + Mul<Self::Recon, Output = Self::Share>
        + Add<Self::Recon, Output = Self::Share>;

    //
    fn reconstruct(share: &Self::Share) -> Self::Recon;

    // one share per player
    fn batches_to_shares(
        to: &mut [Self::Share; BATCH_SIZE],
        from: &[[Self::Batch; PLAYERS]; PACKED],
    );

    /// Used in tests only
    ///
    /// Generates random shares
    fn random_shares<R: RngCore>(rng: &mut R, num: usize) -> Vec<Self::Share> {
        // create share generator with randomness from rng
        let mut keys: [[Key; PLAYERS]; PACKED] = [[Default::default(); PLAYERS]; PACKED];
        for packed_keys in keys.iter_mut().take(PACKED) {
            for player_key in packed_keys.iter_mut().take(PLAYERS) {
                rng.fill_bytes(player_key);
            }
        }
        let mut share_gen: ShareGen<Self> = ShareGen::new(&keys, [PLAYERS; PACKED]);

        // generate requested shares one-by-one
        let mut shares: Vec<Self::Share> = Vec::with_capacity(num);
        for _ in 0..num {
            shares.push(share_gen.next());
        }
        shares
    }

    /// Used in tests only
    ///
    /// Generates random reconstructions
    fn random_recon<R: RngCore>(rng: &mut R, num: usize) -> Vec<Self::Recon> {
        let shares = Self::random_shares(rng, num);
        shares.iter().map(|s| Self::reconstruct(s)).collect()
    }

    // Type of constant parameter to ADDC/MULC gates
    type ConstType: Into<Self::Recon> + Copy + Debug + PartialEq + WireValue;

    // multiplicative identity
    const ONE: Self::ConstType;

    // additive identity
    const ZERO: Self::ConstType;
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use rand::rngs::OsRng;
    use rand::Rng;

    use super::*;

    fn test_recon_pack<D: Domain>() {
        let tests = vec![
            // (reps, selected, recons)
            (2, 1),
        ];

        for (num_reps, num_recons) in tests.into_iter() {
            // select random indexes to extract
            let mut selected = vec![false; PACKED * num_reps];
            let mut rem = PACKED;
            while rem > 0 {
                let i = OsRng.gen::<usize>() % selected.len();
                if !selected[i] {
                    rem -= 1;
                    selected[i] = true;
                }
            }

            // generate random reconstructions
            let recon: Vec<Vec<D::Recon>> = (0..num_reps)
                .map(|_| D::random_recon(&mut OsRng, num_recons))
                .collect();

            // pack the reconstructions into individual coordinates
            let mut packed: Vec<Vec<u8>> = (0..PACKED * num_reps).map(|_| vec![]).collect();
            for i in 0..num_reps {
                let range = i * PACKED..(i + 1) * PACKED;
                D::Recon::pack(
                    <&mut [Vec<u8>; PACKED]>::try_from(&mut packed[range.clone()]).unwrap(),
                    &recon[i][..],
                    <&[bool; PACKED]>::try_from(&selected[range]).unwrap(),
                );
            }

            // collect back into a packed reconstructions
            let mut recovered: Vec<D::Recon> = vec![];
            let mut streams: Vec<&[u8]> = vec![];

            for (i, sel) in selected.iter().copied().enumerate() {
                if sel {
                    streams.push(&packed[i][..]);
                }
            }

            assert_eq!(streams.len(), PACKED);
            D::Recon::unpack(
                &mut recovered,
                <&[&[u8]; PACKED]>::try_from(&streams[..]).unwrap(),
            );

            assert!(recovered.len() >= num_recons);

            // check that the recovered reconstructions are the same as the original in the packed indexes
            for i in 0..num_recons {
                let mut nxt = 0;
                for (j, sel) in selected.iter().copied().enumerate() {
                    if sel {
                        let v1 = &recovered[i];
                        let v2 = &recon[j / PACKED][i];
                        let rep1 = nxt;
                        let rep2 = j % PACKED;
                        assert!(
                            D::Recon::compare_index(
                                nxt,
                                0,
                                &recovered[i], //
                                j % PACKED,
                                0,
                                &recon[j / PACKED][i],
                            ),
                            "recovered[_] = {:?}, recon[_] = {:?}, rep1 = {}, rep2 = {}",
                            v1,
                            v2,
                            rep1,
                            rep2
                        );
                        nxt += 1;
                    }
                }
            }

            /*
            let mut recon_unpacked: Vec<D::Recon> = vec![];
            D::Recon::unpack(
                &mut recon_unpacked,
                &[
                    &dst[0], &dst[1], &dst[2], &dst[3], &dst[4], &dst[5], &dst[6], &dst[7],
                ],
            );
            */
        }

        let selected: [bool; PACKED] = [true; PACKED];

        for num in vec![1, 2, 3, 6, 18, 32, 64, 63, 65, 128, 127] {
            let shares = D::random_shares(&mut OsRng, num);
            let recon: Vec<D::Recon> = shares.iter().map(|s| D::reconstruct(s)).collect();
            let mut dst = [
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
            ];
            D::Recon::pack(&mut dst, &recon[..], &selected);
            let mut recon_unpacked: Vec<D::Recon> = vec![];
            D::Recon::unpack(
                &mut recon_unpacked,
                &[
                    &dst[0], &dst[1], &dst[2], &dst[3], &dst[4], &dst[5], &dst[6], &dst[7],
                ],
            );

            for i in 0..recon.len() {
                assert_eq!(recon_unpacked[i], recon[i]);
            }
        }
    }

    fn test_share_partial_pack<D: Domain>() {
        for num in vec![1, 2, 3, 6, 18, 32, 64, 63, 65, 128, 127] {
            let shares = D::random_shares(&mut OsRng, num);

            let selected: [usize; PACKED] = [
                OsRng.gen::<usize>() % PLAYERS,
                OsRng.gen::<usize>() % PLAYERS,
                OsRng.gen::<usize>() % PLAYERS,
                OsRng.gen::<usize>() % PLAYERS,
                OsRng.gen::<usize>() % PLAYERS,
                OsRng.gen::<usize>() % PLAYERS,
                OsRng.gen::<usize>() % PLAYERS,
                OsRng.gen::<usize>() % PLAYERS,
            ];

            let mut shares_packed = [
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
            ];

            D::Share::pack_selected(&mut shares_packed, &shares[..], selected);

            let mut shares_partial: Vec<D::Share> = vec![];

            D::Share::unpack_selected(
                &mut shares_partial,
                &[
                    &shares_packed[0],
                    &shares_packed[1],
                    &shares_packed[2],
                    &shares_packed[3],
                    &shares_packed[4],
                    &shares_packed[5],
                    &shares_packed[6],
                    &shares_packed[7],
                ],
                selected,
            );

            assert!(shares_partial.len() >= shares.len());

            println!("{:?}", shares_packed);

            for j in 0..shares.len() {
                for rep in 0..PACKED {
                    let p = selected[rep];
                    assert!(
                        D::Share::compare_index(rep, p, &shares_partial[j], rep, p, &shares[j]),
                        "{:?}",
                        selected
                    );
                }
            }
        }

        // test packing
    }

    fn test_domain<D: Domain>() {
        test_recon_pack::<D>();
        test_share_partial_pack::<D>();
    }

    #[test]
    fn test_gf2() {
        test_domain::<gf2::Domain>();
    }

    #[test]
    fn test_z64() {
        test_domain::<z64::Domain>();
    }
}
