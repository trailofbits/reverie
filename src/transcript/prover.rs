use super::*;

use crate::algebra::{Hashable, Pack, PackSelected};
use crate::crypto::hash::PackedHasher;
use crate::generator::ShareGen;
use crate::proof::{OpenOnline, OpenPreprocessing};

use std::any::type_name;
use std::convert::TryFrom;
use std::mem;

use num_traits::Zero;

pub struct ProverTranscript<D: Domain, I: Iterator<Item = D::Recon>> {
    // original un-expanded seeds
    // (used to extract proof at the end)
    seeds: [[u8; KEY_SIZE]; PACKED],

    //
    witness: I,

    // used to generate fresh shares
    share_gen: Box<ShareGen<D>>,

    // transcript hashes
    hash_online: PackedHasher,
    hash_preprocess: PackedHasher,

    // recorded corrections/reconstructions/masked inputs
    reconstructions: Vec<D::Share>,
    corrections: Vec<D::Recon>,
    inputs: Vec<D::Recon>,
}

impl<D: Domain, I: Iterator<Item = D::Recon>> ProverTranscript<D, I> {
    pub fn new(
        witness: I,           // iterator over
        seeds: [Key; PACKED], // seeds for each packed repetition
    ) -> Self {
        Self {
            seeds,
            share_gen: share_gen_from_rep_seeds(&seeds),
            witness,
            hash_online: PackedHasher::new(),
            hash_preprocess: PackedHasher::new(),
            reconstructions: vec![],
            corrections: vec![],
            inputs: vec![],
        }
    }

    /// Extracts proofs from transcript
    ///
    /// # Arguments
    ///
    /// - 'players': The players to omit from the online execution.
    ///              If players[i] == PLAYERS, the preprocessing is opened instead.
    pub(crate) fn extract(
        self,                     // consumes the transcript
        players: [usize; PACKED], // the online players to omit.
    ) -> (Vec<OpenOnline>, Vec<OpenPreprocessing>) {
        let mut dst_recon: [Vec<u8>; PACKED] = [
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        ];

        let mut dst_corr: [Vec<u8>; PACKED] = [
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        ];

        let mut dst_input: [Vec<u8>; PACKED] = [
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        ];

        let selected: Vec<bool> = players.iter().copied().map(|i| i < PLAYERS).collect();

        // pack reconstruction shares of omitted player
        D::Share::pack_selected(&mut dst_recon, &self.reconstructions[..], players);

        // pack corrections
        D::Recon::pack(
            &mut dst_corr,
            &self.corrections[..],
            <&[bool; PACKED]>::try_from(&selected[..]).unwrap(),
        );

        // pack masked inputs
        D::Recon::pack(
            &mut dst_input,
            &self.inputs[..],
            <&[bool; PACKED]>::try_from(&selected[..]).unwrap(),
        );

        // open
        let mut open_preprocessing: Vec<OpenPreprocessing> = vec![];
        let mut open_online: Vec<OpenOnline> = vec![];
        for rep in 0..PACKED {
            let omit = players[rep];
            debug_assert!(omit <= PLAYERS);
            if omit < PLAYERS {
                // fetch the packed corrections
                let corrs = mem::take(&mut dst_corr[rep]);
                let recons = mem::take(&mut dst_recon[rep]);
                let inputs = mem::take(&mut dst_input[rep]);

                // remove seed of unopened player
                let mut seeds = expand_seed(self.seeds[rep]);
                seeds[omit] = [0u8; KEY_SIZE];

                // append to opening
                open_online.push(OpenOnline {
                    omit: omit as u8,
                    recons,
                    corrs,
                    inputs,
                    seeds,
                })
            } else {
                debug_assert_eq!(omit, PLAYERS);
                debug_assert_eq!(
                    dst_corr[rep].len(),
                    0,
                    "rep = {}, players = {:?}, {:?}",
                    rep,
                    &players,
                    &dst_corr
                );

                debug_assert_eq!(
                    dst_recon[rep].len(),
                    0,
                    "rep = {}, players = {:?}, domain = {}, {:?}",
                    rep,
                    &players,
                    type_name::<D>(),
                    &dst_recon
                );

                debug_assert_eq!(
                    dst_input[rep].len(),
                    0,
                    "rep = {}, players = {:?}, {:?}",
                    rep,
                    &players,
                    &dst_input
                );

                open_preprocessing.push(OpenPreprocessing {
                    comm_online: self.hash_online[rep].finalize().into(),
                    seed: self.seeds[rep],
                })
            }
        }

        (open_online, open_preprocessing)
    }
}

impl<D: Domain, I: Iterator<Item = D::Recon>> Transcript<D> for ProverTranscript<D, I> {
    const IS_PROVER: bool = true;

    fn input(&mut self) -> Wire<D> {
        // generate fresh share
        let mask = self.share_gen.next();

        // reconstruct mask
        let lambda = D::reconstruct(&mask);

        // fetch next input and compute "correction"
        // st. mask + corr = input, i.e. (mask || corr) is a sharing of input.
        let input = self.witness.next().expect("witness is too short");
        let corr = input - lambda;

        // commit to input
        corr.hash(&mut self.hash_online);

        // save masked input for proof extraction
        self.inputs.push(corr);
        Wire { mask, corr }
    }

    fn online_hash(&self) -> [Hash; PACKED] {
        self.hash_online.finalize()
    }

    fn preprocess_hash(&self) -> [Hash; PACKED] {
        self.hash_preprocess.finalize()
    }

    fn reconstruct(&mut self, mask: D::Share) -> D::Recon {
        mask.hash(&mut self.hash_online);
        self.reconstructions.push(mask);
        D::reconstruct(&mask)
    }

    fn correction(&mut self, corr: D::Recon) -> D::Recon {
        corr.hash(&mut self.hash_preprocess);
        self.corrections.push(corr);
        corr
    }

    fn zero_check(&mut self, recon: D::Recon) {
        // TODO: create a useful trace for the user
        assert!(
            recon.is_zero(),
            "witness is invalid!. Wire has value {:?}, expected zero.",
            recon
        );
    }

    fn new_mask(&mut self) -> D::Share {
        self.share_gen.next()
    }
}
