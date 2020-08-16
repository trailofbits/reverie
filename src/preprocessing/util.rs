use crate::algebra::{Domain, RingElement, RingModule, Samplable};
use crate::consts::{CONTEXT_RNG_BEAVER, CONTEXT_RNG_BRANCH_MASK, CONTEXT_RNG_INPUT_MASK};
use crate::crypto::*;

pub struct SharesGenerator<D: Domain> {
    pub input: ShareGenerator<D>,
    pub branch: ShareGenerator<D>,
    pub beaver: ShareGenerator<D>,
}

impl<D: Domain> SharesGenerator<D> {
    pub fn new(player_seeds: &[[u8; KEY_SIZE]]) -> Self {
        let input_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_INPUT_MASK, seed)))
            .collect();

        let branch_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_BRANCH_MASK, seed)))
            .collect();

        let beaver_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_BEAVER, seed)))
            .collect();

        Self {
            input: ShareGenerator::new(input_prgs),
            branch: ShareGenerator::new(branch_prgs),
            beaver: ShareGenerator::new(beaver_prgs),
        }
    }
}

pub struct PartialSharesGenerator<D: Domain> {
    pub input: PartialShareGenerator<D>,
    pub branch: PartialShareGenerator<D>,
    pub beaver: PartialShareGenerator<D>,
}

impl<D: Domain> PartialSharesGenerator<D> {
    pub fn new(player_seeds: &[[u8; KEY_SIZE]], omit: usize) -> Self {
        let input_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_INPUT_MASK, seed)))
            .collect();

        let branch_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_BRANCH_MASK, seed)))
            .collect();

        let beaver_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_BEAVER, seed)))
            .collect();

        Self {
            input: PartialShareGenerator::new(input_prgs, omit),
            branch: PartialShareGenerator::new(branch_prgs, omit),
            beaver: PartialShareGenerator::new(beaver_prgs, omit),
        }
    }
}

pub struct ShareGenerator<D: Domain> {
    batches: Vec<D::Batch>,
    shares: Vec<D::Sharing>,
    next: usize,
    prgs: Vec<PRG>,
}

impl<D: Domain> ShareGenerator<D> {
    pub fn new(prgs: Vec<PRG>) -> Self {
        debug_assert_eq!(prgs.len(), D::PLAYERS);
        ShareGenerator {
            batches: vec![D::Batch::ZERO; D::PLAYERS],
            shares: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            next: D::Batch::DIMENSION,
            prgs,
        }
    }

    pub fn next(&mut self) -> D::Sharing {
        if self.next >= D::Batch::DIMENSION {
            debug_assert_eq!(self.next, self.shares.len());
            for i in 0..D::PLAYERS {
                self.batches[i] = D::Batch::gen(&mut self.prgs[i]);
            }
            D::convert(&mut self.shares[..], &self.batches);
            self.next = 0;
        }
        let elem = self.shares[self.next];
        self.next += 1;
        elem
    }

    pub fn batches(&self) -> &[D::Batch] {
        &self.batches[..]
    }

    pub fn is_empty(&self) -> bool {
        return self.next == D::Batch::DIMENSION;
    }

    pub fn empty(&mut self) {
        self.next = D::Batch::DIMENSION;
    }
}

pub struct PartialShareGenerator<D: Domain> {
    batches: Vec<D::Batch>,
    shares: Vec<D::Sharing>,
    omit: usize,
    next: usize,
    prgs: Vec<PRG>,
}

impl<D: Domain> PartialShareGenerator<D> {
    pub fn new(prgs: Vec<PRG>, omit: usize) -> Self {
        debug_assert_eq!(prgs.len(), D::PLAYERS);
        PartialShareGenerator {
            batches: vec![D::Batch::ZERO; D::PLAYERS],
            shares: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
            next: D::Batch::DIMENSION,
            prgs,
            omit,
        }
    }

    pub fn next(&mut self) -> D::Sharing {
        if self.next >= self.shares.len() {
            for i in 0..D::PLAYERS {
                if i != self.omit {
                    self.batches[i] = D::Batch::gen(&mut self.prgs[i]);
                }
            }
            debug_assert_eq!(self.batches[self.omit], D::Batch::ZERO);
            D::convert(&mut self.shares[..], &self.batches);
            self.next = 0;
        }
        let elem = self.shares[self.next];
        self.next += 1;
        elem
    }

    pub fn batches(&self) -> &[D::Batch] {
        &self.batches[..]
    }

    pub fn is_empty(&self) -> bool {
        return self.next == D::Batch::DIMENSION;
    }

    pub fn empty(&mut self) {
        self.next = D::Batch::DIMENSION;
    }
}
