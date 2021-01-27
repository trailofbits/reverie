use crate::algebra::{Domain, RingModule, RingElement, Samplable};
use crate::crypto::{KEY_SIZE, PRG, kdf};
use crate::consts::{CONTEXT_RNG_EDA, CONTEXT_RNG_EDA_2};

pub struct SharesGenerator<D: Domain, D2: Domain> {
    pub eda: ShareGenerator<D>,
    pub eda_2: ShareGenerator<D2>,
}

impl<D: Domain, D2: Domain> SharesGenerator<D, D2> {
    pub fn new(player_seeds: &[[u8; KEY_SIZE]]) -> Self {
        let eda_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_EDA, seed)))
            .collect();
        let eda_prgs2: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_EDA_2, seed)))
            .collect();

        Self {
            eda: ShareGenerator::new(eda_prgs),
            eda_2: ShareGenerator::new(eda_prgs2),
        }
    }
}

pub struct PartialSharesGenerator<D: Domain, D2: Domain> {
    pub eda: PartialShareGenerator<D>,
    pub eda_2: PartialShareGenerator<D2>,
}

impl<D: Domain, D2: Domain> PartialSharesGenerator<D, D2> {
    pub fn new(player_seeds: &[[u8; KEY_SIZE]], omit: usize) -> Self {
        let eda_prgs: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_EDA, seed)))
            .collect();
        let eda_prgs2: Vec<PRG> = player_seeds
            .iter()
            .map(|seed| PRG::new(kdf(CONTEXT_RNG_EDA_2, seed)))
            .collect();

        Self {
            eda: PartialShareGenerator::new(eda_prgs, omit),
            eda_2: PartialShareGenerator::new(eda_prgs2, omit),
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
        self.next == D::Batch::DIMENSION
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
        self.next == D::Batch::DIMENSION
    }

    pub fn empty(&mut self) {
        self.next = D::Batch::DIMENSION;
    }
}

pub fn convert_bit_domain<D: Domain, D2: Domain>(input: D::Batch) -> Result<D2::Batch, String> {
    debug_assert_eq!(D::Batch::DIMENSION, D2::Batch::DIMENSION);
    //TODO: Use random sharings of 1 and 0 (in all groups)
    let mut out = D2::Batch::ZERO;
    for i in 0..D::Batch::DIMENSION {
        if input.get(i) == D::Scalar::ONE {
            out.set(i, D2::Scalar::ONE);
        } else if input.get(i) == D::Scalar::ZERO {
            out.set(i, D2::Scalar::ZERO);
        } else {
            return Err("Only to convert 0 or 1".parse().unwrap())
        }
    }
    return Ok(out);
}

pub fn convert_bit<D: Domain, D2: Domain>(input: D::Scalar) -> D2::Scalar {
    if input == D::Scalar::ONE {
        return D2::Scalar::ONE;
    } else {
        return D2::Scalar::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::algebra::{RingElement, Samplable};
    use crate::algebra::gf2::{BitBatch, GF2P64, GF2P8};
    use crate::fieldswitching::util::convert_bit_domain;

    #[test]
    pub fn test_convert_domain() {
        // TODO: write tests when we have other fields
        let one = BitBatch::ONE;
        let zero = BitBatch::ZERO;
        let two = one + one; // = zero in binary
        let batch = BitBatch::gen(&mut thread_rng());

        assert_eq!(BitBatch::ONE, convert_bit_domain::<GF2P8, GF2P64>(one).unwrap());
        assert_eq!(BitBatch::ZERO, convert_bit_domain::<GF2P8, GF2P64>(zero).unwrap());
        assert_eq!(BitBatch::ZERO, convert_bit_domain::<GF2P8, GF2P64>(two).unwrap());
        assert!(convert_bit_domain::<GF2P8, GF2P64>(batch).is_ok());
    }
}
