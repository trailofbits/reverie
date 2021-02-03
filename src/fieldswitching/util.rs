use crate::algebra::{Domain, RingElement, RingModule};
use crate::consts::{CONTEXT_RNG_EDA, CONTEXT_RNG_EDA_2};
use crate::crypto::{kdf, KEY_SIZE, PRG};
use crate::preprocessing::util::{ShareGenerator, PartialShareGenerator};

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
            return Err("Only to convert 0 or 1".parse().unwrap());
        }
    }
    Ok(out)
}

pub fn convert_bit<D: Domain, D2: Domain>(input: D::Scalar) -> D2::Scalar {
    if input == D::Scalar::ONE {
        D2::Scalar::ONE
    } else {
        D2::Scalar::ZERO
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::algebra::gf2::{BitBatch, GF2P64, GF2P8};
    use crate::algebra::{RingElement, Samplable};
    use crate::fieldswitching::util::convert_bit_domain;

    #[test]
    pub fn test_convert_domain() {
        // TODO: write tests when we have other fields
        let one = BitBatch::ONE;
        let zero = BitBatch::ZERO;
        let two = one + one; // = zero in binary
        let batch = BitBatch::gen(&mut thread_rng());

        assert_eq!(
            BitBatch::ONE,
            convert_bit_domain::<GF2P8, GF2P64>(one).unwrap()
        );
        assert_eq!(
            BitBatch::ZERO,
            convert_bit_domain::<GF2P8, GF2P64>(zero).unwrap()
        );
        assert_eq!(
            BitBatch::ZERO,
            convert_bit_domain::<GF2P8, GF2P64>(two).unwrap()
        );
        assert!(convert_bit_domain::<GF2P8, GF2P64>(batch).is_ok());
    }
}
