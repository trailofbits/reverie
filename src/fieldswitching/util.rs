use crate::algebra::{Domain, RingModule, RingElement};

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
