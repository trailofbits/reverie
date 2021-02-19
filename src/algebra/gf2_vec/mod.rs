use super::{
    Domain, LocalOperation, Packable, RingElement, RingModule, Samplable, Serializable, Sharing,
};

mod batch;
mod scalar;

mod domain64;
mod share64;

pub use domain64::Gf2P64_64;
pub use scalar::Scalar;
