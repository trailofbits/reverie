use super::{
    Domain, LocalOperation, Packable, RingElement, RingModule, Samplable, Serializable, Sharing,
};

mod batch;
mod scalar;

mod domain64;
mod share64;

pub use domain64::GF2P64_64;
