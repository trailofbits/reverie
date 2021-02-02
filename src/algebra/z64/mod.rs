use super::*;

mod batch;
mod scalar;

//mod share64;
mod share8;

//mod domain64;
mod domain8;

pub use batch::Batch;
pub use scalar::Scalar;

//pub use share64::Sharing64;
pub use share8::Sharing8;

//pub use domain64::Z64P64;
pub use domain8::Z64P8;

pub const Z0: Scalar = <Scalar as RingElement>::ZERO;
pub const Z1: Scalar = <Scalar as RingElement>::ONE;
