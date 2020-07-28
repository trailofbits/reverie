use super::*;

use core::arch::x86_64::*;

mod batch;
mod scalar;

mod share64;
mod share8;

mod domain64;
mod domain8;

pub use batch::BitBatch;
pub use scalar::BitScalar;

pub use share64::BitSharing64;
pub use share8::BitSharing8;

pub use domain64::GF2P64;
pub use domain8::GF2P8;

use batch::BATCH_SIZE_BYTES;

pub const BIT0: BitScalar = <BitScalar as RingElement>::ZERO;
pub const BIT1: BitScalar = <BitScalar as RingElement>::ONE;