mod batch;
mod share;

use crate::algebra::{Batch, Domain};
use crate::crypto::prg::{Key, PRG};
use crate::{BATCH_SIZE, PACKED, PLAYERS};

use std::marker::PhantomData;
use std::mem::MaybeUninit;

pub use batch::BatchGen;
pub use share::ShareGen;
