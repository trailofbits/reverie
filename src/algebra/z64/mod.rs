use std::ops::{Add, Mul, Sub};

pub use batch::BatchZ64 as Batch;
pub use domain::DomainZ64 as Domain;
pub use recon::ReconZ64 as Recon;
pub use share::ShareZ64 as Share;

use super::*; // {Batch, Deserialize, Domain, Recon, Serialize, Share, BATCH_SIZE, PACKED, PLAYERS};

mod batch;

mod recon;

mod share;

mod domain;

pub const BIT_SIZE: usize = 64;
