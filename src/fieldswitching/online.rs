use crate::algebra::Domain;
use std::marker::PhantomData;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain, D2: Domain> {
    _ph: PhantomData<D>,
    _ph2: PhantomData<D2>,
}