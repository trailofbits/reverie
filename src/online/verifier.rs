use crate::util::Writer;

use super::*;
use super::{Instruction, Proof, RingHasher, Run, View, ViewRNG, KEY_SIZE};

use crate::algebra::{Domain, RingElement, RingModule, Serializable, Sharing};
use crate::consts::{LABEL_RNG_BEAVER, LABEL_RNG_MASKS};
use crate::consts::{LABEL_RNG_OPEN_ONLINE, LABEL_SCOPE_ONLINE_TRANSCRIPT};
use crate::crypto::TreePRF;
use crate::pp::verifier::PreprocessingExecution;
use crate::pp::Preprocessing;
use crate::util::*;

use blake3::Hash;
use rayon::prelude::*;

impl<D: Domain, const N: usize, const NT: usize, const R: usize> Proof<D, N, NT, R> {
    pub fn verify(&self, program: &[Instruction<<D::Sharing as RingModule>::Scalar>]) -> bool {
        if self.runs.len() != R {
            return false;
        }

        // re-execute the online phase R times
        let mut execs: Vec<(Hash, usize)> = Vec::with_capacity(R);

        #[cfg(test)]
        let runs = self.runs.iter();

        #[cfg(not(test))]
        let runs = self.runs.par_iter();

        let runs = runs.map(|run| {
            // expand keys
            let keys: Box<[Option<[u8; KEY_SIZE]>; N]> = run.open.expand();

            // find the punctured position of the PRF (omitted player index)
            let omitted = keys.iter().position(|key| key.is_none()).unwrap_or(0);
            let keys: Box<[[u8; KEY_SIZE]; N]> = arr_map!(&keys, |v| v.unwrap_or([0u8; KEY_SIZE]));

            // create preprocessing instance (partial re-execution)
            let views: Box<[View; N]> = arr_map!(&keys, |key| View::new_keyed(key));
            let mut rngs: Box<[ViewRNG; N]> =
                arr_map!(&views, |view| { view.rng(LABEL_RNG_BEAVER) });
            let preprocessing: PreprocessingExecution<D, _, N> = PreprocessingExecution::new(
                &mut rngs,
                run.inputs.len(),
                omitted,
                &run.broadcast[..],
                &run.corrections[..],
                program,
            );

            // create transcript hasher
            let mut transcript = RingHasher::new();

            // execute program one instruction at a time
            execute::<D, RingHasher<D::Sharing>, _, N>(
                &mut transcript,
                run.inputs.clone(),
                preprocessing,
                program,
            );

            // return hash of broadcast messages
            (transcript.finalize(), omitted)
        });

        #[cfg(test)]
        execs.extend(runs);

        #[cfg(not(test))]
        runs.collect_into_vec(&mut execs);

        // extract which players to omit in every run (Fiat-Shamir)
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for exec in execs.iter() {
                scope.join(&exec.0);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        for exec in execs {
            if exec.1 != random_usize::<_, N>(&mut rng) {
                return false;
            }
        }

        // otherwise looks good
        true
    }
}
