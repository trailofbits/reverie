use crate::util::Writer;

use super::*;

use crate::algebra::{Domain, RingElement, RingModule, Sharing};
use crate::consts::{
    LABEL_RNG_OPEN_ONLINE, LABEL_RNG_PREPROCESSING, LABEL_SCOPE_CORRECTION,
    LABEL_SCOPE_ONLINE_TRANSCRIPT,
};
use crate::pp::verifier::PreprocessingExecution;
use crate::util::*;

use blake3::Hash;
use rayon::prelude::*;

struct OutputShares<'a, D: Domain, const N: usize> {
    next: usize,
    used: usize,
    omitted: usize,
    batches: &'a [D::Batch],
    sharings: Vec<D::Sharing>,
}

/// This ensures that the user can only get access to the output
/// by validating the online execution against a correctly validated and matching pre-processing execution.
///
/// Avoiding potential misuse where the user fails to check the pre-processing.
pub struct Output<D: Domain, const R: usize> {
    output: Vec<<D::Sharing as RingModule>::Scalar>,
    pp_hashes: Box<[Hash; R]>,
}

impl<D: Domain, const R: usize> Output<D, R> {
    pub fn check(&self, pp_hashes: &[Hash; R]) -> Option<&[<D::Sharing as RingModule>::Scalar]> {
        for i in 0..R {
            if pp_hashes[i] != self.pp_hashes[i] {
                return None;
            }
        }
        Some(&self.output[..])
    }

    // provides access to the output without checking the pre-processing
    // ONLY USED IN TESTS
    #[cfg(test)]
    pub(super) fn unsafe_output(&self) -> &[<D::Sharing as RingModule>::Scalar] {
        &self.output[..]
    }
}

impl<'a, D: Domain, const N: usize> OutputShares<'a, D, N> {
    fn new(batches: &'a [D::Batch], omitted: usize) -> Self {
        OutputShares {
            next: 0,
            used: D::Batch::DIMENSION,
            omitted,
            batches,
            sharings: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
        }
    }

    fn next_output_share(&mut self) -> D::Sharing {
        match self.sharings.get(self.used) {
            Some(share) => {
                self.used += 1;
                *share
            }
            None => {
                let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];

                // copy batch from omitted player
                if self.next < self.batches.len() {
                    batches[self.omitted] = self.batches[self.next];
                }

                // transpose into new batch of sharings
                D::convert(&mut self.sharings[..], &mut batches[..]);
                self.used = 1;
                self.next = self.next + 1;
                self.sharings[0]
            }
        }
    }
}

fn execute_verify<D: Domain, P: Preprocessing<D>, const N: usize>(
    wires: Vec<<D::Sharing as RingModule>::Scalar>,
    mut output_shares: OutputShares<D, N>,
    mut preprocessing: P,
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
) -> (Vec<<D::Sharing as RingModule>::Scalar>, Hash) {
    let mut hasher: RingHasher<D::Sharing> = RingHasher::new();
    let mut output: Vec<<D::Sharing as RingModule>::Scalar> = Vec::new();
    let mut wires: VecMap<<D::Sharing as RingModule>::Scalar> = wires.into();
    for step in program {
        match *step {
            Instruction::AddConst(dst, src, c) => {
                wires.set(dst, wires.get(src) + c);
            }
            Instruction::MulConst(dst, src, c) => {
                wires.set(dst, wires.get(src) * c);
            }
            Instruction::Add(dst, src1, src2) => {
                let sw1 = wires.get(src1);
                let sw2 = wires.get(src2);
                wires.set(dst, sw1 + sw2);
            }
            Instruction::Mul(dst, src1, src2) => {
                // calculate reconstruction shares for every player
                let a_w = wires.get(src1);
                let b_w = wires.get(src2);
                let a_m: D::Sharing = preprocessing.mask(src1);
                let b_m: D::Sharing = preprocessing.mask(src2);
                let ab_gamma: D::Sharing = preprocessing.next_ab_gamma();
                let recon = a_m.action(b_w) + b_m.action(a_w) + ab_gamma;

                // reconstruct
                hasher.write(&recon);

                // corrected wire
                let c_w = recon.reconstruct() + a_w * b_w;

                // append messages from all players to transcript
                #[cfg(test)]
                #[cfg(debug_assertions)]
                {
                    let c_m = preprocessing.mask(dst);

                    println!("mult");
                    println!("  a_w = {:?}", a_w);
                    println!("  b_w = {:?}", b_w);
                    println!("  a_m = {:?} (partial)", a_m);
                    println!("  b_m = {:?} (partial)", b_m);
                    println!("  c_m = {:?} (partial)", c_m);
                    println!("  ab + \\gamma = {:?} (corrected)", ab_gamma);
                    println!("  recon = {:?}", recon);
                }

                // reconstruct and correct share
                wires.set(dst, c_w);
            }
            Instruction::Output(src) => {
                let hidden_share = output_shares.next_output_share();
                let mask = preprocessing.mask(src) + hidden_share;
                output.push(mask.reconstruct() + wires.get(src));
                hasher.write(&mask);
            }
        }
    }
    (output, hasher.finalize())
}

impl<D: Domain, const N: usize, const NT: usize, const R: usize> Proof<D, N, NT, R> {
    pub fn verify(
        &self,
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    ) -> Option<Output<D, R>> {
        if self.runs.len() != R {
            return None;
        }

        // re-execute the online phase R times
        let mut execs: Vec<(Vec<<D::Sharing as RingModule>::Scalar>, Hash, Hash, usize)> =
            Vec::with_capacity(R);

        // do sequential execution in test builds (to ease debugging)
        #[cfg(debug_assertions)]
        let runs = self.runs.iter();

        #[cfg(not(debug_assertions))]
        let runs = self.runs.par_iter();

        let runs = runs.map(|run| {
            // expand keys
            let keys: Box<[Option<[u8; KEY_SIZE]>; N]> = run.open.expand();

            // find the punctured position of the PRF (omitted player index)
            let omitted = keys.iter().position(|key| key.is_none()).unwrap_or(0);
            let keys: Box<[[u8; KEY_SIZE]; N]> = arr_map!(&keys, |v| v.unwrap_or([0u8; KEY_SIZE]));

            // create preprocessing instance (partial re-execution)
            let mut views: Box<[View; N]> = arr_map!(&keys, |key| View::new_keyed(key));
            let mut rngs: Box<[ViewRNG; N]> =
                arr_map!(&views, |view| { view.rng(LABEL_RNG_PREPROCESSING) });
            let preprocessing: PreprocessingExecution<D, _, N> = PreprocessingExecution::new(
                &mut rngs,
                run.inputs.len(),
                omitted,
                &run.multiplications[..],
                &run.corrections[..],
                program,
            );

            // execute program one instruction at a time
            let (output, broadcast_transcript) = execute_verify::<D, _, N>(
                run.inputs.clone(),
                OutputShares::new(&run.reconstructions, omitted),
                preprocessing,
                program,
            );

            // add corrections to player0 view
            {
                let mut scope = views[0].scope(LABEL_SCOPE_CORRECTION);
                for delta in run.corrections.iter() {
                    scope.write(delta)
                }
            }

            // compute hash of pre-processing view commitments
            let mut pp_hash = blake3::Hasher::new();
            for view in views.iter() {
                pp_hash.update(view.hash().as_bytes());
            }

            // return hash of broadcast messages
            (output, broadcast_transcript, pp_hash.finalize(), omitted)
        });

        #[cfg(debug_assertions)]
        execs.extend(runs);

        #[cfg(not(debug_assertions))]
        runs.collect_into_vec(&mut execs);

        // output produced by first repetitions (should be the same across all executions)
        let output = &(execs[0].0)[..];

        // extract which players to omit in every run (Fiat-Shamir)
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for exec in execs.iter() {
                scope.join(&exec.1);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);

        for exec in execs.iter() {
            // check that correct index was opened
            if exec.3 != random_usize::<_, N>(&mut rng) {
                return None;
            }

            // check output (usually a single bit)
            if &exec.0[..] != output {
                return None;
            }
        }

        // hashes to check against pre-processing proof
        let pp_hashes = arr_from_iter!(execs.iter().map(|exec| { exec.2 }));

        // otherwise return the output
        // (usually a field element, indicating whether the witness satisfies the relation computed)
        Some(Output {
            pp_hashes,
            output: execs.pop().unwrap().0,
        })
    }
}
