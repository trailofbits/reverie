use crate::util::Writer;

use super::*;

use crate::algebra::{Domain, RingElement, RingModule, Sharing};
use crate::consts::{
    LABEL_RNG_OPEN_ONLINE, LABEL_RNG_PREPROCESSING, LABEL_SCOPE_CORRECTION,
    LABEL_SCOPE_ONLINE_TRANSCRIPT,
};
use crate::preprocessing::verifier::PreprocessingExecution;
use crate::preprocessing::Preprocessing;
use crate::util::*;

use std::marker::PhantomData;

use blake3::Hash;
use rayon::prelude::*;

macro_rules! batch_to_sharing {
    ($dst:expr, $src:expr, $omit:expr ) => {
        let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
        batches[$omit] = $src;
        D::convert($dst, &batches[..]);
    };
}

pub struct StreamingVerifier<
    D: Domain,
    PI: Iterator<Item = Instruction<D::Scalar>> + Clone,
    const R: usize,
    const N: usize,
    const NT: usize,
> {
    runs: [Run<R, N, NT>; R],
    program: PI,
    _ph: PhantomData<D>,
}

struct ShareIterator<D: Domain, I: Iterator<Item = D::Batch>, const N: usize> {
    idx: usize,
    src: I,
    next: usize,
    shares: Vec<D::Sharing>,
}

struct ScalarIterator<D: Domain, I: Iterator<Item = D::Batch>, const N: usize> {
    src: I,
    next: usize,
    scalars: Vec<D::Scalar>,
}

impl<D: Domain, I: Iterator<Item = D::Batch>, const N: usize> ShareIterator<D, I, N> {
    fn new(idx: usize, src: I) -> Self {
        debug_assert!(idx < N);
        ShareIterator {
            idx,
            src,
            next: D::Batch::DIMENSION,
            shares: vec![D::Sharing::ZERO; D::Batch::DIMENSION],
        }
    }
}

impl<D: Domain, I: Iterator<Item = D::Batch>, const N: usize> Iterator for ShareIterator<D, I, N> {
    type Item = D::Sharing;

    fn next(&mut self) -> Option<Self::Item> {
        // convert the next batch
        if self.next == D::Batch::DIMENSION {
            self.next = 0;
            let mut batches: [D::Batch; N] = [D::Batch::ZERO; N];
            batches[self.idx] = self.src.next()?;
            D::convert(&mut self.shares[..], &batches[..]);
        }

        // return the next partial share
        let share = self.shares[self.next];
        self.next += 1;
        Some(share)
    }
}

/// This ensures that the user can only get access to the output
/// by validating the online execution against a correctly validated and matching pre-processing execution.
///
/// Avoiding potential misuse where the user fails to check the pre-processing.
pub struct Output<D: Domain, const R: usize> {
    output: Vec<D::Scalar>,
    pp_hashes: Array<Hash, R>,
}

impl<D: Domain, const R: usize> Output<D, R> {
    pub fn check(&self, pp_hashes: &[Hash; R]) -> Option<&[D::Scalar]> {
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
    pub(super) fn unsafe_output(&self) -> &[D::Scalar] {
        &self.output[..]
    }
}

struct Verifier<
    D: Domain,
    PI: Iterator<Item = Instruction<D::Scalar>>,
    BI: Iterator<Item = D::Sharing>,
    WI: Iterator<Item = D::Scalar>,
    P: Preprocessing<D>,
    const R: usize,
    const N: usize,
    const NT: usize,
> {
    wires: VecMap<D::Scalar>,
    masked: WI,
    program: PI,
    broadcast: BI,
    preprocessing: P,
}

impl<
        D: Domain,
        PI: Iterator<Item = Instruction<D::Scalar>>,
        BI: Iterator<Item = D::Sharing>,
        WI: Iterator<Item = D::Scalar>,
        P: Preprocessing<D>,
        const R: usize,
        const N: usize,
        const NT: usize,
    > Verifier<D, PI, BI, WI, P, R, N, NT>
{
    fn new() -> Self {
        Verifier {
            wires: VecMap::new(),
        }
    }

    fn run<TW: Writer<D::Sharing>>(&mut self, transcript: &mut TW) -> Option<()> {
        //
        let mut masks: Vec<D::Sharing> = Vec::with_capacity(1024);
        let mut ab_gamma: Vec<D::Sharing> = vec![D::Sharing::ZERO; D::Batch::DIMENSION];

        loop {
            // pre-process the next batch
            masks.clear();
            self.preprocessing
                .next_sharings(&mut masks, &mut ab_gamma[..]);

            // consume the preprocessing batch
            {
                let mut masks = masks.iter().cloned();
                let mut ab_gamma = ab_gamma.iter().cloned();

                // execute instructions from the program until the chunk size limit
                loop {
                    match self.program.next() {
                        Some(Instruction::Input(dst)) => {
                            self.wires.set(dst, self.masked.next()?);
                        }
                        Some(Instruction::AddConst(dst, src, c)) => {
                            let a_w = self.wires.get(src);
                            self.wires.set(dst, a_w + c);
                        }
                        Some(Instruction::MulConst(dst, src, c)) => {
                            let sw = self.wires.get(src);
                            self.wires.set(dst, sw * c);
                        }
                        Some(Instruction::Add(dst, src1, src2)) => {
                            let a_w = self.wires.get(src1);
                            let b_w = self.wires.get(src2);
                            self.wires.set(dst, a_w + b_w);
                        }
                        Some(Instruction::Mul(dst, src1, src2)) => {
                            // calculate reconstruction shares for every player
                            let a_w = self.wires.get(src1);
                            let b_w = self.wires.get(src2);
                            let a_m: D::Sharing = masks.next().unwrap();
                            let b_m: D::Sharing = masks.next().unwrap();
                            let ab_gamma: D::Sharing = ab_gamma.next().unwrap();

                            let recon = a_m.action(b_w)
                                + b_m.action(a_w)
                                + ab_gamma // partial a * b + \gamma
                                + self.broadcast.next()?; // share of omitted player

                            // reconstruct
                            transcript.write(recon);

                            // corrected wire
                            let c_w = recon.reconstruct() + a_w * b_w;

                            // reconstruct and correct share
                            self.wires.set(dst, c_w);

                            // check if call into pre-processing needed
                            if masks.len() == 0 {
                                break;
                            }
                        }
                        Some(Instruction::Output(src)) => {
                            let recon: D::Sharing =
                                masks.next().unwrap() + self.broadcast.next()?;

                            // reconstruct
                            transcript.write(recon);

                            // TODO: write the output to
                            let output = self.wires.get(src) + recon.reconstruct();

                            // check if call into pre-processing needed
                            if masks.len() == 0 {
                                break;
                            }
                        }
                        None => {
                            // end of program
                            return Some(());
                        }
                    }
                }
            }
        }
    }
}

impl<
        D: Domain,
        PI: Iterator<Item = Instruction<D::Scalar>> + Clone,
        const R: usize,
        const N: usize,
        const NT: usize,
    > StreamingVerifier<D, PI, R, N, NT>
{
    pub fn new(program: PI, runs: [Run<R, N, NT>; R]) -> Self {
        StreamingVerifier {
            program,
            runs,
            _ph: PhantomData,
        }
    }

    pub fn verify<
        CI: Iterator<Item = D::Batch>,
        BI: Iterator<Item = D::Batch>,
        WI: Iterator<Item = D::Scalar>,
    >(
        self,
        readers: Vec<(CI, BI, WI)>,
    ) -> Option<Output<D, R>> {
        if readers.len() != R {
            return None;
        }

        let runs: Vec<(_, _)> = readers.into_iter().zip(self.runs.iter()).collect();

        // do sequential execution in test builds (to ease debugging)
        #[cfg(debug_assertions)]
        let runs = runs.into_iter();

        // otherwise parallel iteration
        #[cfg(not(debug_assertions))]
        let runs = runs.into_par_iter();

        let runs = runs.map(|((corrections, broadcast, masked), run)| {
            // expand keys
            let keys: Array<_, N> = run.open.expand();

            // find the punctured position of the PRF (omitted player index)
            let omitted = keys.iter().position(|key| key.is_none()).unwrap_or(0);

            // replace omitted key(s) with dummy
            let keys = keys.map(|v| v.unwrap_or([0u8; KEY_SIZE]));

            // create pre-processing instance
            let mut views = keys.map(|key| View::new_keyed(key));
            let mut rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));
            let preprocessing: PreprocessingExecution<D, _, _, _, N> =
                PreprocessingExecution::new(&mut rngs, omitted, corrections, self.program.clone());

            //
            let broadcast: ShareIterator<D, _, N> = ShareIterator::new(omitted, broadcast);
            let mut verifier: Verifier<_, _, _, _, _, R, N, NT> =
                Verifier::new(masked, self.program.clone(), broadcast, preprocessing);

            let mut transcript: RingHasher<D::Sharing> = RingHasher::new();
            verifier.run(&mut transcript);

            (omitted, transcript.finalize())
        });

        // execute the online phase R times
        let mut execs: Vec<_> = Vec::with_capacity(R);

        #[cfg(debug_assertions)]
        execs.extend(runs);

        #[cfg(not(debug_assertions))]
        runs.collect_into_vec(&mut execs);

        // extract which players to omit in every run (Fiat-Shamir)
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for (_, hash) in execs.iter() {
                scope.join(&hash);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        for (omit, _) in execs.iter() {
            if *omit != random_usize::<_, N>(&mut rng) {
                return None;
            }
        }

        None
    }
}
