use super::*;
use super::{Instruction, RingHasher, Run, View, ViewRNG, KEY_SIZE};

use crate::algebra::{Domain, RingModule, Serializable, Sharing};
use crate::consts::{
    LABEL_RNG_OPEN_ONLINE, LABEL_RNG_PREPROCESSING, LABEL_SCOPE_CORRECTION,
    LABEL_SCOPE_ONLINE_TRANSCRIPT,
};
use crate::crypto::TreePRF;
use crate::preprocessing::prover::PreprocessingExecution;
use crate::preprocessing::{Preprocessing, PreprocessingOutput};
use crate::util::*;

use std::marker::PhantomData;

use blake3::Hash;
use rayon::prelude::*;

impl<T: Serializable + Copy> Writer<T> for Vec<T> {
    fn write(&mut self, message: &T) {
        self.push(*message);
    }
}

struct StreamingProver<
    D: Domain,
    PI: Iterator<Item = Instruction<D::Scalar>> + Clone,
    WI: Iterator<Item = D::Scalar> + Clone,
    const R: usize,
    const N: usize,
    const NT: usize,
> {
    preprocessing: PreprocessingOutput<D, R, N>,
    omitted: [usize; R],
    program: PI,
    inputs: WI,
}

struct SwitchWriter<T, W: Writer<T>> {
    writer: W,
    enabled: bool,
    _ph: PhantomData<T>,
}

impl<T, W: Writer<T>> SwitchWriter<T, W> {
    fn new(writer: W, enabled: bool) -> Self {
        Self {
            writer,
            enabled,
            _ph: PhantomData,
        }
    }
}

impl<T, W: Writer<T>> Writer<T> for SwitchWriter<T, W> {
    fn write(&mut self, elem: &T) {
        if self.enabled {
            self.writer.write(elem)
        }
    }
}

struct BatchExtractor<D: Domain, W: Writer<D::Batch>, const N: usize> {
    idx: usize,
    shares: Vec<D::Sharing>,
    writer: W,
}

impl<D: Domain, W: Writer<D::Batch>, const N: usize> BatchExtractor<D, W, N> {
    fn new(idx: usize, writer: W) -> Self {
        debug_assert!(idx < N);
        BatchExtractor {
            idx,
            shares: Vec::with_capacity(D::Batch::DIMENSION),
            writer,
        }
    }
}

impl<D: Domain, W: Writer<D::Batch>, const N: usize> Writer<D::Sharing>
    for BatchExtractor<D, W, N>
{
    fn write(&mut self, elem: &D::Sharing) {
        self.shares.push(*elem);
        if self.shares.len() == D::Batch::DIMENSION {
            let mut batches = [D::Batch::ZERO; N];
            D::convert_inv(&mut batches[..], &self.shares[..]);
            self.writer.write(&batches[self.idx]);
            self.shares.clear();
        }
    }
}

impl<D: Domain, W: Writer<D::Batch>, const N: usize> Drop for BatchExtractor<D, W, N> {
    fn drop(&mut self) {
        if self.shares.len() > 0 {
            let mut batches = [D::Batch::ZERO; N];
            D::convert_inv(&mut batches[..], &self.shares[..]);
            self.writer.write(&batches[self.idx]);
            self.shares.clear();
        }
    }
}

struct Prover<
    'a,
    D: Domain,
    WI: Iterator<Item = D::Scalar>,
    PI: Iterator<Item = Instruction<D::Scalar>>,
    BW: Writer<D::Sharing>, // broadcast writer
    WW: Writer<D::Scalar>,  // witness wire assignment
    P: Preprocessing<D>,
    const N: usize,
> {
    wires: VecMap<D::Scalar>,
    broadcast: &'a mut BW,
    masked: &'a mut WW,
    witness: WI,
    program: PI,
    preprocessing: P,
}

impl<
        'a,
        D: Domain,
        WI: Iterator<Item = D::Scalar>, // witness iterator
        PI: Iterator<Item = Instruction<D::Scalar>>, // program iterator
        BW: Writer<D::Sharing>,         // broadcast writer
        WW: Writer<D::Scalar>,          // masked witness wire
        P: Preprocessing<D>,
        const N: usize,
    > Prover<'a, D, WI, PI, BW, WW, P, N>
{
    fn new(
        broadcast: &'a mut BW,
        masked: &'a mut WW,
        witness: WI,
        program: PI,
        preprocessing: P,
    ) -> Self {
        Prover {
            witness,
            masked,
            broadcast,
            wires: VecMap::new(),
            program,
            preprocessing,
        }
    }

    fn run(&mut self) {
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
                            let mask: D::Sharing = masks.next().unwrap();
                            let wire =
                                self.witness.next().unwrap() + D::Sharing::reconstruct(&mask);
                            self.wires.set(dst, wire);
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
                            let recon = a_m.action(b_w) + b_m.action(a_w) + ab_gamma;

                            // reconstruct
                            self.broadcast.write(&recon);

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
                            let mask: D::Sharing = masks.next().unwrap();

                            // reconstruct
                            self.broadcast.write(&mask);

                            // output (TODO: save)
                            let output = self.wires.get(src) + mask.reconstruct();

                            // check if call into pre-processing needed
                            if masks.len() == 0 {
                                break;
                            }
                        }
                        None => {
                            // done
                            return;
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
        WI: Iterator<Item = D::Scalar> + Clone,
        const R: usize,
        const N: usize,
        const NT: usize,
    > StreamingProver<D, PI, WI, R, N, NT>
{
    /// Creates a new proof of program execution on the input provided.
    ///
    /// It is crucial for zero-knowledge that the pre-processing output is not reused!
    /// To help ensure this Proof::new takes ownership of PreprocessedProverOutput,
    /// which prevents the programmer from accidentally re-using the output
    pub fn new(preprocessing: PreprocessingOutput<D, R, N>, program: PI, inputs: WI) -> Self {
        let seeds: &[[u8; KEY_SIZE]; R] = &preprocessing.seeds;

        // execute the online phase R times
        let mut execs: Vec<_> = Vec::with_capacity(R);

        // do sequential execution in test builds (to ease debugging)
        #[cfg(debug_assertions)]
        let runs = seeds.iter();

        #[cfg(not(debug_assertions))]
        let runs = seeds.par_iter();

        let runs = runs.map(|seed| {
            // expand seed into RNG keys for players
            let tree: TreePRF<NT> = TreePRF::new(*seed);
            let keys: Array<_, N> = tree.expand().map(|x: &Option<[u8; KEY_SIZE]>| x.unwrap());

            // create fresh view for every player
            let mut views = keys.map(|key| View::new_keyed(key));
            let mut rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));

            // prepare pre-processing execution (online mode), save the corrections.
            let mut corrections = views[0].scope(LABEL_SCOPE_CORRECTION);
            let preprocessing: PreprocessingExecution<D, _, _, ViewRNG, N, true> =
                PreprocessingExecution::new(&mut *rngs, &mut corrections, program.clone());

            // compute public transcript
            let mut transcript: RingHasher<D::Sharing> = RingHasher::new();
            Prover::<_, _, _, _, _, _, N>::new(
                &mut transcript,        // feed the broadcast channel to CRH
                &mut VoidWriter::new(), // discard the masked witness
                inputs.clone(),
                program.clone(),
                preprocessing,
            )
            .run();

            // return the transcript hash
            transcript.finalize()
        });

        #[cfg(debug_assertions)]
        execs.extend(runs);

        #[cfg(not(debug_assertions))]
        runs.collect_into_vec(&mut execs);

        // extract which players to omit in every run (Fiat-Shamir)
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for hash in execs.iter() {
                scope.join(&hash);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        let mut omitted: [usize; R] = [0; R];
        for i in 0..R {
            omitted[i] = random_usize::<_, N>(&mut rng);
        }

        // return prover ready to stream out the proof
        StreamingProver {
            omitted,
            preprocessing,
            inputs,
            program,
        }
    }

    fn stream<
        WC: Writer<D::Batch>,  // corrections writer
        WB: Writer<D::Batch>,  // broadcast message writer
        WW: Writer<D::Scalar>, // masked witness writer
    >(
        mut self,
        writers: Vec<(WC, WB, WW)>,
    ) {
        // do sequential execution in test builds (to ease debugging)
        let runs: Vec<((_, [u8; KEY_SIZE]), usize)> = writers
            .into_iter()
            .zip(self.preprocessing.seeds.iter().cloned())
            .zip(self.omitted.iter().cloned())
            .collect();

        #[cfg(debug_assertions)]
        let runs = runs.into_iter();

        #[cfg(not(debug_assertions))]
        let runs = runs.into_par_iter();

        let runs = runs.map(|(((corrections, broadcast, mut masked), seed), omit)| {
            // expand seed into RNG keys for players
            let tree: TreePRF<NT> = TreePRF::new(seed);
            let keys: Array<_, N> = tree.expand().map(|x: &Option<[u8; KEY_SIZE]>| x.unwrap());

            // create fresh view for every player
            let mut views = keys.map(|key| View::new_keyed(key));
            let mut rngs = views.map(|view| view.rng(LABEL_RNG_PREPROCESSING));

            // prepare pre-processing execution (online mode), save the corrections.
            let mut corrections = SwitchWriter::new(corrections, omit != 0);
            let preprocessing: PreprocessingExecution<D, _, _, ViewRNG, N, true> =
                PreprocessingExecution::new(&mut *rngs, &mut corrections, self.program.clone());

            // compute public transcript
            let mut transcript: BatchExtractor<D, _, N> = BatchExtractor::new(omit, broadcast);
            Prover::<_, _, _, _, _, _, N>::new(
                &mut transcript,
                &mut masked,
                &mut self.inputs.clone(),
                self.program.clone(),
                preprocessing,
            )
            .run();
        });
    }
}
