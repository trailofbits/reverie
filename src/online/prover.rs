use super::*;
use super::{Instruction, Proof, RingHasher, Run, View, ViewRNG, KEY_SIZE};

use crate::algebra::{Domain, RingModule, Serializable, Sharing};
use crate::consts::{
    LABEL_RNG_OPEN_ONLINE, LABEL_RNG_PREPROCESSING, LABEL_SCOPE_CORRECTION,
    LABEL_SCOPE_ONLINE_TRANSCRIPT,
};
use crate::crypto::TreePRF;
use crate::preprocessing::prover::PreprocessingExecution;
use crate::preprocessing::{Preprocessing, PreprocessingOutput};
use crate::util::*;

use blake3::Hash;

use rayon::prelude::*;

impl<T: Serializable + Copy> Writer<T> for Vec<T> {
    fn write(&mut self, message: &T) {
        self.push(*message);
    }
}

fn execute_prover<D: Domain, P: Preprocessing<D>, const N: usize>(
    wires: Vec<<D::Sharing as RingModule>::Scalar>,
    mut preprocessing: P,
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
) -> (Vec<D::Sharing>, Vec<D::Sharing>, Hash) {
    let mut wires: VecMap<<D::Sharing as RingModule>::Scalar> = wires.into();
    let mut multiplications: Vec<D::Sharing> = Vec::new();
    let mut reconstructions: Vec<D::Sharing> = Vec::new();
    let mut hasher: RingHasher<D::Sharing> = RingHasher::new();
    for step in program {
        match *step {
            Instruction::AddConst(dst, src, c) => {
                let a_w = wires.get(src);
                wires.set(dst, a_w + c);

                #[cfg(test)]
                #[cfg(debug_assertions)]
                {
                    println!("prover:add-const");
                    println!("  src  = {}", src);
                    println!("  dst  = {}", dst);
                    println!("  c    = {:?}", c);

                    let r_w = wires.get(dst);
                    let r_m = preprocessing.mask(dst).reconstruct();
                    let a_m = preprocessing.mask(src).reconstruct();

                    let r = r_w + r_m;
                    let a = a_w + a_m;

                    debug_assert_eq!(preprocessing.mask(src), preprocessing.mask(dst));
                    debug_assert_eq!(a + c, r);
                }
            }
            Instruction::MulConst(dst, src, c) => {
                let sw = wires.get(src);
                #[cfg(test)]
                #[cfg(debug_assertions)]
                {
                    println!("prover:mul-const");
                    println!("  src  = {}", src);
                    println!("  dst  = {}", dst);
                    println!("  c    = {:?}", c);
                }
                wires.set(dst, sw * c);
            }
            Instruction::Add(dst, src1, src2) => {
                let a_w = wires.get(src1);
                let b_w = wires.get(src2);

                wires.set(dst, a_w + b_w);

                #[cfg(test)]
                #[cfg(debug_assertions)]
                {
                    println!("prover:add");
                    println!("  src1 = {}", src1);
                    println!("  src2 = {}", src2);
                    println!("  dst  = {}", dst);
                    println!("  a_w  = {:?}", a_w);
                    println!("  b_w  = {:?}", b_w);

                    let c_w = wires.get(dst);
                    let c_m = preprocessing.mask(dst).reconstruct();
                    let a_m = preprocessing.mask(src1).reconstruct();
                    let b_m = preprocessing.mask(src2).reconstruct();

                    let c = c_w + c_m;
                    let a = a_w + a_m;
                    let b = b_w + b_m;

                    debug_assert_eq!(c, a + b);
                }
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
                multiplications.push(recon);

                // corrected wire
                let c_w = recon.reconstruct() + a_w * b_w;

                #[cfg(test)]
                #[cfg(debug_assertions)]
                {
                    let c_m = preprocessing.mask(dst);

                    println!("prover:mult");
                    println!("  src1 = {}", src1);
                    println!("  src2 = {}", src2);
                    println!("  dst  = {}", dst);
                    println!("  a_w  = {:?}", a_w);
                    println!("  b_w  = {:?}", b_w);
                    println!("  a_m  = {:?}", a_m);
                    println!("  b_m  = {:?}", b_m);
                    println!("  c_m  = {:?}", c_m);
                    println!("  ab + \\gamma = {:?}", ab_gamma);
                    println!("  recon = {:?}", recon);

                    // assert that pre-processing is generating valid Beaver triples
                    let a = a_m.reconstruct();
                    let b = b_m.reconstruct();
                    let ab = (ab_gamma - c_m).reconstruct();
                    assert_eq!(a * b, ab);

                    // assert operation computed correctly
                    let i1 = a_w + a_m.reconstruct();
                    let i2 = b_w + b_m.reconstruct();
                    let o = c_w + preprocessing.mask(dst).reconstruct();
                    assert_eq!(i1 * i2, o, "i1 = {:?}, i2 = {:?}, o = {:?}", i1, i2, o);
                }

                // reconstruct and correct share
                wires.set(dst, c_w);
            }
            Instruction::Output(src) => {
                let m: D::Sharing = preprocessing.mask(src);
                #[cfg(test)]
                #[cfg(debug_assertions)]
                {
                    println!("prover:output");
                    println!("  val[{}] = {:?}", src, m.reconstruct() + wires.get(src));
                }
                hasher.write(&m);
                reconstructions.push(m);
            }
        }
    }
    (multiplications, reconstructions, hasher.finalize())
}

impl<D: Domain, const N: usize, const NT: usize, const R: usize> Proof<D, N, NT, R> {
    /// Creates a new proof of program execution on the input provided.
    ///
    /// It is crucial for zero-knowledge that the pre-processing output is not reused!
    /// To help ensure this Proof::new takes ownership of PreprocessedProverOutput,
    /// which prevents the programmer from accidentally re-using the output
    pub fn new(
        preprocessing: PreprocessingOutput<D, R, N>,
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: &[<D::Sharing as RingModule>::Scalar],
    ) -> Proof<D, N, NT, R> {
        let seeds: &[[u8; KEY_SIZE]; R] = &preprocessing.seeds;

        struct Exec<D: Domain, const N: usize, const NT: usize, const R: usize> {
            reconstructions: Option<Vec<D::Sharing>>,
            multiplications: Option<Vec<D::Sharing>>,
            hash: Hash,
            prf: TreePRF<NT>,
            corrections: Option<Vec<D::Batch>>,
            commitments: Box<[Hash; N]>, // commitment to pre-processing views
            wires: Option<Vec<<D::Sharing as RingModule>::Scalar>>,
            omitted: usize,
        }

        // execute the online phase R times
        let mut execs: Vec<Exec<D, N, NT, R>> = Vec::with_capacity(R);

        #[cfg(debug_assertions)]
        let runs = seeds.iter();

        #[cfg(not(debug_assertions))]
        let runs = seeds.par_iter();

        let runs = runs.map(|seed| {
            // expand seed into RNG keys for players
            let tree: TreePRF<NT> = TreePRF::new(*seed);
            let keys: Box<[[u8; KEY_SIZE]; N]> =
                arr_map!(&tree.expand(), |x: &Option<[u8; KEY_SIZE]>| x.unwrap());

            // create fresh view for every player
            let mut views: Box<[View; N]> = arr_map!(&keys, |key| View::new_keyed(key));
            let mut rngs: Box<[ViewRNG; N]> =
                arr_map!(&views, |view| { view.rng(LABEL_RNG_PREPROCESSING) });

            // prepare pre-processing execution (online mode), save the corrections.
            let mut corrections = Vec::<D::Batch>::new();
            let preprocessing: PreprocessingExecution<D, ViewRNG, _, N, true> =
                PreprocessingExecution::new(&mut *rngs, &mut corrections, inputs.len(), program);

            // mask the inputs
            let mut wires: Vec<<D::Sharing as RingModule>::Scalar> =
                Vec::with_capacity(inputs.len());
            for (i, input) in inputs.iter().enumerate() {
                let mask: D::Sharing = preprocessing.mask(i);
                wires.push(*input - mask.reconstruct());
            }

            // execute the online phase (interspersed with pre-processing)
            let (multiplications, reconstructions, hash) =
                execute_prover::<D, _, N>(wires.clone(), preprocessing, program);

            // add corrections to player0 view
            {
                let mut scope = views[0].scope(LABEL_SCOPE_CORRECTION);
                for delta in corrections.iter() {
                    scope.write(delta)
                }
            }

            Exec {
                multiplications: Some(multiplications),
                reconstructions: Some(reconstructions),
                hash,
                commitments: arr_map!(&views, |view| view.hash()),
                prf: tree,
                corrections: Some(corrections),
                wires: Some(wires),
                omitted: 0,
            }
        });

        #[cfg(debug_assertions)]
        execs.extend(runs);

        #[cfg(not(debug_assertions))]
        runs.collect_into_vec(&mut execs);

        // extract which players to omit in every run (Fiat-Shamir)
        let mut view: View = View::new();
        {
            let mut scope = view.scope(LABEL_SCOPE_ONLINE_TRANSCRIPT);
            for run in execs.iter() {
                scope.join(&run.hash);
            }
        }
        let mut rng = view.rng(LABEL_RNG_OPEN_ONLINE);
        for i in 0..R {
            execs[i].omitted = random_usize::<_, N>(&mut rng);

            #[cfg(test)]
            #[cfg(debug_assertions)]
            println!("omitted: {}", execs[i].omitted);
        }

        // compile views of opened players
        let mut runs: Vec<Run<D, N, NT>> = Vec::with_capacity(R);
        execs
            .par_iter_mut()
            .map(|run: &mut _| {
                let mut corrections = run.corrections.take().unwrap();
                if run.omitted == 0 {
                    corrections.clear();
                }

                // extract messages broadcast by omitted player and
                // puncture the PRF to hide the random tape of the hidden player
                Run {
                    corrections,
                    multiplications: shares_to_batches::<D, N>(
                        run.multiplications.take().unwrap(),
                        run.omitted,
                    ),
                    reconstructions: shares_to_batches::<D, N>(
                        run.reconstructions.take().unwrap(),
                        run.omitted,
                    ),
                    commitment: run.commitments[run.omitted],
                    inputs: run.wires.take().unwrap(),
                    open: run.prf.puncture(run.omitted),
                }
            })
            .collect_into_vec(&mut runs);

        Proof { runs }
    }
}
