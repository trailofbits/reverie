use crate::algebra::{Domain, RingElement, RingModule, Samplable};
use crate::consts::{BATCH_SIZE, CONTEXT_ORACLE_PREPROCESSING, CONTEXT_RNG_CORRECTION};
use crate::crypto::{hash, kdf, Hash, Hasher, Prg, RingHasher, TreePrf, KEY_SIZE};
use crate::fieldswitching::util::{convert_bit_domain, PartialSharesGenerator, SharesGenerator};
use crate::oracle::RandomOracle;
use crate::util::Writer;
use crate::{preprocessing, ConnectionInstruction, Instruction};
use async_std::sync::Arc;
use async_std::task;
use rand::rngs::OsRng;
use rand::RngCore;

use serde::{Deserialize, Serialize};

const DEFAULT_CAPACITY: usize = BATCH_SIZE;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Proof<D: Domain, D2: Domain> {
    pub hidden: Vec<Hash>,
    pub random: TreePrf,
    pub preprocessing1: preprocessing::Proof<D>,
    pub preprocessing2: preprocessing::Proof<D2>,
}

pub struct PreprocessingOutput<D: Domain, D2: Domain> {
    pub(crate) hidden: Vec<FsPreprocessingRun<D, D2>>,
    pub(crate) pp_output1: preprocessing::PreprocessingOutput<D>,
    pub(crate) pp_output2: preprocessing::PreprocessingOutput<D2>,
}

#[derive(Clone)] //TODO(gvl): remove clone
pub struct FsPreprocessingRun<D: Domain, D2: Domain> {
    pub(crate) fieldswitching_input: Vec<usize>,
    pub(crate) fieldswitching_output: Vec<Vec<usize>>,
    pub(crate) eda_bits: Vec<Vec<D::Sharing>>,
    pub(crate) eda_composed: Vec<D2::Sharing>,
    pub(crate) seed: [u8; KEY_SIZE],
    pub(crate) corrections: Vec<D2::Batch>,
    pub(crate) union: Hash,
    pub(crate) commitments: Vec<Hash>, // preprocessing commitment for every player
}

impl<D: Domain, D2: Domain> Proof<D, D2> {
    pub fn new(
        conn_program: Vec<ConnectionInstruction>,
        program1: Arc<Vec<Instruction<D::Scalar>>>,
        program2: Arc<Vec<Instruction<D2::Scalar>>>,
        branches1: Vec<Vec<D::Scalar>>,
        branches2: Vec<Vec<D2::Scalar>>,
    ) -> (Self, PreprocessingOutput<D, D2>) {
        assert_eq!(D::PREPROCESSING_REPETITIONS, D2::PREPROCESSING_REPETITIONS);
        assert_eq!(D::ONLINE_REPETITIONS, D2::ONLINE_REPETITIONS);
        assert_eq!(D::PLAYERS, D2::PLAYERS);
        // pick global random seed
        let mut root_seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut root_seed);

        // expand root seed into seed per program + field switching seed
        let mut global_seeds: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; 3];
        TreePrf::expand_full(&mut global_seeds, root_seed);

        // expand the global seed into per-repetition roots
        let mut fieldswitching_exec_roots: Vec<[u8; KEY_SIZE]> =
            vec![[0; KEY_SIZE]; D::PREPROCESSING_REPETITIONS];
        TreePrf::expand_full(&mut fieldswitching_exec_roots, global_seeds[0]);

        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);
        let mut results = Vec::new();
        let (fieldswitching_input, fieldswitching_output) =
            PreprocessingExecution::<D, D2>::get_fs_input_output(&conn_program[..]);
        //TODO(gvl): async and parallelized
        for seed in fieldswitching_exec_roots.iter().cloned() {
            let mut eda_bits = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut eda_composed = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut execution = PreprocessingExecution::<D, D2>::new(seed);
            let mut corrections = Vec::with_capacity(DEFAULT_CAPACITY);
            execution.process(
                &conn_program[..],
                &mut corrections,
                &mut eda_bits,
                &mut eda_composed,
            );
            let (union, commitments) = execution.done();
            results.push(FsPreprocessingRun {
                fieldswitching_input: fieldswitching_input.clone(),
                fieldswitching_output: fieldswitching_output.clone(),
                eda_bits: eda_bits.clone(),
                eda_composed: eda_composed.clone(),
                seed,
                corrections,
                union: union.clone(),
                commitments,
            });
            oracle.feed(union.as_bytes());
        }

        let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();

        // prove preprocessing1
        let (branches_out_1, roots1, results1) = preprocessing::Proof::<D>::new_round_1(
            global_seeds[1],
            &branches1[..],
            program1,
            (vec![], fieldswitching_output),
            &mut oracle,
        );

        let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();

        // prove preprocessing2
        let (branches_out_2, roots2, results2) = preprocessing::Proof::<D2>::new_round_1(
            global_seeds[2],
            &branches2[..],
            program2,
            (fieldswitching_input, vec![]),
            &mut oracle,
        );

        let hidden = preprocessing::Proof::<D2>::get_challenge(&mut oracle);

        let (preprocessing1, pp_output1) = preprocessing::Proof::<D>::new_round_3(
            global_seeds[1],
            branches_out_1,
            roots1,
            results1,
            hidden.clone(),
        );
        let (preprocessing2, pp_output2) = preprocessing::Proof::<D2>::new_round_3(
            global_seeds[2],
            branches_out_2,
            roots2,
            results2,
            hidden.clone(),
        );

        let mut hidden_runs: Vec<FsPreprocessingRun<D, D2>> =
            Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut hidden_hashes: Vec<Hash> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut results1 = results.into_iter().enumerate();
        let mut tree: TreePrf = TreePrf::new(D::PREPROCESSING_REPETITIONS, global_seeds[0]);

        for i in hidden.iter().cloned() {
            tree = tree.puncture(i);
            // find the matching result
            let result = loop {
                let (j, elem) = results1.next().unwrap();
                if i == j {
                    break elem;
                }
            };

            // add to the preprocessing output
            hidden_runs.push(result.clone());

            // add to the preprocessing proof
            hidden_hashes.push(result.union.clone());
        }

        (
            Self {
                hidden: hidden_hashes,
                random: tree,
                preprocessing1,
                preprocessing2,
            },
            PreprocessingOutput {
                hidden: hidden_runs,
                pp_output1,
                pp_output2,
            },
        )
    }

    pub async fn verify(
        &self,
        conn_program: Vec<ConnectionInstruction>,
        program1: Arc<Vec<Instruction<D::Scalar>>>,
        program2: Arc<Vec<Instruction<D2::Scalar>>>,
        branches1: Vec<Vec<D::Scalar>>,
        branches2: Vec<Vec<D2::Scalar>>,
    ) -> Result<(), String> {
        async fn preprocessing_verification<D: Domain, D2: Domain>(
            seed: [u8; KEY_SIZE],
            conn_program: Arc<Vec<ConnectionInstruction>>,
        ) -> Option<Hash> {
            let mut eda_bits = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut eda_composed = Vec::with_capacity(DEFAULT_CAPACITY);

            let mut execution = PreprocessingExecution::<D, D2>::new(seed);
            let mut corrections = Vec::with_capacity(DEFAULT_CAPACITY);
            execution.process(
                &conn_program[..],
                &mut corrections,
                &mut eda_bits,
                &mut eda_composed,
            );

            Some(execution.done().0)
        }

        // derive keys and hidden execution indexes
        let mut roots: Vec<Option<[u8; KEY_SIZE]>> = vec![None; D::PREPROCESSING_REPETITIONS];
        self.random.expand(&mut roots);

        // derive the hidden indexes
        let mut opened: Vec<bool> = Vec::with_capacity(D::PREPROCESSING_REPETITIONS);
        let mut hidden: Vec<usize> = Vec::with_capacity(D::ONLINE_REPETITIONS);
        for (i, key) in roots.iter().enumerate() {
            opened.push(key.is_some());
            if key.is_none() {
                hidden.push(i)
            }
        }

        // prover must open exactly R-H repetitions
        if hidden.len() != D::ONLINE_REPETITIONS {
            return Err(String::from(
                "number of hidden runs in preprocessing is incorrect",
            ));
        }

        // recompute the opened repetitions
        let opened_roots: Vec<[u8; KEY_SIZE]> = roots
            .iter()
            .filter(|v| v.is_some())
            .map(|v| v.unwrap())
            .collect();

        debug_assert_eq!(
            opened_roots.len(),
            D::PREPROCESSING_REPETITIONS - D::ONLINE_REPETITIONS
        );

        // verify pre-processing
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);
        let (fieldswitching_input, fieldswitching_output) =
            PreprocessingExecution::<D, D2>::get_fs_input_output(&conn_program[..]);
        let mut tasks = vec![];
        for seed in opened_roots.iter().cloned() {
            tasks.push(task::spawn(preprocessing_verification::<D, D2>(
                seed,
                Arc::new(conn_program.clone()),
            )));
        }

        let mut opened_hashes = Vec::new();
        for t in tasks {
            let result = t
                .await
                .ok_or_else(|| String::from("Preprocessing task Failed"));
            if result.is_err() {
                return Err(result.err().unwrap());
            }
            opened_hashes.push(result.unwrap());
        }

        // interleave the proved hashes with the recomputed ones
        let mut open_hsh = opened_hashes.iter();
        let mut hide_hsh = self.hidden.iter();
        for open in opened {
            if open {
                oracle.feed(open_hsh.next().unwrap().as_bytes());
            } else {
                oracle.feed(hide_hsh.next().unwrap().as_bytes());
            }
        }

        let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();
        let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();

        let output1 = self
            .preprocessing1
            .verify_round_1(
                &branches1[..],
                program1.clone(),
                (vec![], fieldswitching_output.clone()),
                &mut oracle,
            )
            .await;
        let output2 = self
            .preprocessing2
            .verify_round_1(
                &branches2[..],
                program2.clone(),
                (fieldswitching_input.clone(), vec![]),
                &mut oracle,
            )
            .await;

        if output1.is_some() && output2.is_some() {
            let output1 = output1.unwrap();
            let output2 = output2.unwrap();
            if output1.0[..] != output2.0[..]
                || hidden[..] != output1.0[..]
                || !preprocessing::Proof::<D>::verify_challenge(&mut oracle, output1.0)
                || !preprocessing::Proof::<D2>::verify_challenge(&mut oracle, output2.0)
            {
                return Err(String::from("preprocessing challenges did not verify"));
            }
        } else {
            return Err(String::from(
                "one of the sub circuits did not verify properly",
            ));
        }

        Ok(())
    }
}

pub struct PreprocessingExecution<D: Domain, D2: Domain> {
    // commitments to player random
    commitments: Vec<Hash>,

    // interpreter state
    eda_composed_shares: Vec<D2::Sharing>,
    eda_bits_shares: Vec<Vec<D::Sharing>>,

    // scratch space
    scratch: Vec<D2::Batch>,
    scratch2: Vec<Vec<D::Batch>>,

    // sharings
    shares: SharesGenerator<D2, D>,

    corrections_prg: Vec<Prg>,
    corrections: RingHasher<D2::Batch>, // player 0 corrections
}

impl<D: Domain, D2: Domain> PreprocessingExecution<D, D2> {
    pub fn new(root: [u8; KEY_SIZE]) -> Self {
        // expand repetition seed into per-player seeds
        let mut player_seeds: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; D::PLAYERS];
        TreePrf::expand_full(&mut player_seeds, root);

        // commit to per-player randomness
        let commitments: Vec<Hash> = player_seeds.iter().map(|seed| hash(seed)).collect();

        Self {
            commitments,
            shares: SharesGenerator::new(&player_seeds[..]),
            scratch: vec![D2::Batch::ZERO; D2::PLAYERS],
            scratch2: vec![vec![D::Batch::ZERO; D::PLAYERS]; D2::NR_OF_BITS],
            eda_composed_shares: Vec::with_capacity(D::Batch::DIMENSION),
            eda_bits_shares: Vec::with_capacity(D2::Batch::DIMENSION),
            corrections_prg: player_seeds
                .iter()
                .map(|seed| Prg::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
                .collect(),
            corrections: RingHasher::new(),
        }
    }

    #[inline(always)]
    fn generate<CW: Writer<D2::Batch>>(
        &mut self,
        eda_bits: &mut Vec<Vec<D::Sharing>>,
        eda_composed: &mut Vec<D2::Sharing>,
        corrections: &mut CW, // player 0 corrections
        batch_eda: &mut Vec<Vec<D::Batch>>,
    ) {
        debug_assert_eq!(self.eda_composed_shares.len(), D2::Batch::DIMENSION);
        debug_assert!(self.shares.eda_2.is_empty());
        let len = D2::NR_OF_BITS;

        // transpose sharings into per player batches
        batch_eda.resize(len, vec![D::Batch::ZERO; D::Sharing::DIMENSION]);
        for (pos, eda_share) in self.eda_bits_shares.iter().enumerate() {
            D::convert_inv(&mut batch_eda[pos][..], &eda_share[..]);
        }
        self.eda_bits_shares.clear();

        let mut eda = vec![D::Batch::ZERO; len];
        let mut eda_out = D2::Batch::ZERO;

        for i in 0..D2::PLAYERS {
            let corr = D2::Batch::gen(&mut self.corrections_prg[i]);
            for j in 0..len {
                eda[j] = eda[j] + batch_eda[j][i];
                self.scratch2[j][i] = self.scratch2[j][i] + batch_eda[j][i];
            }
            eda_out = eda_out + corr;
            self.scratch[i] = corr;
        }

        let two = D2::Batch::ONE + D2::Batch::ONE;
        let mut pow_two = D2::Batch::ONE;
        let mut arith = D2::Batch::ZERO;
        for eda_b in eda.iter().cloned() {
            arith = arith + pow_two * convert_bit_domain::<D, D2>(eda_b).unwrap()[0];
            pow_two = pow_two * two;
        }
        // println!("arith: {:?}", arith);
        // correct shares for player 0 (correction bits)
        let delta = arith - eda_out;

        // write correction batch (player 0 correction bits)
        // for the pre-processing phase, the writer will simply be a hash function.
        corrections.write(delta);

        // correct eda (in parallel)
        self.scratch[0] = self.scratch[0] + delta;

        #[cfg(test)]
        {
            // let mut eda_comp = D2::Batch::ZERO;
            let mut recon = D2::Batch::ZERO;
            for i in 0..D::PLAYERS {
                // eda_comp = eda_comp + self.shares.eda.batches()[i];
                recon = recon + self.scratch[i];
            }
            let mut arith = D2::Batch::ZERO;
            let mut pow_two = D2::Batch::ONE;
            for eda_b in eda.iter().cloned() {
                let x = convert_bit_domain::<D, D2>(eda_b).unwrap()[0];
                // println!("x: {:?}", x);
                arith = arith + pow_two * x;
                pow_two = pow_two * two;
            }
            // println!("eda: {:?}", eda);
            assert_eq!(arith, recon);
        }

        // transpose into shares
        if eda_bits.len() != len {
            eda_bits.resize(len, Vec::with_capacity(D::Batch::DIMENSION));
        }
        for (j, eda_bit) in eda_bits.iter_mut().enumerate() {
            let start = eda_bit.len();
            eda_bit.resize(start + D::Batch::DIMENSION, D::Sharing::ZERO);
            D::convert(&mut eda_bit[start..], &self.scratch2[j][..]);
        }

        let start = eda_composed.len();
        eda_composed.resize(start + D2::Batch::DIMENSION, D2::Sharing::ZERO);
        D2::convert(&mut eda_composed[start..], &self.scratch[..]);

        debug_assert_eq!(self.eda_bits_shares.len(), 0);
    }

    pub fn get_fs_input_output(
        conn_program: &[ConnectionInstruction],
    ) -> (Vec<usize>, Vec<Vec<usize>>) {
        let mut fieldswitching_output = Vec::new();
        let mut fieldswitching_input = Vec::new();
        for gate in conn_program {
            match gate {
                ConnectionInstruction::BToA(dst, src) => {
                    fieldswitching_output.push(src[0..D2::NR_OF_BITS].to_vec());
                    fieldswitching_input.push(*dst);
                }
                ConnectionInstruction::AToB(_dst, _src) => {}
                ConnectionInstruction::Challenge(_dst) => {}
            }
        }

        (fieldswitching_input, fieldswitching_output)
    }

    pub fn process<CW: Writer<D2::Batch>>(
        &mut self,
        conn_program: &[ConnectionInstruction],
        corrections: &mut CW,                // player 0 corrections
        eda_bits: &mut Vec<Vec<D::Sharing>>, // eda bits in boolean form
        eda_composed: &mut Vec<D2::Sharing>, // eda bits composed in arithmetic form
    ) {
        let m = D2::NR_OF_BITS;
        let mut batch_eda = vec![vec![D::Batch::ZERO; D::PLAYERS]; m];

        for gate in conn_program {
            match gate {
                ConnectionInstruction::BToA(_dst, _src) => {
                    self.eda_composed_shares.resize(
                        self.eda_composed_shares.len() + D2::Batch::DIMENSION,
                        D2::Sharing::ZERO,
                    );
                    self.eda_bits_shares
                        .resize(m, Vec::with_capacity(D::Batch::DIMENSION));
                    // push the input masks to the deferred eda stack
                    for eda in self.eda_bits_shares.iter_mut() {
                        let mask = self.shares.eda_2.next();
                        eda.push(mask);
                    }

                    // assign mask to output
                    for _i in 0..D2::Batch::DIMENSION {
                        self.eda_composed_shares.push(self.shares.eda.next());
                    }

                    // if the batch is full, generate next batch of edaBits shares
                    if self.eda_composed_shares.len() == D2::Batch::DIMENSION {
                        self.generate(eda_bits, eda_composed, corrections, &mut batch_eda);
                    }
                }
                ConnectionInstruction::AToB(_dst, _src) => {}
                ConnectionInstruction::Challenge(_dst) => {}
            }
        }

        // pad final eda batch if needed
        if !self.eda_composed_shares.is_empty() {
            self.eda_composed_shares
                .resize(D2::Batch::DIMENSION, D2::Sharing::ZERO);
            for i in 0..m {
                self.eda_bits_shares[i].resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            }
            self.shares.eda_2.empty();
            self.generate(eda_bits, eda_composed, corrections, &mut batch_eda);
        }
    }

    pub fn done(mut self) -> (Hash, Vec<Hash>) {
        // add corrections and Merkle root to player 0 commitment
        self.commitments[0] = {
            let mut comm = Hasher::new();
            comm.update(self.commitments[0].as_bytes());
            comm.update(self.corrections.finalize().as_bytes());
            comm.finalize()
        };

        // merge player commitments with branch tree commitment
        let mut union = Hasher::new();
        for comm in self.commitments.iter() {
            union.update(comm.as_bytes());
        }

        // return player commitments
        (union.finalize(), self.commitments)
    }
}

pub(crate) struct PartialPreprocessingExecution<D: Domain, D2: Domain> {
    // commitments to player random
    commitments: Vec<Hash>,
    omitted: usize,

    // interpreter state
    eda_composed_shares: Vec<D2::Sharing>,
    eda_bits_shares: Vec<Vec<D::Sharing>>,

    // scratch space
    scratch: Vec<D2::Batch>,
    scratch2: Vec<Vec<D::Batch>>,

    // sharings
    shares: PartialSharesGenerator<D2, D>,

    corrections_prg: Vec<Prg>,
    corrections: RingHasher<D2::Batch>, // player 0 corrections
}

impl<D: Domain, D2: Domain> PartialPreprocessingExecution<D, D2> {
    pub fn new(tree: TreePrf) -> Self {
        // expand repetition seed into per-player seeds
        let mut player_seeds: Vec<Option<[u8; KEY_SIZE]>> = vec![None; D::PLAYERS];
        tree.expand(&mut player_seeds);

        // find omitted player
        let mut omitted: usize = 0;
        for (i, seed) in player_seeds.iter().enumerate() {
            if seed.is_none() {
                omitted = i;
            }
        }

        // replace omitted player with dummy key
        let player_seeds: Vec<[u8; KEY_SIZE]> = player_seeds
            .into_iter()
            .map(|seed| seed.unwrap_or([0u8; KEY_SIZE]))
            .collect();

        // commit to per-player randomness
        let commitments: Vec<Hash> = player_seeds.iter().map(|seed| hash(seed)).collect();

        // aggregate branch hashes into Merkle tree and return pre-processor for circuit
        let corrections_prg = player_seeds
            .iter()
            .map(|seed| Prg::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
            .collect();

        let shares = PartialSharesGenerator::new(&player_seeds[..], omitted);

        Self {
            commitments,
            omitted,
            shares,
            scratch: vec![D2::Batch::ZERO; D2::PLAYERS],
            scratch2: vec![vec![D::Batch::ZERO; D::PLAYERS]; D2::NR_OF_BITS],
            eda_composed_shares: Vec::with_capacity(D::Batch::DIMENSION),
            eda_bits_shares: Vec::with_capacity(D2::Batch::DIMENSION),
            corrections_prg,
            corrections: RingHasher::new(),
        }
    }

    #[inline(always)]
    fn generate<I: Iterator<Item = D2::Batch>>(
        &mut self,
        eda_bits: &mut Vec<Vec<D::Sharing>>,
        eda_composed: &mut Vec<D2::Sharing>,
        corrections: &mut I, // player 0 corrections
        batch_eda: &mut Vec<Vec<D::Batch>>,
        len: usize,
    ) -> Option<()> {
        debug_assert_eq!(self.eda_composed_shares.len(), D2::Batch::DIMENSION);
        debug_assert!(self.shares.eda_2.is_empty());

        // transpose sharings into per player batches
        batch_eda.resize(len, vec![D::Batch::ZERO; D::Sharing::DIMENSION]);
        for (pos, eda) in batch_eda.iter_mut().enumerate() {
            D::convert_inv(&mut eda[..], &self.eda_bits_shares[pos][..]);
        }
        self.eda_bits_shares.clear();

        for i in 0..D2::PLAYERS {
            self.scratch[i] = D2::Batch::gen(&mut self.corrections_prg[i]);

            if i == 0 {
                let corr = corrections.next()?;
                self.scratch[0] = self.scratch[0] + corr;
                self.corrections.update(corr);
            }
        }

        // transpose into shares
        if eda_bits.len() != len {
            eda_bits.resize(len, Vec::with_capacity(D::Batch::DIMENSION));
        }
        for (j, eda_bit) in eda_bits.iter_mut().enumerate() {
            let start = eda_bit.len();
            eda_bit.resize(start + D::Batch::DIMENSION, D::Sharing::ZERO);
            D::convert(&mut eda_bit[start..], &self.scratch2[j][..]);
        }

        let start = eda_composed.len();
        eda_composed.resize(start + D2::Batch::DIMENSION, D2::Sharing::ZERO);
        D2::convert(&mut eda_composed[start..], &self.scratch[..]);

        Some(())
    }

    pub fn process(
        &mut self,
        conn_program: &[ConnectionInstruction],
        corrections: &[D2::Batch],           // player 0 corrections
        eda_bits: &mut Vec<Vec<D::Sharing>>, // eda bits in boolean form
        eda_composed: &mut Vec<D2::Sharing>, // eda bits composed in arithmetic form
    ) -> Option<Option<ConnectionInstruction>> {
        let mut out = None;
        let mut corrections = corrections.iter().cloned();

        let m = D2::NR_OF_BITS;
        let mut batch_eda = vec![vec![D::Batch::ZERO; D::PLAYERS]; m];

        for gate in conn_program {
            match gate {
                ConnectionInstruction::BToA(_dst, src) => {
                    self.eda_composed_shares
                        .resize(self.eda_composed_shares.len() + 1, D2::Sharing::ZERO); //TODO(gvl): better scaling
                    self.eda_bits_shares
                        .resize(src.len(), Vec::with_capacity(D::Batch::DIMENSION));
                    // push the input masks to the deferred eda stack
                    for (pos, &_src) in src.iter().enumerate() {
                        let mask = self.shares.eda_2.next();
                        self.eda_bits_shares[pos].push(mask);
                    }

                    // assign mask to output
                    self.eda_composed_shares.push(self.shares.eda.next());

                    // if the batch is full, generate next batch of edaBits shares
                    if self.eda_composed_shares.len() == D2::Batch::DIMENSION {
                        self.generate(eda_bits, eda_composed, &mut corrections, &mut batch_eda, m);
                    }
                }
                ConnectionInstruction::AToB(_dst, _src) => {}
                ConnectionInstruction::Challenge(dst) => {
                    out = Some(ConnectionInstruction::Challenge(*dst));
                }
            }
        }

        // pad final eda batch if needed
        if !self.eda_composed_shares.is_empty() {
            self.eda_composed_shares
                .resize(D2::Batch::DIMENSION, D2::Sharing::ZERO);
            for i in 0..m {
                self.eda_bits_shares[i].resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            }
            self.shares.eda_2.empty();
            let option = self.generate(eda_bits, eda_composed, &mut corrections, &mut batch_eda, m);
            if option.is_some() {
                Some(out)
            } else {
                None
            }
        } else {
            Some(out)
        }
    }

    pub fn commitment(mut self, omitted_commitment: &Hash) -> Hash {
        // add corrections to player0
        self.commitments[0] = {
            let mut hash = Hasher::new();
            hash.update(self.commitments[0].as_bytes());
            hash.update(self.corrections.finalize().as_bytes());
            hash.finalize()
        };

        let mut hasher = Hasher::new();
        for i in 0..D::PLAYERS {
            hasher.update(
                if i == self.omitted {
                    &omitted_commitment
                } else {
                    &self.commitments[i]
                }
                .as_bytes(),
            );
        }
        hasher.finalize()
    }
}
