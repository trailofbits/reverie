use crate::algebra::{Domain, RingModule, Samplable, RingElement};
use crate::{Instruction, ConnectionInstruction, preprocessing};
use crate::crypto::{KEY_SIZE, PRG, RingHasher, kdf, TreePRF};
use rand::rngs::OsRng;
use rand::RngCore;
use crate::preprocessing::PreprocessingOutput;
use async_std::sync::Arc;
use async_std::task;
use crate::fieldswitching::util::{convert_bit_domain, SharesGenerator};
use crate::consts::{CONTEXT_RNG_CORRECTION, CONTEXT_ORACLE_PREPROCESSING};
use crate::util::Writer;
use crate::oracle::RandomOracle;

const DEFAULT_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct Proof<D: Domain, D2: Domain> {
    pub(crate) fieldswitching_input: Vec<usize>,
    pub(crate) fieldswitching_output: Vec<Vec<usize>>,
    pub(crate) eda_bits: Vec<Vec<D::Sharing>>,
    pub(crate) eda_composed: Vec<D2::Sharing>,
    pub(crate) random: TreePRF,
    pub(crate) preprocessing1: preprocessing::Proof<D>,
    pub(crate) pp_output1: PreprocessingOutput<D>,
    pub(crate) preprocessing2: preprocessing::Proof<D2>,
    pub(crate) pp_output2: PreprocessingOutput<D2>,
}

#[derive(Clone)]
pub struct Output<D: Domain, D2: Domain> {
    pub(crate) eda_bits: Vec<Vec<D::Sharing>>,
    pub(crate) eda_composed: Vec<D2::Sharing>,
    pub(crate) output1: preprocessing::Output<D>,
    pub(crate) output2: preprocessing::Output<D2>,
}

impl<D: Domain, D2: Domain> Proof<D, D2> {
    pub(crate) fn new(
        conn_program: Vec<ConnectionInstruction>,
        program1: Vec<Instruction<D::Scalar>>,
        program2: Vec<Instruction<D2::Scalar>>,
        branches1: Vec<Vec<D::Scalar>>,
        branches2: Vec<Vec<D2::Scalar>>,
    ) -> Self {
        // pick global random seed
        let mut root_seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut root_seed);

        // expand root seed into seed per program + field switching seed
        let mut global_seeds: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; 3];
        TreePRF::expand_full(&mut global_seeds, root_seed);

        let mut eda_bits = Vec::with_capacity(DEFAULT_CAPACITY);
        let mut eda_composed = Vec::with_capacity(DEFAULT_CAPACITY);

        // expand the global seed into per-repetition roots
        let mut fieldswitching_exec_roots: Vec<[u8; KEY_SIZE]> = vec![[0; KEY_SIZE]; D::PREPROCESSING_REPETITIONS];
        TreePRF::expand_full(&mut fieldswitching_exec_roots, global_seeds[0]);

        let mut fieldswitching_input = vec![];
        let mut fieldswitching_output = vec![];
        //TODO(gvl): async and parallelized
        for seed in fieldswitching_exec_roots.iter().cloned() {
            let mut execution = PreprocessingExecution::<D, D2>::new(seed);
            let mut corrections = Vec::with_capacity(DEFAULT_CAPACITY);
            eda_bits.clear();
            eda_composed.clear();
            execution.process(&conn_program[..], &mut corrections, &mut eda_bits, &mut eda_composed);
            fieldswitching_input = execution.fieldswitching_input;
            fieldswitching_output = execution.fieldswitching_output;
        }

        let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();

        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);
        // prove preprocessing1
        let (branches_out_1, roots1, results1) = preprocessing::Proof::<D>::new_round_1(global_seeds[1],
                                                                              &branches1[..],
                                                                              program1.iter().cloned(),
                                                                              vec![],
                                                                              fieldswitching_output.clone(),
                                                                              &mut oracle,
        );

        let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();

        // prove preprocessing2
        let (branches_out_2, roots2, results2) = preprocessing::Proof::<D2>::new_round_1(global_seeds[2],
                                                                                        &branches2[..],
                                                                                        program2.iter().cloned(),
                                                                                        fieldswitching_input.clone(),
                                                                                        vec![],
                                                                                        &mut oracle,
        );

        let hidden = preprocessing::Proof::<D2>::get_challenge(&mut oracle);

        let (preprocessing1, pp_output1) = preprocessing::Proof::<D>::new_round_3(global_seeds[1],
                                                                                  branches_out_1,
                                                                                  roots1,
                                                                                  results1,
                                                                                  hidden.clone(),
        );
        let (preprocessing2, pp_output2) = preprocessing::Proof::<D2>::new_round_3(global_seeds[2],
                                                                                  branches_out_2,
                                                                                  roots2,
                                                                                  results2,
                                                                                  hidden.clone(),
        );

        let mut tree: TreePRF = TreePRF::new(D::PREPROCESSING_REPETITIONS, global_seeds[0]);
        //TODO: puncture:
        // for i in hidden.iter().cloned() {
        //     tree = tree.puncture(i);
        // }

        Self {
            fieldswitching_input,
            fieldswitching_output,
            eda_bits,
            eda_composed,
            random: tree,
            preprocessing1,
            pp_output1,
            preprocessing2,
            pp_output2,
        }
    }

    pub(crate) async fn verify(&self,
                               conn_program: Vec<ConnectionInstruction>,
                               program1: Vec<Instruction<D::Scalar>>,
                               program2: Vec<Instruction<D2::Scalar>>,
                               branches1: Vec<Vec<D::Scalar>>,
                               branches2: Vec<Vec<D2::Scalar>>,
    ) -> Result<Output<D, D2>, String> {
        async fn preprocessing_verification<D: Domain, D2: Domain>(
            seed: [u8; KEY_SIZE],
            branches1: Arc<Vec<Vec<D::Scalar>>>,
            branches2: Arc<Vec<Vec<D2::Scalar>>>,
            conn_program: Arc<Vec<ConnectionInstruction>>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            proof1: preprocessing::Proof<D>,
            proof2: preprocessing::Proof<D2>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
        ) -> Option<Output<D, D2>> {
            let mut eda_bits = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut eda_composed = Vec::with_capacity(DEFAULT_CAPACITY);

            let mut execution = PreprocessingExecution::<D, D2>::new(seed);
            let mut corrections = Vec::with_capacity(DEFAULT_CAPACITY);
            execution.process(&conn_program[..], &mut corrections, &mut eda_bits, &mut eda_composed);

            let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();
            let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();
            let mut oracle = RandomOracle::new(CONTEXT_ORACLE_PREPROCESSING, None);
            let output1 = proof1.verify_round_1(&branches1[..],
                                        program1.iter().cloned(),
                                        vec![],
                                        fieldswitching_output.clone(),
                &mut oracle,
            ).await;
            let output2 = proof2.verify_round_1(&branches2[..],
                                        program2.iter().cloned(),
                                        fieldswitching_input.clone(),
                                        vec![],
                                        &mut oracle,
            ).await;

            if output1.is_some() && output2.is_some() {
                preprocessing::Proof::<D>::verify_challenge(&mut oracle, output1.clone().unwrap().0);
                preprocessing::Proof::<D2>::verify_challenge(&mut oracle, output2.clone().unwrap().0);

                Some(Output {
                    eda_bits,
                    eda_composed,
                    output1: output1.clone().unwrap().1,
                    output2: output2.clone().unwrap().1,
                })
            } else {
                None
            }
        }

        // derive keys and hidden execution indexes
        let mut roots: Vec<Option<[u8; KEY_SIZE]>> = vec![None; D::PREPROCESSING_REPETITIONS];
        self.random.expand(&mut roots);

        // verify pre-processing
        let mut tasks = vec![];
        for seed in roots.iter().cloned() {
            tasks.push(task::spawn(preprocessing_verification(
                seed.unwrap(),
                Arc::new(branches1.clone()),
                Arc::new(branches2.clone()),
                Arc::new(conn_program.clone()),
                Arc::new(program1.clone()),
                Arc::new(program2.clone()),
                self.preprocessing1.clone(),
                self.preprocessing2.clone(),
                self.fieldswitching_input.clone(),
                self.fieldswitching_output.clone(),
            )));
        }

        let mut result = Err(String::from("No tasks were started"));
        for t in tasks {
            result = t.await.ok_or_else(|| String::from("Preprocessing task Failed"));
            if result.is_err() {
                return result;
            }
        }

        result
    }
}

struct PreprocessingExecution<D: Domain, D2: Domain> {
    // commitments to player random
    // commitments: Vec<Hash>,

    // Indexes for input and output that needs to go through field switching
    fieldswitching_input: Vec<usize>,
    fieldswitching_output: Vec<Vec<usize>>,

    // interpreter state
    eda_composed_shares: Vec<D2::Sharing>,
    eda_bits_shares: Vec<Vec<D::Sharing>>,

    // scratch space
    scratch: Vec<D2::Batch>,
    scratch2: Vec<Vec<D::Batch>>,

    // sharings
    shares: SharesGenerator<D2, D>,

    corrections_prg: Vec<PRG>,
    corrections: RingHasher<D2::Batch>, // player 0 corrections
}

impl<D: Domain, D2: Domain> PreprocessingExecution<D, D2> {
    pub fn new(root: [u8; KEY_SIZE]) -> Self {
        // expand repetition seed into per-player seeds
        let mut player_seeds: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; D::PLAYERS];
        TreePRF::expand_full(&mut player_seeds, root);

        Self {
            shares: SharesGenerator::new(&player_seeds[..]),
            scratch: vec![D2::Batch::ZERO; D2::PLAYERS],
            scratch2: vec![vec![D::Batch::ZERO; D::PLAYERS]; 2], //TODO(gvl): replace 2 with actual size
            eda_composed_shares: Vec::with_capacity(D::Batch::DIMENSION),
            eda_bits_shares: Vec::with_capacity(D2::Batch::DIMENSION),
            corrections_prg: player_seeds
                .iter()
                .map(|seed| PRG::new(kdf(CONTEXT_RNG_CORRECTION, seed)))
                .collect(),
            corrections: RingHasher::new(),
            fieldswitching_input: Vec::new(),
            fieldswitching_output: Vec::new(),
        }
    }

    #[inline(always)]
    fn generate<CW: Writer<D2::Batch>>(
        &mut self,
        eda_bits: &mut Vec<Vec<D::Sharing>>,
        eda_composed: &mut Vec<D2::Sharing>,
        corrections: &mut CW, // player 0 corrections
        batch_eda: &mut Vec<Vec<D::Batch>>,
        len: usize,
    ) {
        debug_assert_eq!(self.eda_composed_shares.len(), D2::Batch::DIMENSION);
        debug_assert!(self.shares.eda_2.is_empty());

        // transpose sharings into per player batches
        batch_eda.resize(len, vec![D::Batch::ZERO; D::Sharing::DIMENSION]);
        for pos in 0..len {
            D::convert_inv(&mut batch_eda[pos][..], &self.eda_bits_shares[pos][..]);
        }
        self.eda_bits_shares.clear();

        // generate 3 batches of shares for every player
        let mut eda = vec![D2::Batch::ZERO; len];
        let mut eda_out = D2::Batch::ZERO;

        // compute random c sharing and reconstruct a,b sharings
        for i in 0..D2::PLAYERS {
            let corr = D2::Batch::gen(&mut self.corrections_prg[i]);
            for j in 0..len {
                eda[j] = eda[j] + convert_bit_domain::<D, D2>(batch_eda[j][i]).unwrap();
                self.scratch2[j][i] = self.scratch2[j][i] + batch_eda[j][i];
            }
            eda_out = eda_out + corr;
            self.scratch[i] = corr;
        }

        let two = D2::Batch::ONE + D2::Batch::ONE;
        let mut pow_two = D2::Batch::ONE;
        let mut arith = D2::Batch::ZERO;
        for j in 0..len {
            arith = arith + pow_two * eda[j];
            pow_two = pow_two * two;
        }
        // correct shares for player 0 (correction bits)
        let delta = arith - eda_out;

        // write correction batch (player 0 correction bits)
        // for the pre-processing phase, the writer will simply be a hash function.
        corrections.write(delta);

        // correct eda (in parallel)
        self.scratch[0] = self.scratch[0] + delta;

        // transpose into shares
        if eda_bits.len() != len {
            eda_bits.resize(len, Vec::with_capacity(D::Batch::DIMENSION));
        }
        for j in 0..len {
            let start = eda_bits[j].len();
            eda_bits[j].resize(start + D::Batch::DIMENSION, D::Sharing::ZERO);
            D::convert(&mut eda_bits[j][start..], &self.scratch2[j][..]);
        }

        let start = eda_composed.len();
        eda_composed.resize(start + D2::Batch::DIMENSION, D2::Sharing::ZERO);
        D2::convert(&mut eda_composed[start..], &self.scratch[..]);

        debug_assert_eq!(self.eda_bits_shares.len(), 0);
    }

    pub fn process<CW: Writer<D2::Batch>>(&mut self,
                                          conn_program: &[ConnectionInstruction],
                                          corrections: &mut CW,               // player 0 corrections
                                          eda_bits: &mut Vec<Vec<D::Sharing>>,     // eda bits in boolean form
                                          eda_composed: &mut Vec<D2::Sharing>,     // eda bits composed in arithmetic form
    ) {
        //TODO(gvl): set outer dimension to size of target field
        let mut m = 1;
        let mut batch_eda = vec![vec![D::Batch::ZERO; D::PLAYERS]; m];

        for gate in conn_program.clone() {
            match gate {
                ConnectionInstruction::BToA(dst, src) => {
                    self.fieldswitching_output.push(src.to_vec());
                    self.fieldswitching_input.push(*dst);

                    if src.len() > m {
                        m = src.len()
                    }
                    self.eda_composed_shares.resize(self.eda_composed_shares.len() + 1, D2::Sharing::ZERO); //TODO(gvl): better scaling
                    self.eda_bits_shares.resize(src.len(), Vec::with_capacity(D::Batch::DIMENSION));
                    // push the input masks to the deferred eda stack
                    for (pos, &_src) in src.iter().enumerate() {
                        let mask = self.shares.eda_2.next();
                        self.eda_bits_shares[pos].push(mask.clone());
                    }

                    // assign mask to output
                    self.eda_composed_shares.push(self.shares.eda.next());

                    // if the batch is full, generate next batch of edaBits shares
                    if self.eda_composed_shares.len() == D2::Batch::DIMENSION {
                        self.generate(eda_bits, eda_composed, corrections, &mut batch_eda, src.len());
                    }
                }
                _ => {}
            }
        }

        // pad final eda batch if needed
        if !self.eda_composed_shares.is_empty() {
            self.eda_composed_shares.resize(D2::Batch::DIMENSION, D2::Sharing::ZERO);
            //TODO(gvl): make len flexible
            for i in 0..m {
                self.eda_bits_shares[i].resize(D::Batch::DIMENSION, D::Sharing::ZERO);
            }
            self.shares.eda_2.empty();
            self.generate(eda_bits, eda_composed, corrections, &mut batch_eda, m);
        }
    }
}


