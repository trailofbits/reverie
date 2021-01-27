use crate::algebra::{Domain, RingModule, Samplable, RingElement};
use crate::{Instruction, ConnectionInstruction, preprocessing};
use crate::crypto::{KEY_SIZE, PRG, RingHasher, kdf, TreePRF};
use rand::rngs::OsRng;
use rand::RngCore;
use crate::preprocessing::PreprocessingOutput;
use async_std::sync::Arc;
use async_std::task;
use crate::fieldswitching::util::{convert_bit_domain, SharesGenerator};
use crate::consts::CONTEXT_RNG_CORRECTION;
use crate::util::{Writer, VoidWriter};

const DEFAULT_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct Proof<D: Domain, D2: Domain> {
    pub(crate) fieldswitching_input: Vec<usize>,
    pub(crate) fieldswitching_output: Vec<Vec<usize>>,
    pub(crate) eda_bits: Vec<Vec<D::Sharing>>,
    pub(crate) eda_composed: Vec<D2::Sharing>,
    pub(crate) preprocessing1: preprocessing::Proof<D>,
    pub(crate) pp_output1: PreprocessingOutput<D>,
    pub(crate) preprocessing2: preprocessing::Proof<D2>,
    pub(crate) pp_output2: PreprocessingOutput<D2>,
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
        let mut seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut seed);

        let mut eda_bits = Vec::with_capacity(DEFAULT_CAPACITY);
        let mut eda_composed = Vec::with_capacity(DEFAULT_CAPACITY);
        let mut execution = PreprocessingExecution::<D, D2>::new(seed);
        let mut corrections = Vec::with_capacity(DEFAULT_CAPACITY);
        execution.process(&conn_program[..], &mut corrections, &mut eda_bits, &mut eda_composed);

        let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();

        // prove preprocessing1
        let (preprocessing1, pp_output1) =
            preprocessing::Proof::new(seed,
                                      &branches1[..],
                                      program1.iter().cloned(),
                                      vec![],
                                      execution.fieldswitching_output.clone(),
            );

        let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();

        // prove preprocessing2
        let (preprocessing2, pp_output2) =
            preprocessing::Proof::new(seed,
                                      &branches2[..],
                                      program2.iter().cloned(),
                                      execution.fieldswitching_input.clone(),
                                      vec![],
            );

        println!("{:?}", eda_bits);
        println!("{:?}", eda_composed);
        println!("{:?}", corrections);
        Self {
            fieldswitching_input: execution.fieldswitching_input,
            fieldswitching_output: execution.fieldswitching_output,
            eda_bits,
            eda_composed,
            preprocessing1,
            pp_output1,
            preprocessing2,
            pp_output2,
        }
    }

    pub(crate) async fn verify(&self,
                               program1: Vec<Instruction<D::Scalar>>,
                               program2: Vec<Instruction<D2::Scalar>>,
                               branches1: Vec<Vec<D::Scalar>>,
                               branches2: Vec<Vec<D2::Scalar>>,
    ) -> Result<(preprocessing::Output<D>, preprocessing::Output<D2>), String> {
        async fn preprocessing_verification<D: Domain, D2: Domain>(
            branches1: Arc<Vec<Vec<D::Scalar>>>,
            branches2: Arc<Vec<Vec<D2::Scalar>>>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            proof1: preprocessing::Proof<D>,
            proof2: preprocessing::Proof<D2>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
        ) -> Option<(preprocessing::Output<D>, preprocessing::Output<D2>)> {
            let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();
            let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();
            let output1 = proof1.verify(&branches1[..],
                                        program1.iter().cloned(),
                                        vec![],
                                        fieldswitching_output.clone(),
            ).await;
            let output2 = proof2.verify(&branches2[..],
                                        program2.iter().cloned(),
                                        fieldswitching_input.clone(),
                                        vec![],
            ).await;
            if output1.is_some() && output2.is_some() {
                Some((output1.unwrap(), output2.unwrap()))
            } else {
                None
            }
        }

        // verify pre-processing
        let preprocessing_task = task::spawn(preprocessing_verification(
            Arc::new(branches1.clone()),
            Arc::new(branches2.clone()),
            Arc::new(program1.clone()),
            Arc::new(program2.clone()),
            self.preprocessing1.clone(),
            self.preprocessing2.clone(),
            self.fieldswitching_input.clone(),
            self.fieldswitching_output.clone(),
        ));

        // check that online execution matches preprocessing (executing both in parallel)
        preprocessing_task
            .await
            .ok_or_else(|| String::from("Preprocessing task Failed"))
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


