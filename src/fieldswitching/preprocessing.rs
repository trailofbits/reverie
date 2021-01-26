use crate::algebra::Domain;
use std::marker::PhantomData;
use crate::{Instruction, ConnectionInstruction, preprocessing};
use crate::crypto::KEY_SIZE;
use rand::rngs::OsRng;
use rand::RngCore;
use crate::preprocessing::PreprocessingOutput;
use async_std::sync::Arc;
use async_std::task;

#[derive(Clone)]
pub struct Proof<D: Domain, D2: Domain> {
    pub(crate) fieldswitching_input: Vec<usize>,
    pub(crate) fieldswitching_output: Vec<Vec<usize>>,
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
        let mut impacted_output = Vec::new();
        let mut impacted_input = Vec::new();
        for gate in conn_program.clone() {
            match gate {
                ConnectionInstruction::BToA(dst, src) => {
                    impacted_output.push(src.to_vec());
                    impacted_input.push(dst);
                }
                _ => {}
            }
        }
        println!("{:?}", impacted_output);
        println!("{:?}", impacted_input);

        let branches1: Vec<&[D::Scalar]> = branches1.iter().map(|b| &b[..]).collect();

        // pick global random seed
        let mut seed: [u8; KEY_SIZE] = [0; KEY_SIZE];
        OsRng.fill_bytes(&mut seed);

        // prove preprocessing1
        let (preprocessing1, pp_output1) =
            preprocessing::Proof::new(seed,
                                      &branches1[..],
                                      program1.iter().cloned(),
                                      vec![],
                                      impacted_output.clone(),
            );

        let branches2: Vec<&[D2::Scalar]> = branches2.iter().map(|b| &b[..]).collect();

        // prove preprocessing2
        let (preprocessing2, pp_output2) =
            preprocessing::Proof::new(seed,
                                      &branches2[..],
                                      program2.iter().cloned(),
                                      impacted_input.clone(),
                                      vec![],
            );

        Self {
            fieldswitching_input: impacted_input,
            fieldswitching_output: impacted_output,
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
        async fn preprocessing_verification<D: Domain, D2:Domain>(
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


