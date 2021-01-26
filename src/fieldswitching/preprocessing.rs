use crate::algebra::Domain;
use std::marker::PhantomData;
use crate::{Instruction, ConnectionInstruction, preprocessing};
use crate::crypto::KEY_SIZE;
use rand::rngs::OsRng;
use rand::RngCore;
use crate::preprocessing::PreprocessingOutput;

pub struct Proof<D: Domain, D2: Domain> {
    preprocessing1: preprocessing::Proof<D>,
    pp_output1: PreprocessingOutput<D>,
    preprocessing2: preprocessing::Proof<D2>,
    pp_output2: PreprocessingOutput<D2>,
}

impl<D: Domain, D2: Domain> Proof<D, D2> {
    pub(crate) async fn new(
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
            preprocessing1,
            pp_output1,
            preprocessing2,
            pp_output2,
        }
    }
}
