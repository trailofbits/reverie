use crate::algebra::{Domain, RingElement};
use serde::{Deserialize, Serialize};
use crate::{Instruction, ConnectionInstruction, preprocessing, online, fieldswitching};
use async_channel::{bounded, Sender, Receiver};
use async_std::sync::Arc;
use async_std::task;
use crate::fieldswitching::util::convert_bit;
use crate::oracle::RandomOracle;
use crate::consts::CONTEXT_ORACLE_ONLINE;
use crate::online::StreamingVerifier;
use std::iter::Cloned;
use std::slice::Iter;

const CHANNEL_CAPACITY: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain, D2: Domain> {
    online1: online::Proof<D>,
    online2: online::Proof<D2>,
    preprocessing1: preprocessing::Proof<D>,
    preprocessing2: preprocessing::Proof<D2>,
    chunks1: Vec<Vec<u8>>,
    chunks2: Vec<Vec<u8>>,
}

impl<D: Domain, D2: Domain> Proof<D, D2> {
    pub(crate) async fn new(
        bind: Option<Vec<u8>>,
        conn_program: Vec<ConnectionInstruction>,
        program1: Vec<Instruction<D::Scalar>>,
        program2: Vec<Instruction<D2::Scalar>>,
        witness: Vec<D::Scalar>,
        branch_index: usize,
        pp: fieldswitching::preprocessing::Proof<D, D2>,
    ) -> Self {
        async fn online_proof<D: Domain, D2: Domain>(
            send1: Sender<Vec<u8>>,
            send2: Sender<Vec<u8>>,
            bind: Option<Vec<u8>>,
            conn_program: Vec<ConnectionInstruction>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            branch_index: usize,
            witness: Arc<Vec<D::Scalar>>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
            pp_output1: preprocessing::PreprocessingOutput<D>,
            pp_output2: preprocessing::PreprocessingOutput<D2>,
            eda_bits: Vec<Vec<D::Sharing>>,
            eda_composed: Vec<D2::Sharing>,
        ) -> Option<(online::Proof<D>, online::Proof<D2>)> {
            let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind.as_ref().map(|x| &x[..]));

            let (branch_1, masked_branches_1, output1) = online::StreamingProver::new_round_1(
                pp_output1.clone(),
                branch_index,
                &mut program1.clone().iter().cloned(),
                &mut witness.clone().iter().cloned(),
                vec![],
                fieldswitching_output.clone(),
                eda_bits.clone(),
                vec![],
                &mut oracle,
            ).await;

            let mut input2 = Vec::new();
            for gate in conn_program {
                match gate {
                    ConnectionInstruction::BToA(_dst, src) => {
                        let mut pow_two = D2::Scalar::ONE;
                        let two = D2::Scalar::ONE + D2::Scalar::ONE;
                        let mut next = D2::Scalar::ZERO;
                        for &_src in src.iter() {
                            next = next + convert_bit::<D, D2>(output1[_src - 4].clone()) * pow_two;
                            pow_two = two * pow_two;
                        }
                        input2.push(next);
                    }
                    _ => {}
                }
            }

            let (branch_2, masked_branches_2, _output2) = online::StreamingProver::new_round_1(
                pp_output2.clone(),
                branch_index,
                program2.clone().iter().cloned(),
                input2.clone().iter().cloned(),
                fieldswitching_input.clone(),
                vec![],
                vec![],
                eda_composed.clone(),
                &mut oracle,
            ).await;

            let omitted = online::StreamingProver::<D>::get_challenge(&mut oracle);

            let (online1, prover1) = online::StreamingProver::new_round_3(pp_output1, branch_1, masked_branches_1, omitted.clone());
            let (online2, prover2) = online::StreamingProver::new_round_3(pp_output2, branch_2, masked_branches_2, omitted.clone());

            prover1
                .stream(send1,
                        program1.iter().cloned(),
                        witness.iter().cloned(),
                        vec![],
                        fieldswitching_output.clone(),
                        eda_bits.clone(),
                        vec![],
                ).await
                .unwrap();
            prover2
                .stream(send2,
                        program2.iter().cloned(),
                        input2.iter().cloned(),
                        fieldswitching_input.clone(),
                        vec![],
                        vec![],
                        eda_composed.clone(),
                ).await
                .unwrap();
            Some((online1, online2))
        }
        // create prover for online phase
        let (send1, recv1) = bounded(CHANNEL_CAPACITY);
        let (send2, recv2) = bounded(CHANNEL_CAPACITY);
        let prover_task = task::spawn(online_proof(
            send1,
            send2,
            bind,
            conn_program.clone(),
            Arc::new(program1.clone()),
            Arc::new(program2.clone()),
            branch_index,
            Arc::new(witness.clone()),
            pp.fieldswitching_input,
            pp.fieldswitching_output,
            pp.pp_output1,
            pp.pp_output2,
            pp.eda_bits,
            pp.eda_composed,
        ));

        // read all chunks from online execution
        let mut chunks1 = Vec::with_capacity(D::ONLINE_REPETITIONS);
        while let Ok(chunk) = recv1.recv().await {
            chunks1.push(chunk)
        }
        let mut chunks2 = Vec::with_capacity(D2::ONLINE_REPETITIONS);
        while let Ok(chunk) = recv2.recv().await {
            chunks2.push(chunk)
        }

        let (online1, online2) = prover_task.await.unwrap();
        Self {
            online1,
            online2,
            preprocessing1: pp.preprocessing1,
            preprocessing2: pp.preprocessing2,
            chunks1,
            chunks2,
        }
    }

    pub async fn verify(&self,
                        bind: Option<Vec<u8>>,
                        program1: Vec<Instruction<D::Scalar>>,
                        program2: Vec<Instruction<D2::Scalar>>,
                        preprocessed: fieldswitching::preprocessing::Output<D, D2>,
                        pp: fieldswitching::preprocessing::Proof<D, D2>,
    ) -> Result<Vec<D2::Scalar>, String> {
        async fn online_verification<D: Domain, D2: Domain>(
            bind: Option<Vec<u8>>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            proof1: online::Proof<D>,
            proof2: online::Proof<D2>,
            preprocessed: fieldswitching::preprocessing::Output<D, D2>,
            recv1: Receiver<Vec<u8>>,
            recv2: Receiver<Vec<u8>>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
        ) -> Result<online::Output<D2>, String> {
            let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind.as_ref().map(|x| &x[..]));

            let verifier1 = online::StreamingVerifier::new(program1.iter().cloned(), proof1);
            let (mut omitted1, _result1) = match verifier1.verify_round_1(recv1, vec![], fieldswitching_output, preprocessed.eda_bits, vec![], &mut oracle).await {
                Ok(out) => out,
                Err(e) => return Err(e),
            };

            let verifier2 = online::StreamingVerifier::new(program2.iter().cloned(), proof2);
            let (mut omitted2, result2) = match verifier2.verify_round_1(recv2, fieldswitching_input, vec![], vec![], preprocessed.eda_composed, &mut oracle).await {
                Ok(out) => out,
                Err(e) => return Err(e),
            };

            if !<StreamingVerifier<D, Cloned<Iter<Instruction<D::Scalar>>>>>::verify_omitted(&mut oracle, omitted1) {
                return Err(String::from("omitted values for proof 1 are incorrect"));
            }
            if !<StreamingVerifier<D2, Cloned<Iter<Instruction<D2::Scalar>>>>>::verify_omitted(&mut oracle, omitted2) {
                return Err(String::from("omitted values for proof 2 are incorrect"));
            }

            return Ok(result2);
        }

        // verify the online execution
        let (send1, recv1) = bounded(CHANNEL_CAPACITY);
        let (send2, recv2) = bounded(CHANNEL_CAPACITY);
        let task_online = task::spawn(online_verification(
            bind,
            Arc::new(program1.clone()),
            Arc::new(program2.clone()),
            self.online1.clone(),
            self.online2.clone(),
            preprocessed.clone(),
            recv1,
            recv2,
            pp.fieldswitching_input.clone(),
            pp.fieldswitching_output.clone(),
        ));

        // send proof to the online verifier
        for chunk in self.chunks1.clone().into_iter() {
            if let Err(_e) = send1.send(chunk).await {
                return Err(String::from("Failed to send chunk to the verifier"));
            }
        }

        // send proof to the online verifier
        for chunk in self.chunks2.clone().into_iter() {
            if let Err(_e) = send2.send(chunk).await {
                return Err(String::from("Failed to send chunk to the verifier"));
            }
        }

        match task_online.await {
            //TODO(gvl): both preprocessed checking
            Ok(out) => Ok(out.check(&preprocessed.output2).ok_or_else(|| {
                String::from("Online task output did not match preprocessing output")
            })?),
            Err(_e) => Err(String::from("Online verification task failed")),
        }
    }
}