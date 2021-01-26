use crate::algebra::{Domain, RingElement};
use serde::{Deserialize, Serialize};
use crate::{Instruction, ConnectionInstruction, preprocessing, online, fieldswitching};
use async_channel::{bounded, Sender, Receiver};
use async_std::sync::Arc;
use async_std::task;
use crate::fieldswitching::util::convert_bit;

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
        ) -> Option<(online::Proof<D>, online::Proof<D2>)> {
            let (online1, prover1) = online::StreamingProver::new(
                bind.as_ref().map(|x| &x[..]),
                pp_output1,
                branch_index,
                program1.clone().iter().cloned(),
                witness.clone().iter().cloned(),
                vec![],
                fieldswitching_output.clone(),
            )
                .await;
            let output1 = prover1
                .stream(send1,
                        program1.iter().cloned(),
                        witness.iter().cloned(),
                        vec![],
                        fieldswitching_output.clone(),
                ).await
                .unwrap();

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

            let (online2, prover2) = online::StreamingProver::new(
                bind.as_ref().map(|x| &x[..]),
                pp_output2,
                branch_index,
                program2.clone().iter().cloned(),
                input2.clone().iter().cloned(),
                fieldswitching_input.clone(),
                vec![],
            )
                .await;
            prover2
                .stream(send2,
                        program2.iter().cloned(),
                        input2.iter().cloned(),
                        fieldswitching_input.clone(),
                        vec![],
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
                        preprocessed1: preprocessing::Output<D>,
                        preprocessed2: preprocessing::Output<D2>,
                        pp: fieldswitching::preprocessing::Proof<D, D2>,
    ) -> Result<Vec<D2::Scalar>, String> {
        async fn online_verification<D: Domain, D2: Domain>(
            bind: Option<Vec<u8>>,
            program1: Arc<Vec<Instruction<D::Scalar>>>,
            program2: Arc<Vec<Instruction<D2::Scalar>>>,
            proof1: online::Proof<D>,
            proof2: online::Proof<D2>,
            preprocessed1: preprocessing::Output<D>,
            recv1: Receiver<Vec<u8>>,
            recv2: Receiver<Vec<u8>>,
            fieldswitching_input: Vec<usize>,
            fieldswitching_output: Vec<Vec<usize>>,
        ) -> Result<online::Output<D2>, String> {
            let verifier1 = online::StreamingVerifier::new(program1.iter().cloned(), proof1);
            let result1 = verifier1.verify(bind.as_ref().map(|x| &x[..]), recv1, vec![], fieldswitching_output).await;
            let _possible_err = match result1 {
                Ok(out) => Ok(out
                    .check(&preprocessed1).ok_or_else(|| {
                    String::from("Online task output did not match preprocessing output")
                })?),
                Err(_e) => Err(String::from("Online verification task failed")),
            }; //TODO(gvl): output err if needed
            let verifier2 = online::StreamingVerifier::new(program2.iter().cloned(), proof2);
            verifier2.verify(bind.as_ref().map(|x| &x[..]), recv2, fieldswitching_input, vec![]).await
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
            preprocessed1,
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
            Ok(out) => Ok(out.check(&preprocessed2).ok_or_else(|| {
                String::from("Online task output did not match preprocessing output")
            })?),
            Err(_e) => Err(String::from("Online verification task failed")),
        }
    }
}