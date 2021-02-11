use crate::algebra::{Domain, Packable, RingElement};
use crate::consts::CONTEXT_ORACLE_ONLINE;
use crate::crypto::{Hash, MerkleSetProof, TreePrf};
use crate::fieldswitching::preprocessing::{
    FsPreprocessingRun, PartialPreprocessingExecution, PreprocessingExecution,
};
use crate::fieldswitching::util::{convert_bit, FullProgram};
use crate::online::{StreamingProver, StreamingVerifier};
use crate::oracle::RandomOracle;
use crate::{fieldswitching, online, preprocessing, ConnectionInstruction, Instruction};
use async_channel::{bounded, Receiver};
use async_std::sync::Arc;
use async_std::task;
use serde::{Deserialize, Serialize};
use std::iter::Cloned;
use std::marker::PhantomData;
use std::slice::Iter;

const CHANNEL_CAPACITY: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain, D2: Domain> {
    online1: online::Proof<D>,
    online2: online::Proof<D2>,
    runs: Vec<OnlineRun<D, D2>>,
    chunks1: Vec<Vec<u8>>,
    chunks2: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnlineRun<D: Domain, D2: Domain> {
    open: TreePrf,
    // randomness for opened players
    commitment: Hash,
    // commitment for hidden preprocessing player
    corrections: Vec<u8>,
    run1: super::super::online::OnlineRun<D>,
    run2: super::super::online::OnlineRun<D2>,
}

impl<D: Domain, D2: Domain> Proof<D, D2> {
    pub async fn new<'a>(
        bind: Option<Vec<u8>>,
        conn_program: Vec<ConnectionInstruction>,
        program1: Vec<Instruction<D::Scalar>>,
        program2: Vec<Instruction<D2::Scalar>>,
        witness: Vec<D::Scalar>,
        branch_index: usize,
        pp: fieldswitching::preprocessing::PreprocessingOutput<D, D2>,
    ) -> Self {
        async fn online_proof<D: Domain, D2: Domain>(
            program: FullProgram<D, D2>,
            branch_index: usize,
            witness: Arc<Vec<D::Scalar>>,
            run: FsPreprocessingRun<D, D2>,
            run_index: usize,
            pp_output1: preprocessing::PreprocessingOutput<D>,
            pp_output2: preprocessing::PreprocessingOutput<D2>,
        ) -> Option<(
            Vec<D::Scalar>,
            Vec<D2::Scalar>,
            Vec<(Vec<u8>, MerkleSetProof)>,
            Vec<(Vec<u8>, MerkleSetProof)>,
            Vec<D2::Scalar>,
            Vec<[u8; 32]>,
        )> {
            let run1 = pp_output1.hidden[run_index].clone();
            let mut oracle_inputs = Vec::new();
            let (branch_1, masked_branches_1, output1, mut _oracle_inputs) =
                online::StreamingProver::do_runs_round_1(
                    pp_output1.clone(),
                    branch_index,
                    &mut program.1.clone().iter().cloned(),
                    &mut witness.clone().iter().cloned(),
                    (vec![], run.fieldswitching_output.clone()),
                    (run.eda_bits.clone(), vec![]),
                    vec![run1],
                )
                .await;
            oracle_inputs.append(&mut _oracle_inputs);

            let mut input2 = Vec::new();
            for gate in program.0 {
                match gate {
                    ConnectionInstruction::BToA(_dst, src) => {
                        let mut pow_two = D2::Scalar::ONE;
                        let two = D2::Scalar::ONE + D2::Scalar::ONE;
                        let mut next = D2::Scalar::ZERO;
                        for &_src in src.iter() {
                            next = next + convert_bit::<D, D2>(output1[_src - 4]) * pow_two;
                            pow_two = two * pow_two;
                        }
                        input2.push(next);
                    }
                    ConnectionInstruction::AToB(_dst, _src) => {}
                }
            }

            let run2 = pp_output2.hidden[run_index].clone();
            let (branch_2, masked_branches_2, _output2, mut _oracle_inputs) =
                online::StreamingProver::do_runs_round_1(
                    pp_output2.clone(),
                    branch_index,
                    &mut program.2.clone().iter().cloned(),
                    &mut input2.clone().iter().cloned(),
                    (run.fieldswitching_input.clone(), vec![]),
                    (vec![], run.eda_composed.clone()),
                    vec![run2],
                )
                .await;
            oracle_inputs.append(&mut _oracle_inputs);
            // println!("output: {:?}", _output2);

            Some((
                branch_1,
                branch_2,
                masked_branches_1,
                masked_branches_2,
                input2,
                oracle_inputs,
            ))
        }
        // create prover for online phase
        let mut prover_tasks = Vec::new();

        let mut fieldswitching_input = Vec::new();
        let mut fieldswitching_output = Vec::new();
        let mut eda_bits = Vec::new();
        let mut eda_composed = Vec::new();
        for (run_index, run) in pp.hidden.iter().cloned().enumerate() {
            prover_tasks.push(task::spawn(online_proof(
                (
                    conn_program.clone(),
                    Arc::new(program1.clone()),
                    Arc::new(program2.clone()),
                ),
                branch_index,
                Arc::new(witness.clone()),
                run.clone(),
                run_index,
                pp.pp_output1.clone(),
                pp.pp_output2.clone(),
            )));
            fieldswitching_input = run.fieldswitching_input.clone();
            fieldswitching_output = run.fieldswitching_output.clone();
            eda_bits.push(run.eda_bits.clone());
            eda_composed.push(run.eda_composed.clone());
        }

        let mut branch_1 = Vec::new();
        let mut branch_2 = Vec::new();
        let mut masked_branches_1 = Vec::new();
        let mut masked_branches_2 = Vec::new();
        let mut input2 = Vec::new();
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind.as_ref().map(|x| &x[..]));
        for t in prover_tasks {
            let (
                mut _branch_1,
                mut _branch_2,
                mut _masked_branches_1,
                mut _masked_branches_2,
                _input2,
                oracle_inputs,
            ) = t.await.unwrap();
            branch_1.append(&mut _branch_1);
            branch_2.append(&mut _branch_2);
            masked_branches_1.append(&mut _masked_branches_1);
            masked_branches_2.append(&mut _masked_branches_2);
            input2 = _input2;
            for oracle_feed in oracle_inputs {
                // println!("prover: {:?}", oracle_feed);
                oracle.feed(&oracle_feed);
            }
        }

        let omitted = online::StreamingProver::<D>::get_challenge(&mut oracle);

        let (online1, _prover1) = online::StreamingProver::new_round_3(
            pp.pp_output1.clone(),
            Arc::new(branch_1.clone()),
            masked_branches_1.clone(),
            omitted.clone(),
        );
        let prover1 = StreamingProver {
            branch: Arc::new(branch_1),
            omitted: omitted.clone(),
            preprocessing: pp.pp_output1.clone(),
        };
        let (online2, _prover2) = online::StreamingProver::new_round_3(
            pp.pp_output2.clone(),
            Arc::new(branch_2.clone()),
            masked_branches_2.clone(),
            omitted.clone(),
        );
        let prover2 = StreamingProver {
            branch: Arc::new(branch_2),
            omitted: omitted.clone(),
            preprocessing: pp.pp_output2.clone(),
        };

        let (send1, recv1) = bounded(CHANNEL_CAPACITY);
        let (send2, recv2) = bounded(CHANNEL_CAPACITY);
        prover1
            .stream(
                send1,
                program1.iter().cloned(),
                witness.iter().cloned(),
                (vec![], fieldswitching_output.clone()),
                eda_bits.clone(),
                vec![],
            )
            .await
            .unwrap();
        prover2
            .stream(
                send2,
                program2.iter().cloned(),
                input2.iter().cloned(),
                (fieldswitching_input.clone(), vec![]),
                vec![],
                eda_composed.clone(),
            )
            .await
            .unwrap();

        // read all chunks from online execution
        let mut chunks1 = Vec::with_capacity(D::ONLINE_REPETITIONS);
        let mut chunks2 = Vec::with_capacity(D2::ONLINE_REPETITIONS);
        while let Ok(chunk) = recv1.recv().await {
            chunks1.push(chunk)
        }
        while let Ok(chunk) = recv2.recv().await {
            chunks2.push(chunk)
        }
        Self {
            // omit player from TreePRF and provide pre-processing commitment
            runs: omitted
                .iter()
                .cloned()
                .zip(pp.hidden.clone())
                .zip(pp.pp_output1.hidden.iter())
                .zip(pp.pp_output2.hidden.iter())
                .zip(masked_branches_1.into_iter())
                .zip(masked_branches_2.into_iter())
                .map(
                    |(((((omit, run), run1), run2), (branch1, proof1)), (branch2, proof2))| {
                        let tree1 = TreePrf::new(D::PLAYERS, run1.seed);
                        let run1 = super::super::online::OnlineRun {
                            proof: proof1,
                            branch: branch1,
                            commitment: run1.commitments[omit].clone(),
                            open: tree1.puncture(omit),
                            _ph: PhantomData,
                        };
                        let tree2 = TreePrf::new(D::PLAYERS, run2.seed);
                        let run2 = super::super::online::OnlineRun {
                            proof: proof2,
                            branch: branch2,
                            commitment: run2.commitments[omit].clone(),
                            open: tree2.puncture(omit),
                            _ph: PhantomData,
                        };
                        let tree = TreePrf::new(D::PLAYERS, run.seed);
                        let mut corrections: Vec<u8> = Vec::new();
                        Packable::pack(&mut corrections, run.corrections.iter()).unwrap();
                        // println!("omit: {:?}", omit);
                        OnlineRun {
                            open: tree.puncture(omit),
                            commitment: run.commitments[omit].clone(),
                            corrections,
                            run1,
                            run2,
                        }
                    },
                )
                .collect(),
            online1,
            online2,
            chunks1,
            chunks2,
        }
    }

    pub async fn verify(
        &self,
        bind: Option<Vec<u8>>,
        conn_program: Vec<ConnectionInstruction>,
        program1: Vec<Instruction<D::Scalar>>,
        program2: Vec<Instruction<D2::Scalar>>,
    ) -> Result<Vec<D2::Scalar>, String> {
        async fn online_verification<D: Domain, D2: Domain>(
            program: FullProgram<D, D2>,
            run: OnlineRun<D, D2>,
            run_index: usize,
            proof1: online::Proof<D>,
            proof2: online::Proof<D2>,
            mut recv1: Receiver<Vec<u8>>,
            mut recv2: Receiver<Vec<u8>>,
        ) -> Result<(Vec<[u8; 32]>, Vec<usize>, Vec<usize>, Vec<D2::Scalar>, Hash), String>
        {
            let mut execution = PartialPreprocessingExecution::<D, D2>::new(run.open);

            let mut eda_composed = Vec::new();
            let mut eda_bits = Vec::new();
            let mut corrections = Vec::new();
            match D2::Batch::unpack(&mut corrections, &run.corrections) {
                Ok(_) => (),
                Err(e) => return Err(format!("{:?}", e)),
            };
            execution.process(
                &program.0[..],
                &corrections[..],
                &mut eda_bits,
                &mut eda_composed,
            );

            let (fieldswitching_input, fieldswitching_output) =
                PreprocessingExecution::<D, D2>::get_fs_input_output(&program.0[..]);

            let verifier1 =
                online::StreamingVerifier::new(program.1.iter().cloned(), proof1.clone());
            let run1 = verifier1.proof.runs[run_index].clone();
            let (mut oracle_feed1, omitted1, _result1) = match verifier1
                .do_verify_round_1(&mut recv1, (vec![], fieldswitching_output), vec![run1])
                .await
            {
                Ok(out) => out,
                Err(e) => return Err(e),
            };

            let verifier2 =
                online::StreamingVerifier::new(program.2.iter().cloned(), proof2.clone());
            let run2 = verifier2.proof.runs[run_index].clone();
            let (mut oracle_feed2, omitted2, result2) = match verifier2
                .do_verify_round_1(&mut recv2, (fieldswitching_input, vec![]), vec![run2])
                .await
            {
                Ok(out) => out,
                Err(e) => return Err(e),
            };
            oracle_feed1.append(&mut oracle_feed2);

            return Ok((
                oracle_feed1,
                omitted1,
                omitted2,
                result2.result,
                execution.commitment(&run.commitment),
            ));
        }

        assert_eq!(self.runs.len(), self.online1.runs.len());
        assert_eq!(self.runs.len(), self.online2.runs.len());

        // verify the online execution

        let mut tasks = Vec::new();
        let mut senders1 = Vec::new();
        let mut senders2 = Vec::new();
        for (run_index, run) in self.runs.iter().cloned().enumerate() {
            let (send1, recv1) = bounded(CHANNEL_CAPACITY);
            let (send2, recv2) = bounded(CHANNEL_CAPACITY);
            tasks.push(task::spawn(online_verification(
                (
                    conn_program.clone(),
                    Arc::new(program1.clone()),
                    Arc::new(program2.clone()),
                ),
                run,
                run_index,
                self.online1.clone(),
                self.online2.clone(),
                recv1,
                recv2,
            )));
            senders1.push(send1);
            senders2.push(send2);
        }

        // send proof to the online verifier
        for (chunk, send1) in self
            .chunks1
            .clone()
            .into_iter()
            .zip(senders1.iter().cloned())
        {
            if let Err(_e) = send1.send(chunk.clone()).await {
                return Err(String::from("Failed to send chunk to the verifier"));
            }
        }

        // send proof to the online verifier
        for (chunk, send2) in self
            .chunks2
            .clone()
            .into_iter()
            .zip(senders2.iter().cloned())
        {
            if let Err(_e) = send2.send(chunk.clone()).await {
                return Err(String::from("Failed to send chunk to the verifier"));
            }
        }

        let mut omitted1 = Vec::new();
        let mut omitted2 = Vec::new();
        let mut output = Vec::new();
        let mut oracle = RandomOracle::new(CONTEXT_ORACLE_ONLINE, bind.as_ref().map(|x| &x[..]));
        for t in tasks {
            let result = t.await;
            if result.is_err() {
                return Err(result.err().unwrap());
            }
            let (oracle_feed, mut _omitted1, mut _omitted2, _result, _commitment) = result.unwrap();
            omitted1.append(&mut _omitted1);
            omitted2.append(&mut _omitted2);
            output = _result;
            // TODO(gvl): Why is this not the case?
            // if output != _result {
            //     println!("output: {:?}", output);
            //     println!("output: {:?}", _result);
            //     return Err(String::from("results are inconsistent between rounds"));
            // }
            for feed in oracle_feed {
                // println!("verifier: {:?}", feed);
                oracle.feed(&feed);
            }
            // oracle.feed(commitment.as_bytes());
        }

        if !<StreamingVerifier<D, Cloned<Iter<Instruction<D::Scalar>>>>>::verify_omitted(
            &mut oracle,
            omitted1,
        ) {
            return Err(String::from("omitted values for proof 1 are incorrect"));
        }
        if !<StreamingVerifier<D2, Cloned<Iter<Instruction<D2::Scalar>>>>>::verify_omitted(
            &mut oracle,
            omitted2,
        ) {
            return Err(String::from("omitted values for proof 2 are incorrect"));
        }

        //TODO(gvl): both preprocessed checking
        // Ok(out) => Ok(out.check(&preprocessed.output2).ok_or_else(|| {
        //     String::from("Online task output did not match preprocessing output")
        // })?),

        Ok(output)
    }
}
