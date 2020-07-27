use crate::algebra::Domain;
use crate::online;
use crate::preprocessing;
use crate::Instruction;

use rand::rngs::OsRng;
use rand_core::RngCore;

use async_channel::bounded;
use async_std::task;

use serde::{Deserialize, Serialize};

const CHUNK_SIZE: usize = 10_000_000;
const CHANNEL_CAPACITY: usize = 100;

// simplified interface
#[derive(Deserialize, Serialize)]
pub struct Proof<
    D: Domain,
    const P: usize,
    const PT: usize,
    const R: usize,
    const RT: usize,
    const H: usize,
> {
    preprocessing: preprocessing::Proof<D, P, PT, R, RT, H>,
    online: online::Proof<D, H, P, PT>,
    chunks: Vec<Vec<u8>>,
}

impl<
        D: Domain,
        const P: usize,
        const PT: usize,
        const R: usize,
        const RT: usize,
        const H: usize,
    > Proof<D, P, PT, R, RT, H>
{
    async fn new_async(program: Vec<Instruction<D::Scalar>>, witness: Vec<D::Scalar>) -> Self {
        // prove preprocessing
        let mut seed: [u8; 16] = [0; 16];
        OsRng.fill_bytes(&mut seed);
        let (preprocessing, pp_output) =
            preprocessing::Proof::new(seed, program.iter().cloned(), CHUNK_SIZE);

        // create prover for online phase
        let (online, prover) = online::StreamingProver::new(
            pp_output,
            program.iter().cloned(),
            witness.iter().cloned(),
        );
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let prover_task =
            task::spawn(prover.stream(send, program.into_iter(), witness.into_iter()));

        // read all chunks from online execution
        let mut chunks = vec![];
        while let Ok(chunk) = recv.recv().await {
            chunks.push(chunk)
        }

        // should never fail
        prover_task.await.unwrap();
        Proof {
            preprocessing,
            online,
            chunks,
        }
    }

    async fn verify_async(&self, program: Vec<Instruction<D::Scalar>>) -> Option<Vec<D::Scalar>> {
        // verify pre-processing
        let pp_hashes = self.preprocessing.verify(program.iter().cloned())?;

        // verify the online execution
        let verifier = online::StreamingVerifier::new(program.into_iter(), self.online.clone());
        let (send, recv) = bounded(CHANNEL_CAPACITY);
        let online_task = task::spawn(verifier.verify(recv));
        for chunk in self.chunks.clone().into_iter() {
            send.send(chunk).await.ok()?;
        }

        // check that online execution matches preprocessing
        online_task.await?.check(&pp_hashes)
    }

    pub fn new(program: &[Instruction<D::Scalar>], witness: &[D::Scalar]) -> Self {
        task::block_on(Self::new_async(program.to_owned(), witness.to_owned()))
    }

    pub fn verify(&self, program: &[Instruction<D::Scalar>]) -> Option<Vec<D::Scalar>> {
        task::block_on(self.verify_async(program.to_owned()))
    }
}
