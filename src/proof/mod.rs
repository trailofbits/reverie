use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::hash::{Hash, Hasher, HASH_SIZE};
use crate::crypto::prg::{Key, KEY_SIZE};
use crate::crypto::ro::RandomOracle;
use crate::interpreter::{CombineInstance, Instance};
use crate::transcript::{ProverTranscript, VerifierTranscriptOnline, VerifierTranscriptPreprocess};
use crate::{
    CombineOperation, ONLINE_REPS, PACKED, PACKED_REPS, PLAYERS, PREPROCESSING_REPS, TOTAL_REPS,
};

const CTX_CHALLENGE: &str = "random-oracle challenge";

// parallelize in release mode only (for easier debugging)
#[cfg(not(debug_assertions))]
use rayon::prelude::*;

// parallelize in release mode only (for easier debugging)
#[cfg(debug_assertions)]
macro_rules! parallel_iter {
    ($v:expr) => {
        $v.into_iter()
    };
}

// parallelize in release mode only (for easier debugging)
#[cfg(not(debug_assertions))]
macro_rules! parallel_iter {
    ($v:expr) => {
        $v.into_par_iter()
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub(crate) struct OpenOnline {
    pub omit: u8,              // which player is unopened.
    pub seeds: [Key; PLAYERS], // randomness of opened players (unopened player has zero key)
    pub recons: Vec<u8>,       // packed reconstructions
    pub corrs: Vec<u8>,        // packed corrections
    pub inputs: Vec<u8>,       // packed masked inputs
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub(crate) struct OpenPreprocessing {
    pub seed: Key,                    // seed to derive per-player random tapes
    pub comm_online: [u8; HASH_SIZE], // commitment to the online phase
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
struct ProofSingle {
    online: Vec<OpenOnline>,
    preprocessing: Vec<OpenPreprocessing>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Proof {
    comm: [u8; HASH_SIZE],
    gf2: ProofSingle,
    z64: ProofSingle,
}

fn random_int(ro: &mut RandomOracle, bound: usize) -> usize {
    let mut buf = [0u8; 16];
    ro.fill(&mut buf);
    (u128::from_le_bytes(buf) % bound as u128) as usize
}

pub(crate) fn challenge_to_opening(challenge: &[u8; HASH_SIZE]) -> HashMap<usize, usize> {
    let mut ro = RandomOracle::new(CTX_CHALLENGE, challenge);
    let mut online: HashMap<usize, usize> = HashMap::new();
    while online.len() < ONLINE_REPS {
        let rept_idx = random_int(&mut ro, TOTAL_REPS);
        let omit_idx = random_int(&mut ro, PLAYERS);
        online.insert(rept_idx, omit_idx);
    }
    online
}

pub(crate) fn opening_to_packed(open: &HashMap<usize, usize>) -> Vec<[usize; PLAYERS]> {
    debug_assert_eq!(open.len(), ONLINE_REPS);
    let mut packed: Vec<[usize; PACKED]> = vec![];
    for i in 0..PACKED_REPS {
        let mut pack: [usize; PACKED] = [PLAYERS; PACKED];
        for (j, packed) in pack.iter_mut().enumerate().take(PACKED) {
            let idx = i * PACKED + j;
            if open.contains_key(&idx) {
                debug_assert!(open[&idx] < PLAYERS);
                *packed = open[&idx];
            }
        }
        packed.push(pack);
    }
    packed
}

pub(crate) fn combine_hashes<'a, I: Iterator<Item = &'a Hash>>(hashes: I) -> Hash {
    let mut hasher = Hasher::new();
    for hash in hashes {
        hasher.update(hash.as_bytes());
    }
    hasher.finalize()
}

impl ProofSingle {
    pub fn check_format(&self) -> bool {
        self.online.len() == ONLINE_REPS && self.preprocessing.len() == PREPROCESSING_REPS
    }
}

// The collects are necessary in release mode
#[allow(clippy::needless_collect)]
impl Proof {
    pub fn new(
        circuit: Arc<Vec<CombineOperation>>, // combined circuit
        wit_gf2: Arc<Vec<bool>>,             // gf2 witness
        wit_z64: Arc<Vec<u64>>,              // z64 witness
        wire_counts: (usize, usize),         // Sizes for instances
    ) -> Self {
        let (z64_count, gf2_count) = wire_counts;
        // execute every instance in parallel
        let instances: Vec<([Hash; PACKED], (_, _))> =
            parallel_iter!((0..PACKED_REPS).collect::<Vec<usize>>())
                .map(|_i| {
                    // generate key-material for each instance in the batch
                    let mut keys = [[0u8; KEY_SIZE]; PACKED];
                    for key in keys.iter_mut().take(PACKED) {
                        OsRng.fill_bytes(key);
                    }

                    //
                    let instance_gf2 = Instance::new(
                        ProverTranscript::new(wit_gf2.iter().map(|b| (*b).into()), keys),
                        gf2_count,
                    );

                    //
                    let instance_z64 = Instance::new(
                        ProverTranscript::new(wit_z64.iter().map(|b| (*b).into()), keys),
                        z64_count,
                    );

                    // process every instruction in the circuit
                    let mut ins = CombineInstance::new(instance_gf2, instance_z64);
                    for op in circuit.iter() {
                        ins.step(op);
                    }
                    let hash = ins.hash();
                    let (gf2_ins, z64_ins) = ins.split();
                    (hash, (gf2_ins.extract(), z64_ins.extract()))
                })
                .collect();

        // compute challenge
        let mut comms = vec![];
        let mut transcripts = vec![];
        for (hash, extractions) in instances.into_iter() {
            comms.extend(&hash);
            transcripts.push(extractions);
        }

        // commit to transcript states
        let comm = combine_hashes(comms.iter());

        // ask random oracle which players to open
        let open = challenge_to_opening(comm.as_bytes());
        let packed_open = opening_to_packed(&open);

        debug_assert_eq!(packed_open.len(), PACKED_REPS);
        debug_assert_eq!(transcripts.len(), PACKED_REPS);

        // pair the transcripts with the players to open
        let ext: Vec<(_, _)> = transcripts
            .into_iter()
            .zip(packed_open.into_iter())
            .collect();

        #[cfg(debug_assertions)]
        let ext = ext.into_iter();

        #[cfg(not(debug_assertions))]
        let ext = ext.into_par_iter();

        // extract in parallel
        #[allow(clippy::type_complexity)] // I tried to fix this and it panic'd rustc lol
        let ext: Vec<(
            (Vec<OpenOnline>, Vec<OpenPreprocessing>),
            (Vec<OpenOnline>, Vec<OpenPreprocessing>),
        )> = ext
            .map(|((gf2, z64), open)| (gf2.extract(open), z64.extract(open)))
            .collect();

        // collect all the online/preprocessing openings into a single vector

        let mut gf2: ProofSingle = ProofSingle {
            online: vec![],
            preprocessing: vec![],
        };

        let mut z64: ProofSingle = ProofSingle {
            online: vec![],
            preprocessing: vec![],
        };

        for rep in ext.into_iter() {
            gf2.online.extend(rep.0 .0.into_iter());
            gf2.preprocessing.extend(rep.0 .1.into_iter());
            z64.online.extend(rep.1 .0.into_iter());
            z64.preprocessing.extend(rep.1 .1.into_iter());
        }

        Proof {
            comm: comm.into(),
            gf2,
            z64,
        }
    }

    pub fn verify(&self, circuit: Arc<Vec<CombineOperation>>, wire_counts: (usize, usize)) -> bool {
        if !self.gf2.check_format() {
            return false;
        }
        if !self.z64.check_format() {
            return false;
        }

        let (z64_count, gf2_count) = wire_counts;

        let online_reps: Vec<(&[OpenOnline], &[OpenOnline])> = self
            .gf2
            .online
            .chunks_exact(PACKED)
            .zip(self.z64.online.chunks_exact(PACKED))
            .collect();

        let preprocessing_reps: Vec<(&[OpenPreprocessing], &[OpenPreprocessing])> = self
            .gf2
            .preprocessing
            .chunks_exact(PACKED)
            .zip(self.z64.preprocessing.chunks_exact(PACKED))
            .collect();

        // prepare all the online repetitions (in batches of 8)
        let online_reps = parallel_iter!(online_reps).map(|(gf2, z64)| {
            let instance_gf2 = Instance::new(
                VerifierTranscriptOnline::new(<&[_; PACKED]>::try_from(gf2).unwrap()),
                gf2_count,
            );
            let instance_z64 = Instance::new(
                VerifierTranscriptOnline::new(<&[_; PACKED]>::try_from(z64).unwrap()),
                z64_count,
            );
            let mut ins = CombineInstance::new(instance_gf2, instance_z64);
            for op in circuit.iter() {
                ins.step(op);
            }
            ins.hash()
        });

        // prepare all the preprocessing repetitions (in batches of 8)
        let preprocessing_reps = parallel_iter!(preprocessing_reps).map(|(gf2, z64)| {
            let instance_gf2 = Instance::new(
                VerifierTranscriptPreprocess::new(<&[_; PACKED]>::try_from(gf2).unwrap()),
                gf2_count,
            );
            let instance_z64 = Instance::new(
                VerifierTranscriptPreprocess::new(<&[_; PACKED]>::try_from(z64).unwrap()),
                z64_count,
            );
            let mut ins = CombineInstance::new(instance_gf2, instance_z64);
            for op in circuit.iter() {
                ins.step(op);
            }
            ins.hash()
        });

        // run all the executions
        let reps: Vec<[Hash; PACKED]> = online_reps.chain(preprocessing_reps).collect();

        // flat vector of array of hashes to a single vector of hashes
        let mut hashes: Vec<Hash> = Vec::with_capacity(TOTAL_REPS);
        for arr in reps.iter() {
            hashes.extend(arr);
        }

        // order the repetitions
        let open = challenge_to_opening(&self.comm);
        let mut online_hashes = hashes[..ONLINE_REPS].iter();
        let mut preprocessing_hashes = hashes[ONLINE_REPS..].iter();
        let mut ordered_hashes: Vec<&Hash> = Vec::with_capacity(TOTAL_REPS);
        for i in 0..TOTAL_REPS {
            if open.contains_key(&i) {
                ordered_hashes.push(online_hashes.next().unwrap())
            } else {
                ordered_hashes.push(preprocessing_hashes.next().unwrap())
            }
        }

        // join all the hashes into a single hash (fed to the RO)
        let comm = combine_hashes(ordered_hashes.into_iter());
        comm.as_bytes() == &self.comm
    }
}

#[cfg(test)]
mod tests {
    use bincode;
    use test::Bencher;

    use super::*;
    use crate::Operation;

    #[bench]
    fn bench_prover(b: &mut Bencher) {
        #[cfg(not(debug_assertions))]
        let circuit = {
            let mut circuit = vec![
                CombineOperation::GF2(Operation::Input(0)),
                CombineOperation::GF2(Operation::Input(1)),
            ];
            circuit.append(&mut vec![
                CombineOperation::GF2(Operation::Mul(2, 0, 1));
                100_000
            ]);
            circuit
        };

        #[cfg(debug_assertions)]
        let circuit = vec![
            CombineOperation::GF2(Operation::Input(0)),
            CombineOperation::GF2(Operation::Input(1)),
            CombineOperation::GF2(Operation::Mul(2, 0, 1)),
        ];

        let circuit = Arc::new(circuit);

        let wit_gf2 = Arc::new(vec![true, true]);

        let wit_z64 = Arc::new(vec![0]);

        b.iter(|| {
            Proof::new(
                circuit.clone(),
                wit_gf2.clone(),
                wit_z64.clone(),
                (128, 128),
            )
        });
    }

    #[bench]
    fn bench_verifier(b: &mut Bencher) {
        #[cfg(not(debug_assertions))]
        let circuit = {
            let mut circuit = vec![
                CombineOperation::GF2(Operation::Input(0)),
                CombineOperation::GF2(Operation::Input(1)),
            ];
            circuit.append(&mut vec![
                CombineOperation::GF2(Operation::Mul(2, 0, 1));
                100_000
            ]);
            circuit
        };

        #[cfg(debug_assertions)]
        let circuit = vec![
            CombineOperation::GF2(Operation::Input(0)),
            CombineOperation::GF2(Operation::Input(1)),
            CombineOperation::GF2(Operation::Mul(2, 0, 1)),
        ];

        let circuit = Arc::new(circuit);

        let wit_gf2 = Arc::new(vec![true, true]);

        let wit_z64 = Arc::new(vec![0]);

        let proof = Proof::new(
            circuit.clone(),
            wit_gf2.clone(),
            wit_z64.clone(),
            (128, 128),
        );

        b.iter(|| {
            println!("1");
            assert!(proof.verify(circuit.clone(), (128, 128)));
        });
    }

    #[test]
    fn test_prover_gf2_mul() {
        let mut circuit = vec![];

        for _ in 2..66 {
            circuit.push(CombineOperation::GF2(Operation::Input(1)))
        }

        circuit.push(CombineOperation::B2A(0, 2));

        circuit.extend(
            vec![
                CombineOperation::GF2(Operation::Input(0)),
                CombineOperation::GF2(Operation::Input(1)),
                CombineOperation::GF2(Operation::Mul(2, 0, 1)),
                CombineOperation::GF2(Operation::Add(3, 0, 1)),
                CombineOperation::GF2(Operation::Mul(2, 2, 3)),
            ]
            .into_iter(),
        );

        let circuit = Arc::new(circuit);
        let wit_gf2 = Arc::new(vec![true; 128]);
        let wit_z64 = Arc::new(vec![0]);

        let proof = Proof::new(circuit.clone(), wit_gf2, wit_z64, (128, 128));

        println!("size = {}", bincode::serialize(&proof).unwrap().len());

        assert!(proof.verify(circuit, (128, 128)));
    }
}
