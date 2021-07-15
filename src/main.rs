#![allow(dead_code)]
#![allow(unused_imports)]

mod witness;

use rand::rngs::OsRng;
use rand::Rng;

use async_std::task;

use clap::{App, Arg};
use reverie::algebra::*;
use reverie::crypto::prg::KEY_SIZE;
use reverie::interpreter::{CombineInstance, Instance};
use reverie::proof::Proof;
use reverie::transcript::ProverTranscript;
use reverie::PACKED;
use reverie::{evaluate_composite_program, largest_wires};
use reverie::{CombineOperation, Operation};

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::process::exit;

use num_traits::Zero;
use std::marker::PhantomData;
use std::mem;
use std::sync::Arc;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub trait Parser<E>: Sized {
    fn new(reader: BufReader<File>) -> io::Result<Self>;

    fn next(&mut self) -> io::Result<Option<E>>;
}

enum FileStreamer<E, P: Parser<E>> {
    Memory(Arc<Vec<E>>, PhantomData<P>),
}

impl<E, P: Parser<E>> FileStreamer<E, P> {
    fn new(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        let meta = file.metadata()?;

        // parse once and load into memory
        let reader = BufReader::new(file);
        let mut contents: Vec<E> = Vec::with_capacity(meta.len() as usize / mem::size_of::<E>());
        let mut parser = P::new(reader)?;
        while let Some(elem) = parser.next()? {
            contents.push(elem)
        }
        Ok(FileStreamer::Memory(Arc::new(contents), PhantomData))
    }

    fn rewind(&self) -> Arc<Vec<E>> {
        match self {
            FileStreamer::Memory(vec, PhantomData) => vec.clone(),
        }
    }
}

async fn prove<WP: Parser<bool> + Send + 'static>(
    program_path: &str,
    witness_path: &str,
) -> io::Result<Result<(), String>> {
    // open and parse program
    let file = File::open(program_path)?;
    let reader = BufReader::new(file);
    let program: Vec<CombineOperation> = bincode::deserialize_from(reader).unwrap();

    // open and parse witness
    let witness: FileStreamer<_, WP> = FileStreamer::new(witness_path)?;

    println!("Evaluating program in ~zero knowledge~");
    let wire_counts = largest_wires(program.as_slice());

    let program_arc = Arc::new(program);

    let proof = Proof::new(program_arc, witness.rewind(), Arc::new(vec![]), wire_counts);

    println!("size = {}", bincode::serialize(&proof).unwrap().len());

    Ok(Ok(()))
}

async fn oneshot<WP: Parser<gf2::Recon> + Send + 'static>(
    program_path: &str,
    witness_path: &str,
) -> io::Result<()> {
    // open and parse program
    let file = File::open(program_path)?;
    let reader = BufReader::new(file);
    let program: Vec<CombineOperation> = bincode::deserialize_from(reader).unwrap();

    // open and parse witness
    let witness: FileStreamer<_, WP> = FileStreamer::new(witness_path)?;
    let witness: Vec<bool> = witness.rewind().iter().map(|r| !r.is_zero()).collect();

    println!("Evaluating program in cleartext");
    evaluate_composite_program(program.as_slice(), &witness, &[]);

    Ok(())
}

async fn async_main() {
    let matches = App::new("Speed Reverie")
        .about("Gotta go fast")
        .arg(
            Arg::with_name("operation")
                .long("operation")
                .help("Specify the operation: \"prove\"")
                .possible_values(&["prove", "oneshot", "version_info"])
                .empty_values(false)
                .required(true),
        )
        .arg(
            Arg::with_name("witness-path")
                .long("witness-path")
                .help("The path to the file containing the witness (for proving)")
                .required_if("operation", "prove")
                .required_if("operation", "oneshot")
                .required_if("operation", "bench")
                .empty_values(false),
        )
        .arg(
            Arg::with_name("program-path")
                .long("program-path")
                .help("The path to the file containing the program (or statement)")
                .required_if("operation", "prove")
                .required_if("operation", "oneshot")
                .required_if("operation", "bench")
                .empty_values(false),
        )
        .get_matches();

    match matches.value_of("operation").unwrap() {
        "oneshot" => {
            let res = oneshot::<witness::WitParser>(
                matches.value_of("program-path").unwrap(),
                matches.value_of("witness-path").unwrap(),
            )
            .await;
            match res {
                Err(e) => {
                    eprintln!("Invalid proof: {}", e);
                    exit(-1)
                }
                Ok(output) => println!("{:?}", output),
            }
        }
        "prove" => {
            let res = prove::<witness::WitParser>(
                matches.value_of("program-path").unwrap(),
                matches.value_of("witness-path").unwrap(),
            )
            .await;
            match res {
                Err(e) => {
                    eprintln!("Invalid proof: {}", e);
                    exit(-1)
                }
                Ok(output) => println!("{:?}", output),
            }
        }
        "version_info" => print_version().await,
        _ => unreachable!(),
    }
}

async fn print_version() {
    println!("reverie_version: speed-reverie {}", built_info::PKG_VERSION);
    if let (Some(dirty), Some(hash)) = (built_info::GIT_DIRTY, built_info::GIT_COMMIT_HASH) {
        println!("reverie_commit_sha: {}", hash);
        println!(
            "reverie_uncommitted_changes: {}",
            if dirty { "TRUE" } else { "FALSE" }
        );
    }
}

fn main() {
    task::block_on(async_main());
}

/*
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn many_mul() {
        let w_gf2: Vec<gf2::Recon> = vec![true.into(); 64];
        let t_gf2: ProverTranscript<gf2::Domain, _> = ProverTranscript::new(w_gf2.iter().copied());

        let w_z64: Vec<z64::Recon> = vec![];
        let t_z64: ProverTranscript<z64::Domain, _> = ProverTranscript::new(w_z64.iter().copied());

        let mut keys = [[[0u8; KEY_SIZE]; PLAYERS]; PACKED];

        let mut rng = OsRng::new().unwrap();
        for i in 0..PACKED {
            for j in 0..PLAYERS {
                rng.fill_bytes(&mut keys[i][j]);
            }
        }

        let i_gf2 = Instance::new(t_gf2, 128, &keys, [PLAYERS; PACKED]);
        let i_z64 = Instance::new(t_z64, 10, &keys, [PLAYERS; PACKED]);

        let mut ins = CombineInstance::new(i_gf2, i_z64);

        let program = vec![
            CombineOperation::B2A(0, 0),
            CombineOperation::Z64(Operation::AssertZero(0)),
        ];

        for op in program.iter() {
            ins.step(op)
        }

        for _ in 0..100_000 {
            ins.step(&CombineOperation::B2A(0, 0));
        }

        for i in 0..100_000_000 {
            if i % 1_000_000 == 0 {
                println!("{}", i);
            }
            ins.step(&CombineOperation::GF2(Operation::Mul(0, 0, 0)));
        }

        println!("size: {} B", proof_size(ins));
    }
}
2. Attempt to scroll and interact with the UI while the gadget tool is running

struct BatchGenerator {
    omit: usize,
    // prgs: [ChaCha; PLAYERS],
    prgs: [Aes128Ctr; PLAYERS],
}

impl BatchGenerator {
    fn new(seeds: &[[u8; KEY_SIZE]; PLAYERS], omit: usize) -> Self {
        BatchGenerator {
            omit,
            prgs: [
                new_aes(&seeds[0]),
                new_aes(&seeds[1]),
                new_aes(&seeds[2]),
                new_aes(&seeds[3]),
                new_aes(&seeds[4]),
                new_aes(&seeds[5]),
                new_aes(&seeds[6]),
                new_aes(&seeds[7]),
                /*
                ChaCha::new_chacha12(&seeds[0], &[0u8; 8]),
                ChaCha::new_chacha12(&seeds[1], &[0u8; 8]),
                ChaCha::new_chacha12(&seeds[2], &[0u8; 8]),
                ChaCha::new_chacha12(&seeds[3], &[0u8; 8]),
                ChaCha::new_chacha12(&seeds[4], &[0u8; 8]),
                ChaCha::new_chacha12(&seeds[5], &[0u8; 8]),
                ChaCha::new_chacha12(&seeds[6], &[0u8; 8]),
                ChaCha::new_chacha12(&seeds[7], &[0u8; 8]),
                */
            ],
        }
    }

    fn gen(&mut self, dst: &mut [Batch; PLAYERS]) {
        for i in 0..PLAYERS {
            dst[i] = Batch::zero();
            if i != self.omit {
                // let _ = self.prgs[i].xor_read(dst[i].as_mut());
                self.prgs[i].apply_keystream(dst[i].as_mut());
            }
        }
    }

    fn gen_recons(&mut self, dst: &mut [Batch; PLAYERS]) -> Batch {
        let mut recons = Batch::zero();
        for i in 0..PLAYERS {
            dst[i] = Batch::zero();
            if i != self.omit {
                // let _ = self.prgs[i].xor_read(dst[i].as_mut());
                self.prgs[i].apply_keystream(dst[i].as_mut());
            }
            recons += &dst[i];
        }
        recons
    }
}

struct BeaverMachine {
    corr: blake3::Hasher,
    reps: [BatchGenerator; PACKED],
    next: usize,
    temp_a: [[Batch; PLAYERS]; PACKED],
    temp_b: [[Batch; PLAYERS]; PACKED],
    temp_c: [[Batch; PLAYERS]; PACKED],
    a: [Share; 8 * batch::BATCH_SIZE],
    b: [Share; 8 * batch::BATCH_SIZE],
    c: [Share; 8 * batch::BATCH_SIZE],
}

impl BeaverMachine {
    fn gen(&mut self) {
        // generate fresh shares
        for i in 0..PACKED {
            let a = self.reps[i].gen_recons(&mut self.temp_a[i]);
            let b = self.reps[i].gen_recons(&mut self.temp_b[i]);
            let c = self.reps[i].gen_recons(&mut self.temp_c[i]);

            // player 0 correction
            let delta = a * b - c;
            self.corr.update(delta.as_ref());

            // correct player 0 share of c
            self.temp_c[i][0] += &delta;
        }

        // transpose into shares
        convert(&mut self.a, &self.temp_a);
        convert(&mut self.b, &self.temp_b);
        convert(&mut self.c, &self.temp_c);
    }

    #[inline(always)]
    fn next(&mut self) -> (Share, Share, Share) {
        if self.next >= 8 * batch::BATCH_SIZE {
            self.gen();
            self.next = 1;
            (self.a[0], self.b[0], self.c[0])
        } else {
            let res = (self.a[self.next], self.b[self.next], self.c[self.next]);
            self.next += 1;
            res
        }
    }

    fn new(reps: &[([[u8; KEY_SIZE]; PLAYERS], usize); PACKED]) -> Self {
        let reps = [
            BatchGenerator::new(&reps[0].0, reps[0].1),
            BatchGenerator::new(&reps[1].0, reps[1].1),
            BatchGenerator::new(&reps[2].0, reps[2].1),
            BatchGenerator::new(&reps[3].0, reps[3].1),
            BatchGenerator::new(&reps[4].0, reps[4].1),
            BatchGenerator::new(&reps[5].0, reps[5].1),
            BatchGenerator::new(&reps[6].0, reps[6].1),
            BatchGenerator::new(&reps[7].0, reps[7].1),
        ];
        BeaverMachine {
            corr: blake3::Hasher::new(),
            next: 8 * batch::BATCH_SIZE,
            reps,
            temp_a: unsafe { MaybeUninit::zeroed().assume_init() },
            temp_b: unsafe { MaybeUninit::zeroed().assume_init() },
            temp_c: unsafe { MaybeUninit::zeroed().assume_init() },
            a: unsafe { MaybeUninit::zeroed().assume_init() },
            b: unsafe { MaybeUninit::zeroed().assume_init() },
            c: unsafe { MaybeUninit::zeroed().assume_init() },
        }
    }
}


const KEY_SIZE: usize = 16;
const PLAYERS: usize = 8;
const PACKED: usize = 8;

fn main() {
    let total_reps = 256;

    let packed_reps = vec![0; total_reps / PACKED];

    let _: Vec<()> = packed_reps
        .par_iter()
        .map(|_| {
            let op = Operation::Mul(0, 0, 0);
            let mut wires: Vec<Share> = Vec::with_capacity(1024);

            wires.push(Share::zero());

            let mut beaver = BeaverMachine::new(&[
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
                ([[0u8; KEY_SIZE]; PLAYERS], PLAYERS),
            ]);

            // try to benchmark 200 000 000 multiplications
            for i in 0..50_000_000 {
                // if i % 1_000_000 == 0 {
                //    println!("{}", i);
                //}
                match op {
                    Operation::Add(dst, src1, src2) => {
                        wires[dst] = wires[src1] + wires[src2];
                    }
                    Operation::Mul(dst, src1, src2) => {
                        // take next multiplication triple
                        let (a, b, c) = beaver.next();
                        let x = wires[src1];
                        let y = wires[src2];

                        // do beaver multiplication
                        let d = (x - a).recons();
                        let e = (y - b).recons();
                        wires[dst] = c + x * e + y * d - e * d;
                    }
                    Operation::Random(dst) => {}
                    Operation::Zero(src) => {}
                    Operation::Input(dst) => {}
                }
            }
        })
        .collect();
}
*/
