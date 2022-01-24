#![allow(dead_code)]
#![allow(unused_imports)]

use std::fs::File;
use std::io;
use std::io::{BufReader, BufWriter};
use std::marker::PhantomData;
use std::mem;
use std::process::exit;
use std::sync::Arc;

use async_std::task;
use clap::{App, Arg};
use num_traits::Zero;
use rand::rngs::OsRng;
use rand::Rng;
use reverie::algebra::*;
use reverie::crypto::prg::KEY_SIZE;
use reverie::interpreter::{CombineInstance, Instance};
use reverie::proof::Proof;
use reverie::transcript::ProverTranscript;
use reverie::PACKED;
use reverie::{evaluate_composite_program, largest_wires};
use reverie::{CombineOperation, Operation};

mod witness;

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
    proof_path: &str,
) -> io::Result<Result<(), String>> {
    // open and parse program
    let program_file = File::open(program_path)?;
    let program_reader = BufReader::new(program_file);
    let program: Vec<CombineOperation> = bincode::deserialize_from(program_reader).unwrap();

    // open and parse witness
    let witness: FileStreamer<_, WP> = FileStreamer::new(witness_path)?;

    // Create Proof
    println!("Evaluating program in ~zero knowledge~");
    let wire_counts = largest_wires(program.as_slice());
    let proof = Proof::new(
        Arc::new(program),
        witness.rewind(),
        Arc::new(vec![]),
        wire_counts,
    );

    // Write proof to file
    let proof_file = File::create(proof_path)?;
    let proof_writer = BufWriter::new(proof_file);
    if bincode::serialize_into(proof_writer, &proof).is_ok() {
        Ok(Ok(()))
    } else {
        Ok(Err("Could not serialize Proof".to_string()))
    }
}

async fn verify<WP: Parser<bool> + Send + 'static>(
    program_path: &str,
    proof_path: &str,
) -> io::Result<Result<(), String>> {
    // open and parse program
    let program_file = File::open(program_path)?;
    let program_reader = BufReader::new(program_file);
    let program: Vec<CombineOperation> = bincode::deserialize_from(program_reader).unwrap();

    // Deserialize the proof
    let proof_file = File::open(proof_path)?;
    let proof_reader = BufReader::new(proof_file);
    let proof: Proof = bincode::deserialize_from(proof_reader).unwrap();

    // Verify the proof
    println!("Verifying Proof");
    let wire_counts = largest_wires(program.as_slice());
    if proof.verify(Arc::new(program), wire_counts) {
        Ok(Ok(()))
    } else {
        Ok(Err("Unverifiable Proof".to_string()))
    }
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

async fn oneshot_zk<WP: Parser<bool> + Send + 'static>(
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

    // Create the proof
    let proof = Proof::new(
        program_arc.clone(),
        witness.rewind(),
        Arc::new(vec![]),
        wire_counts,
    );

    // Verify the proof
    if proof.verify(program_arc, wire_counts) {
        Ok(Ok(()))
    } else {
        Ok(Err("Unverifiable Proof".to_string()))
    }
}

async fn async_main() {
    let matches = App::new("Speed Reverie")
        .about("Gotta go fast")
        .arg(
            Arg::new("operation")
                .long("operation")
                .help("Specify the operation: \"prove\", \"verify\"")
                .possible_values(&["prove", "verify", "oneshot", "oneshot-zk", "version_info"])
                .forbid_empty_values(true)
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("witness-path")
                .long("witness-path")
                .help("The path to the file containing the witness (for proving)")
                .required_if_eq_any(&[
                    ("operation", "prove"),
                    ("operation", "oneshot"),
                    ("operation", "oneshot-zk"),
                    ("operation", "bench"),
                ])
                .takes_value(true)
                .forbid_empty_values(true),
        )
        .arg(
            Arg::new("program-path")
                .long("program-path")
                .help("The path to the file containing the program (or statement)")
                .required_if_eq_any(&[
                    ("operation", "prove"),
                    ("operation", "verify"),
                    ("operation", "oneshot"),
                    ("operation", "oneshot-zk"),
                    ("operation", "bench"),
                ])
                .forbid_empty_values(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("proof-path")
                .long("proof-path")
                .help("The path to write the proof file")
                .required_if_eq_any(&[("operation", "prove"), ("operation", "verify")])
                .forbid_empty_values(true)
                .takes_value(true),
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
        "oneshot-zk" => {
            let res = oneshot_zk::<witness::WitParser>(
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
                matches.value_of("proof-path").unwrap(),
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
        "verify" => {
            let res = verify::<witness::WitParser>(
                matches.value_of("program-path").unwrap(),
                matches.value_of("proof-path").unwrap(),
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
