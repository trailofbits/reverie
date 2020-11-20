use std::fs::File;
use std::io::{self, BufReader};
use std::marker::PhantomData;

mod instruction;
mod witness;

use reverie::algebra::gf2::*;
use reverie::online;
use reverie::preprocessing;
use reverie::Instruction;

use async_channel::bounded;
use async_std::task;

use std::io::prelude::*;
use std::io::SeekFrom;
use std::mem;
use std::process::exit;
use std::sync::Arc;

use clap::{App, Arg};
use rand::rngs::OsRng;
use rand::Rng;

use rayon::prelude::*;

use sysinfo::SystemExt;

const MAX_VEC_SIZE: usize = 1024 * 1024 * 1024;

const IN_MEMORY_FILE_SIZE: usize = 1024 * 1024 * 1024;

pub trait Parser<E>: Sized {
    fn new(reader: BufReader<File>) -> io::Result<Self>;

    fn next(&mut self) -> io::Result<Option<E>>;
}

fn write_vec<W: io::Write>(dst: &mut W, src: &[u8]) -> io::Result<()> {
    assert!(src.len() < MAX_VEC_SIZE);
    dst.write_all(&(src.len() as u32).to_le_bytes()[..])?;
    dst.write_all(src)
}

fn read_vec<R: io::Read>(src: &mut R) -> io::Result<Option<Vec<u8>>> {
    // obtain the length of the following vector
    let mut len = [0u8; 4];
    match src.read_exact(&mut len) {
        Err(err) => {
            if let io::ErrorKind::UnexpectedEof = err.kind() {
                return Ok(None);
            } else {
                return Err(err);
            }
        }
        _ => (),
    }

    // sanity check the length (un-trusted input)
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_VEC_SIZE {
        return Ok(None);
    }

    // read the vector
    let mut vec = vec![0u8; len];
    match src.read_exact(&mut vec[..]) {
        Err(err) => {
            if let io::ErrorKind::UnexpectedEof = err.kind() {
                return Ok(None);
            } else {
                return Err(err);
            }
        }
        _ => (),
    }
    Ok(Some(vec))
}

enum FileStreamer<E, P: Parser<E>> {
    File(File, PhantomData<P>),
    Memory(Arc<Vec<E>>),
}

enum FileStream<E, P: Parser<E>> {
    Memory(Arc<Vec<E>>, usize),
    File(P),
}

fn load_all<E, P: Parser<E>>(path: &str) -> io::Result<Vec<E>> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    let reader = BufReader::new(file);
    let mut contents: Vec<E> = Vec::with_capacity(meta.len() as usize / mem::size_of::<E>());
    let mut parser = P::new(reader)?;
    while let Some(elem) = parser.next()? {
        contents.push(elem)
    }
    Ok(contents)
}

impl<E, P: Parser<E>> FileStreamer<E, P> {
    fn new(path: &str, mem_size: usize) -> io::Result<Self> {
        let file = File::open(path)?;
        let meta = file.metadata()?;

        // parse small files once and load into memory
        if meta.len() < mem_size as u64 {
            println!("load into memory");
            let reader = BufReader::new(file);
            let mut contents: Vec<E> =
                Vec::with_capacity(meta.len() as usize / mem::size_of::<E>());
            let mut parser = P::new(reader)?;
            while let Some(elem) = parser.next()? {
                contents.push(elem)
            }
            println!("done");
            return Ok(FileStreamer::Memory(Arc::new(contents)));
        }

        // larger files streamed in (multiple times) and parsed Just-in-Time
        Ok(FileStreamer::File(file, PhantomData))
    }

    /// Reset the file stream
    ///
    /// For in-memory files this is a noop
    /// For disk based files this seeks to the start and
    /// re-initializes the (potentially) stateful parser.
    fn rewind(&self) -> io::Result<FileStream<E, P>> {
        match self {
            FileStreamer::File(file, _) => {
                let mut file_c = file.try_clone()?;
                file_c.seek(SeekFrom::Start(0))?;
                Ok(FileStream::File(P::new(BufReader::new(file_c))?))
            }
            FileStreamer::Memory(vec) => Ok(FileStream::Memory(vec.clone(), 0)),
        }
    }
}

impl<E: Clone, P: Parser<E>> Iterator for FileStream<E, P> {
    type Item = E;

    fn next(&mut self) -> Option<E> {
        match self {
            FileStream::File(parser) => parser.next().unwrap(),
            FileStream::Memory(vec, n) => {
                let res = vec.get(*n).cloned();
                *n = *n + 1;
                res
            }
        }
    }
}

fn load_branches<BP: Parser<BitScalar> + Send + 'static>(
    branch_paths: Option<Vec<&str>>,
) -> io::Result<Vec<Vec<BitScalar>>> {
    match branch_paths {
        None => Ok(vec![vec![]]),
        Some(paths) => {
            let loads: Vec<io::Result<Vec<BitScalar>>> = paths
                .par_iter()
                .map(|path| load_all::<_, BP>(path))
                .collect();
            let mut branches: Vec<Vec<BitScalar>> = Vec::with_capacity(loads.len());
            for load in loads.into_iter() {
                branches.push(load?);
            }
            Ok(branches)
        }
    }
}

async fn prove<
    IP: Parser<Instruction<BitScalar>> + Send + 'static,
    WP: Parser<BitScalar> + Send + 'static,
    BP: Parser<BitScalar> + Send + 'static,
>(
    proof_path: &str,
    program_path: &str,
    witness_path: &str,
    branch_paths: Option<Vec<&str>>,
    branch_index: usize,
) -> io::Result<()> {
    let branch_vecs = load_branches::<BP>(branch_paths)?;

    // collect branch slices
    let branches: Vec<&[BitScalar]> = branch_vecs.iter().map(|v| &v[..]).collect();

    // load to memory depending on available RAM
    let mut system = sysinfo::System::new();
    system.refresh_all();
    let available_mem = system.get_available_memory();

    // open and parse program
    let program: FileStreamer<_, IP> =
        FileStreamer::new(program_path, (available_mem * 1024 / 4) as usize)?;

    // open and parse witness
    let witness: FileStreamer<_, WP> = FileStreamer::new(witness_path, IN_MEMORY_FILE_SIZE)?;

    // open destination
    let mut proof = File::create(proof_path)?;

    // prove preprocessing
    println!("preprocessing...");
    let (preprocessing, pp_output) = preprocessing::Proof::<GF2P8>::new(
        OsRng.gen(),       // seed
        &branches[..],     // branches
        program.rewind()?, // program
    );
    write_vec(&mut proof, &preprocessing.serialize()[..])?;

    // create streaming prover instance
    println!("oracle pass...");
    let (online, prover) = online::StreamingProver::<GF2P8>::new(
        None,
        pp_output,
        branch_index,
        program.rewind()?,
        witness.rewind()?,
    )
    .await;
    write_vec(&mut proof, &online.serialize()[..])?;

    // create prover for online phase
    println!("stream proof...");
    let (send, recv) = bounded(100);
    let stream_task = task::spawn(prover.stream(send, program.rewind()?, witness.rewind()?));

    // read all chunks from online execution
    // (stream out the proof to disk)
    while let Ok(chunk) = recv.recv().await {
        write_vec(&mut proof, &chunk)?;
    }

    // wait for streaming prover to merge
    stream_task.await.unwrap();
    Ok(())
}

async fn verify<
    IP: Parser<Instruction<BitScalar>> + Send + 'static,
    BP: Parser<BitScalar> + Send + 'static,
>(
    proof_path: &str,
    program_path: &str,
    branch_paths: Option<Vec<&str>>,
) -> io::Result<Result<Vec<BitScalar>, String>> {
    let branch_vecs = load_branches::<BP>(branch_paths)?;

    // collect branch slices
    let branches: Vec<&[BitScalar]> = branch_vecs.iter().map(|v| &v[..]).collect();

    // open and parse program
    let program: FileStreamer<_, IP> = FileStreamer::new(program_path, 0)?;

    // open and parse proof
    let mut proof = BufReader::new(File::open(proof_path)?);

    // parse preprocessing
    let preprocessing: preprocessing::Proof<GF2P8> = read_vec(&mut proof)?
        .and_then(|v| preprocessing::Proof::<GF2P8>::deserialize(&v))
        .expect("Failed to deserialize proof after preprocessing");

    let pp_output = match preprocessing.verify(&branches[..], program.rewind()?).await {
        Some(output) => output,
        None => panic!("Failed to verify preprocessed proof"),
    };

    let online = read_vec(&mut proof)?
        .and_then(|v| online::Proof::<GF2P8>::deserialize(&v))
        .expect("Failed to deserialize online proof");

    // verify the online execution
    let (send, recv) = bounded(100);
    let task_online =
        task::spawn(online::StreamingVerifier::new(program.rewind()?, online).verify(None, recv));

    while let Some(vec) = read_vec(&mut proof)? {
        send.send(vec).await.unwrap();
    }

    mem::drop(send);

    let online_output = task_online.await.unwrap();

    Ok(online_output
        .check(&pp_output)
        .ok_or_else(|| String::from("Online output check failed")))
}

async fn async_main() -> io::Result<()> {
    let matches = App::new("Reverie Companion")
        .version("0.2")
        .author("Mathias Hall-Andersen <mathias@hall-andersen.dk>")
        .about("Provides a simple way to use Reverie.")
        .arg(
            Arg::with_name("operation")
                .long("operation")
                .help("Specify the operation: \"prove\" or \"verify\"")
                .possible_values(&["prove", "verify"])
                .empty_values(false)
                .required(true),
        )
        .arg(
            Arg::with_name("proof-path")
                .long("proof-path")
                .help("The path to the file containing the proof (source or destination)")
                .empty_values(false)
                .required(true),
        )
        .arg(
            Arg::with_name("branch-path")
                .long("branch-path")
                .help("The path to a file containing branch bits (may occur multiple times)")
                .empty_values(false)
                .multiple(true),
        )
        .arg(
            Arg::with_name("branch-index")
                .long("branch-index")
                .help("The index/active branch")
                .empty_values(false),
        )
        .arg(
            Arg::with_name("witness-path")
                .long("witness-path")
                .help("The path to the file containing the witness (for proving)")
                .required_if("operation", "prove")
                .empty_values(false),
        )
        .arg(
            Arg::with_name("program-path")
                .long("program-path")
                .help("The path to the file containing the program (or statement)")
                .required(true)
                .empty_values(false),
        )
        .arg(
            Arg::with_name("output-path")
                .long("output-path")
                .help("The path to the file in which to write the output")
                .empty_values(false),
        )
        .arg(
            Arg::with_name("program-format")
                .long("program-format")
                .help("The format of the program input.")
                .possible_values(&["bristol", "bin"])
                .empty_values(false)
                .required(true),
        )
        .get_matches();

    let branches: Option<Vec<&str>> = matches.values_of("branch-path").map(|vs| vs.collect());

    match matches.value_of("operation").unwrap() {
        "prove" => {
            let branch_index: usize = if branches.is_some() {
                matches
                    .value_of("branch-index")
                    .map(|s| s.parse().unwrap())
                    .unwrap()
            } else {
                0
            };
            match matches.value_of("program-format").unwrap() {
                "bristol" => prove::<
                    instruction::bristol::InsParser,
                    witness::WitParser,
                    witness::WitParser,
                >(
                    matches.value_of("proof-path").unwrap(),
                    matches.value_of("program-path").unwrap(),
                    matches.value_of("witness-path").unwrap(),
                    branches,
                    branch_index,
                )
                .await,
                "bin" => {
                    prove::<instruction::bin::InsParser, witness::WitParser, witness::WitParser>(
                        matches.value_of("proof-path").unwrap(),
                        matches.value_of("program-path").unwrap(),
                        matches.value_of("witness-path").unwrap(),
                        branches,
                        branch_index,
                    )
                    .await
                }
                _ => unreachable!(),
            }
        }
        "verify" => {
            let res = match matches.value_of("program-format").unwrap() {
                "bristol" => {
                    verify::<instruction::bristol::InsParser, witness::WitParser>(
                        matches.value_of("proof-path").unwrap(),
                        matches.value_of("program-path").unwrap(),
                        branches,
                    )
                    .await?
                }
                "bin" => {
                    verify::<instruction::bin::InsParser, witness::WitParser>(
                        matches.value_of("proof-path").unwrap(),
                        matches.value_of("program-path").unwrap(),
                        branches,
                    )
                    .await?
                }
                _ => unreachable!(),
            };
            match res {
                Err(e) => {
                    eprintln!("Invalid proof: {}", e);
                    exit(-1)
                }
                Ok(output) => println!("{:?}", output),
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}

fn main() {
    task::block_on(async_main()).unwrap();
}
