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

// const MAX_VEC_SIZE: usize = 1024 * 1024 * 1024;

const IN_MEMORY_FILE_SIZE: usize = 1024 * 1024 * 1024;

pub trait Parser<E>: Sized {
    fn new(reader: BufReader<File>) -> io::Result<Self>;

    fn next(&mut self) -> io::Result<Option<E>>;
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

async fn prove_and_verify<
    IP: Parser<Instruction<BitScalar>> + Send + 'static,
    WP: Parser<BitScalar> + Send + 'static,
    BP: Parser<BitScalar> + Send + 'static,
>(
    program_path: &str,
    witness_path: &str,
) -> io::Result<Option<Vec<BitScalar>>> {

    let branch_vecs = load_branches::<BP>(None)?;
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


    // prove preprocessing
    println!("preprocessing...");
    let (preprocessing, pp_output) = preprocessing::Proof::<GF2P8>::new(
        [128u8; 32],       // seed
        &branches[..],     // branches
        program.rewind()?, // program
    );

    // let preproc_prf = preprocessing.serialize();

    // create streaming prover instance
    println!("oracle pass...");
    let (online, prover) = online::StreamingProver::<GF2P8>::new(
        None,
        pp_output,
        0,
        program.rewind()?,
        witness.rewind()?,
    )
    .await;
    // let online_prf = online.serialize();

    // create prover for online phase
    println!("stream proof...");
    let (send, recv) = bounded(100);
    let stream_task = task::spawn(prover.stream(send, program.rewind()?, witness.rewind()?));

    // read all chunks from online execution
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    while let Ok(chunk) = recv.recv().await {
        chunks.push(chunk);
    }

    // wait for streaming prover to merge
    stream_task.await.unwrap();

    // Verification stage

    // parse preprocessing
    let preprocessing2: preprocessing::Proof<GF2P8> = preprocessing;
        // preprocessing::Proof::<GF2P8>::deserialize(&preproc_prf).expect("Failed to deserialize proof after preprocessing");

    let pp_output2 = match preprocessing2.verify(&branches[..], program.rewind()?).await {
        Some(output) => output,
        None => panic!("Failed to verify preprocessed proof")
    };

    let online2 = online;
        // online::Proof::<GF2P8>::deserialize(&online_prf).expect("Failed to deserialize online proof");

    // verify the online execution
    let (send2, recv2) = bounded(100);
    let task_online =
        task::spawn(online::StreamingVerifier::new(program.rewind()?, online2).verify(None, recv2));


    for chunk in chunks {
        send2.send(chunk).await.unwrap();
    }

    mem::drop(send2);

    let online_output = match task_online.await {
        Some(output) => output,
        None => return Ok(None),
    };

    Ok(online_output.check(&pp_output2))
}

async fn async_main() -> io::Result<()> {
    let matches = App::new("Reverie One-Shot")
        .version("0.2")
        .author("Mathias Hall-Andersen <mathias@hall-andersen.dk>")
        .about("Runs Reverie from start to finish in a single command")
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
        .get_matches();

        let res = prove_and_verify::<
                instruction::bristol::InsParser,
                witness::WitParser,
                witness::WitParser,
            >(
                matches.value_of("program-path").unwrap(),
                matches.value_of("witness-path").unwrap(),
            )
            .await?;

        match res {
            None => {
                eprintln!("Failed to Verify: Invalid Proof");
                exit(-1)
            }
            Some(output) => println!("{:?}", output),
        }
        Ok(())
}

fn main() {
    task::block_on(async_main()).unwrap();
}
