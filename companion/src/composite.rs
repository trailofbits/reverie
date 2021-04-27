use std::fs::File;
use std::io::{self, BufReader};

mod instruction;
mod witness;

use reverie::algebra::gf2::*;
use reverie::algebra::z64::*;
use reverie::evaluate_composite_program;
use reverie::InstructionCombine;

use async_std::task;

use std::process::exit;
use std::sync::Arc;

use clap::{App, Arg};
use std::marker::PhantomData;
use std::mem;

const MAX_VEC_SIZE: usize = 1024 * 1024 * 1024;

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
    if let Err(err) = src.read_exact(&mut len) {
        if let io::ErrorKind::UnexpectedEof = err.kind() {
            return Ok(None);
        } else {
            return Err(err);
        }
    }

    // sanity check the length (un-trusted input)
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_VEC_SIZE {
        return Ok(None);
    }

    // read the vector
    let mut vec = vec![0u8; len];
    if let Err(err) = src.read_exact(&mut vec[..]) {
        if let io::ErrorKind::UnexpectedEof = err.kind() {
            return Ok(None);
        } else {
            return Err(err);
        }
    }
    Ok(Some(vec))
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

    /// Reset the file stream
    ///
    /// For in-memory files this is a noop
    /// For disk based files this seeks to the start and
    /// re-initializes the (potentially) stateful parser.
    fn rewind(&self) -> Arc<Vec<E>> {
        match self {
            FileStreamer::Memory(vec, PhantomData) => vec.clone(),
        }
    }
}


async fn oneshot<WP: Parser<BitScalar> + Send + 'static>(
    program_path: &str,
    witness_path: &str,
) -> io::Result<Result<Vec<Scalar>, String>> {
    // open and parse program
    let file = File::open(program_path)?;
    let reader = BufReader::new(file);
    let program: Vec<InstructionCombine> = bincode::deserialize_from(reader).unwrap();

    // open and parse witness
    let witness: FileStreamer<_, WP> = FileStreamer::new(witness_path)?;

    println!("Evaluating program in cleartext");
    let cleartext = evaluate_composite_program(
        &program.as_slice(),
        &witness.rewind(),
    );

    Ok(Ok(cleartext))
}

async fn async_main() -> io::Result<()> {
    let matches = App::new("Reverie Companion (Composite)")
        .version("0.2")
        .author("Mathias Hall-Andersen <mathias@hall-andersen.dk>")
        .about("Provides a simple way to use Reverie.")
        .arg(
            Arg::with_name("operation")
                .long("operation")
                .help("Specify the operation: \"oneshot\"")
                .possible_values(&["oneshot"])
                .empty_values(false)
                .required(true),
        )
        .arg(
            Arg::with_name("proof-path")
                .long("proof-path")
                .help("The path to the file containing the proof (source or destination)")
                .empty_values(false)
                .required_if("operation", "prove")
                .required_if("operation", "verify"),
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
        .get_matches();

    match matches.value_of("operation").unwrap() {
        "oneshot" => {
            let res = oneshot::<witness::WitParser>(
                matches.value_of("program-path").unwrap(),
                matches.value_of("witness-path").unwrap(),
            )
                .await?;
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