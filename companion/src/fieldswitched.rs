use std::fs::File;
use std::io::{self, BufReader};
use std::marker::PhantomData;

mod instruction;
mod witness;

use reverie::algebra::gf2::*;
use reverie::algebra::z64::*;
use reverie::fieldswitching;
use reverie::Instruction;

use async_std::task;

use std::mem;
use std::process::exit;
use std::sync::Arc;

use clap::{App, Arg};

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

async fn prove<
    IP: Parser<Instruction<BitScalar>> + Send + 'static,
    IP2: Parser<Instruction<Scalar>> + Send + 'static,
    WP: Parser<BitScalar> + Send + 'static,
    BP: Parser<BitScalar> + Send + 'static,
>(
    proof_path: &str,
    program_path: &str,
    program2_path: &str,
    witness_path: &str,
) -> io::Result<()> {
    // open and parse program
    let program: FileStreamer<_, IP> = FileStreamer::new(program_path)?;

    let program2: FileStreamer<_, IP2> = FileStreamer::new(program2_path)?;

    // open and parse witness
    let witness: FileStreamer<_, WP> = FileStreamer::new(witness_path)?;

    // open destination
    let mut proof = File::create(proof_path)?;

    // prove preprocessing
    println!("preprocessing...");
    let (preprocessing, pp_output) = fieldswitching::preprocessing::Proof::<Gf2P8, Z64P8>::new(
        Vec::new(),
        program.rewind(),
        program2.rewind(),
        Vec::new(),
        Vec::new(),
    );

    write_vec(&mut proof, &bincode::serialize(&preprocessing).unwrap()[..])?;

    // create streaming prover instance
    println!("oracle pass...");
    let online_proof = fieldswitching::online::Proof::<Gf2P8, Z64P8>::new(
        None,
        Vec::new(),
        program.rewind(),
        program2.rewind(),
        witness.rewind(),
        0,
        pp_output,
    )
    .await;

    write_vec(&mut proof, &bincode::serialize(&online_proof).unwrap()[..])?;

    Ok(())
}

async fn verify<
    IP: Parser<Instruction<BitScalar>> + Send + 'static,
    IP2: Parser<Instruction<Scalar>> + Send + 'static,
    BP: Parser<BitScalar> + Send + 'static,
>(
    proof_path: &str,
    program_path: &str,
    program2_path: &str,
) -> io::Result<Result<Vec<Scalar>, String>> {
    // open and parse program
    let program: FileStreamer<_, IP> = FileStreamer::new(program_path)?;
    let program2: FileStreamer<_, IP2> = FileStreamer::new(program2_path)?;

    // open and parse proof
    let mut proof = BufReader::new(File::open(proof_path)?);

    // parse preprocessing
    let preprocessing: fieldswitching::preprocessing::Proof<Gf2P8, Z64P8> = read_vec(&mut proof)?
        .and_then(|v| bincode::deserialize(&v).ok())
        .expect("Failed to deserialize proof after preprocessing");

    let _pp_output = match preprocessing
        .verify(
            Vec::new(),
            program.rewind(),
            program2.rewind(),
            Vec::new(),
            Vec::new(),
        )
        .await
    {
        Ok(output) => output,
        _ => panic!("Failed to verify preprocessed proof"),
    };

    let online: fieldswitching::online::Proof<Gf2P8, Z64P8> = read_vec(&mut proof)?
        .and_then(|v| bincode::deserialize(&v).ok())
        .expect("Failed to deserialize online proof");

    // verify the online execution
    let online_output =
        task::block_on(online.verify(None, Vec::new(), program.rewind(), program2.rewind()));

    // TODO (ehennenfent) Do we need to do anything else to check the output here?

    Ok(online_output)
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
        "prove" => {
            prove::<
                instruction::bin::InsParser<BitScalar>,
                instruction::bin::InsParser<Scalar>,
                witness::WitParser,
                witness::WitParser,
            >(
                matches.value_of("proof-path").unwrap(),
                matches.value_of("program-path").unwrap(),
                matches.value_of("program2-path").unwrap(),
                matches.value_of("witness-path").unwrap(),
            )
            .await
        }
        "verify" => {
            let res = verify::<
                instruction::bin::InsParser<BitScalar>,
                instruction::bin::InsParser<Scalar>,
                witness::WitParser,
            >(
                matches.value_of("proof-path").unwrap(),
                matches.value_of("program-path").unwrap(),
                matches.value_of("program2-path").unwrap(),
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
