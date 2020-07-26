extern crate reverie;

use reverie::algebra::gf2::{GF2P64, GF2P8};
use reverie::algebra::*;

use reverie::online;
use reverie::preprocessing;
use reverie::Instruction;

use std::marker::PhantomData;

use async_channel::bounded;
use async_std::task;

#[cfg(feature = "profiler")]
extern crate cpuprofiler;

#[cfg(feature = "profiler")]
use cpuprofiler::PROFILER;

use std::env;

#[derive(PartialEq, Eq)]
enum ProofSystem {
    GF2P64,
    GF2P8,
}

#[derive(PartialEq, Eq, Copy, Clone)]
enum Operation {
    Multiplication,
    Addition,
}

#[derive(Clone)]
struct Program<E: RingElement> {
    op: Instruction<E>,
    next: usize,
    preamble: Vec<Instruction<E>>,
    length: usize,
}

impl<E: RingElement> Program<E> {
    fn new(op: Instruction<E>, preamble: Vec<Instruction<E>>, length: usize) -> Self {
        Program {
            op,
            next: 0,
            preamble,
            length,
        }
    }
}

impl<E: RingElement> Iterator for Program<E> {
    type Item = Instruction<E>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next > self.length {
            None
        } else if self.next >= self.preamble.len() {
            self.next += 1;
            Some(self.op)
        } else {
            self.next += 1;
            Some(self.preamble[self.next - 1])
        }
    }
}

async fn async_main() {
    let mut args = env::args();

    // skip path
    args.next();

    // first arg is the system
    let system: ProofSystem = match &args.next().unwrap()[..] {
        "gf2p8" => ProofSystem::GF2P8,
        "gf2p64" => ProofSystem::GF2P64,
        _ => unimplemented!(),
    };

    // second arg is the operation to benchmark
    let operation: Operation = match &args.next().unwrap()[..] {
        "mul" => Operation::Multiplication,
        "add" => Operation::Addition,
        _ => unimplemented!(),
    };

    // third arg the number of ops to bench
    let ops: u64 = args.next().unwrap().parse().unwrap();

    if system == ProofSystem::GF2P8 {
        let inputs: Vec<<GF2P8 as Domain>::Scalar> = vec![
            <GF2P8 as Domain>::Scalar::ONE,
            <GF2P8 as Domain>::Scalar::ONE,
        ];

        println!("pre-process: {}", ops);

        let chunk_size = 10_000_000;

        let program: Program<<GF2P8 as Domain>::Scalar> = Program::new(
            match operation {
                Operation::Addition => Instruction::Add(2, 0, 1),
                Operation::Multiplication => Instruction::Mul(2, 0, 1),
            },
            vec![Instruction::Input(0), Instruction::Input(1)],
            ops as usize,
        );

        let (_proof_pp, output) = preprocessing::Proof::<GF2P8, 8, 8, 252, 256, 44>::new(
            [0u8; 16],
            program.clone(),
            chunk_size,
        );

        println!("first online pass");

        let (prover, _): (online::StreamingProver<GF2P8, _, _, 44, 8, 8>, _) =
            online::StreamingProver::new(output, program.clone(), inputs.into_iter());

        println!("stream out result");

        let (send, recv) = bounded(100);

        let t1 = task::spawn(prover.stream(send));

        let mut data = 0;
        while let Ok(chunk) = recv.recv().await {
            data += chunk.len();
            println!("data: {} bytes", data);
        }

        t1.await.unwrap()
    }

    if system == ProofSystem::GF2P64 {
        unimplemented!()
    }
}

fn main() {
    // start profiler
    #[cfg(feature = "profiler")]
    PROFILER.lock().unwrap().start("./reverie.prof").unwrap();

    task::block_on(async_main());

    // stop profiler
    #[cfg(feature = "profiler")]
    PROFILER.lock().unwrap().stop().unwrap();
}
