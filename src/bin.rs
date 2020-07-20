extern crate reverie;

use reverie::algebra::gf2::{GF2P64, GF2P8};
use reverie::algebra::*;

/*
use reverie::online;
use reverie::preprocessing;
use reverie::Instruction;

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

#[derive(PartialEq, Eq)]
enum Operation {
    Multiplication,
    Addition,
}
*/

fn main() {
    /*
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

    // start profiler
    #[cfg(feature = "profiler")]
    PROFILER.lock().unwrap().start("./reverie.prof").unwrap();

    if system == ProofSystem::GF2P8 {
        let one = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ONE;
        let zero = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ZERO;
        let inputs: Vec<<<GF2P8 as Domain>::Sharing as RingModule>::Scalar> = vec![one, one, one];

        println!("process: {}", ops);

        let program = vec![
            match operation {
                Operation::Addition => Instruction::Add(2, 0, 1),
                Operation::Multiplication => Instruction::Mul(2, 0, 1),
            };
            ops as usize
        ];

        let (_proof_pp, output) = preprocessing::Proof::<GF2P8, 8, 8, 252, 256, 44>::new(
            [0u8; 16],
            &program[..],
            inputs.len(),
        );

        println!("preprocessing done");

        let _proof_online: online::Proof<GF2P8, 8, 8, 44> =
            online::Proof::new(output, &program, &inputs);

        println!("online done");
    }

    if system == ProofSystem::GF2P64 {
        let one = <<GF2P64 as Domain>::Sharing as RingModule>::Scalar::ONE;
        let zero = <<GF2P64 as Domain>::Sharing as RingModule>::Scalar::ZERO;
        let inputs: Vec<<<GF2P64 as Domain>::Sharing as RingModule>::Scalar> = vec![one, one, one];

        println!("process: {}", ops);

        let program = vec![
            match operation {
                Operation::Addition => Instruction::Add(2, 0, 1),
                Operation::Multiplication => Instruction::Mul(2, 0, 1),
            };
            ops as usize
        ];

        let (_proof_pp, output) = preprocessing::Proof::<GF2P64, 64, 64, 631, 1024, 23>::new(
            [0u8; 16],
            &program[..],
            inputs.len(),
        );

        println!("preprocessing done");

        let _proof_online: online::Proof<GF2P64, 64, 64, 23> =
            online::Proof::new(output, &program, &inputs);

        println!("online done");
    }

    // stop profiler
    #[cfg(feature = "profiler")]
    PROFILER.lock().unwrap().stop().unwrap();
    */
}
