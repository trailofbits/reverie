extern crate reverie;

use reverie::algebra::gf2::{Bit, BitBatch};
use reverie::algebra::RingVector;
use reverie::crypto::ElementHasher;
use reverie::online::prover::Execution;
use reverie::online::Instruction;

use reverie::pp::PreprocessedProof;

use std::env;

use rayon::prelude::*;

fn main() {
    let mut inputs: RingVector<BitBatch> = RingVector::new();

    inputs.set(0, Bit::new(1));
    inputs.set(1, Bit::new(1));

    let mut args = env::args();
    args.next();

    let multiplications: u64 = args.next().unwrap().parse().unwrap();

    println!("process: {}", multiplications);

    PreprocessedProof::<BitBatch, 64, 64, 631, 1024, 23>::new(multiplications, [0u8; 16]);

    println!("preprocessed done");

    for _ in 0..2 {
        println!("run online");
        let _: Vec<()> = vec![0u8; 23]
            .par_iter()
            .map(|_| {
                let mut exec: Execution<BitBatch, ElementHasher<BitBatch>, 64, 64> =
                    Execution::new([0u8; 16], &inputs, 8);

                let ins = Instruction::Mul(3, 0, 1);
                for _ in 0..multiplications {
                    exec.step(&ins);
                }
            })
            .collect();
    }
}
