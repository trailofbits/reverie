extern crate reverie;

/*
use reverie::algebra::gf2::{Bit, BitBatch};
use reverie::algebra::RingVector;
use reverie::crypto::ElementHasher;
use reverie::online::prover::Proof;
use reverie::online::Instruction;

use reverie::pp::PreprocessedProof;
*/

use std::env;

use rayon::prelude::*;

fn main() {

    /*
    let mut inputs: RingVector<BitBatch> = RingVector::new();

    inputs.set(0, Bit::new(1));
    inputs.set(1, Bit::new(1));

    let mut args = env::args();
    args.next();

    let multiplications: u64 = args.next().unwrap().parse().unwrap();

    println!("process: {}", multiplications);

    let program = vec![Instruction::Mul(2, 0, 1); multiplications as usize];

    PreprocessedProof::<BitBatch, 8, 8, 252, 256, 44>::new(multiplications, [0u8; 16]);

    println!("preprocessed done");

    let keys: Vec<[u8; 16]> = vec![[0u8; 16]; 44];

    let _: Proof<BitBatch, 8, 8> =  Proof::new(&keys[..], &program, &inputs);

    println!("online done");
    */
}
