extern crate reverie;

use reverie::algebra::gf2p8::GF2P8;
use reverie::algebra::*;

use reverie::online::{Instruction, Proof};
use reverie::pp::PreprocessedProof;

use std::env;

use rayon::prelude::*;

fn main() {
    let one = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ONE;
    let zero = <<GF2P8 as Domain>::Sharing as RingModule>::Scalar::ZERO;
    let mut inputs: Vec<<<GF2P8 as Domain>::Sharing as RingModule>::Scalar> = vec![one, one, one];

    let mut args = env::args();
    args.next();

    let multiplications: u64 = args.next().unwrap().parse().unwrap();

    println!("process: {}", multiplications);

    let program = vec![Instruction::Mul(2, 0, 1); multiplications as usize];

    PreprocessedProof::<GF2P8, 8, 8, 252, 256, 44>::new(multiplications, [0u8; 16]);

    println!("preprocessed done");

    let keys: Vec<[u8; 16]> = vec![[0u8; 16]; 44];

    let _: Proof<GF2P8, 8, 8> = Proof::new(&keys[..], &program, &inputs);

    println!("online done");
}
