pub mod prover;
pub mod verifier;

use crate::crypto::{RingHasher, TreePRF, KEY_SIZE};
use crate::fs::{View, ViewRNG};
use crate::pp::Preprocessing;
use crate::util::{VecMap, Writer};
use crate::Instruction;

use crate::algebra::{Domain, RingElement, RingModule, Samplable, Sharing};

/// Represents the state required to partially re-execute a single repetition of the online phase.
pub struct Run<D: Domain, const N: usize, const NT: usize> {
    inputs: Vec<<D::Sharing as RingModule>::Scalar>, // initial wire values (masked witness)
    corrections: Vec<D::Batch>,                      // correction shares for player0
    broadcast: Vec<D::Batch>,                        // messages broadcast by hidden player
    open: TreePRF<NT>, // PRF used to derive random tapes for the opened players
}

/// A proof of the online phase consists of a collection of runs to amplify soundness.
pub struct Proof<D: Domain, const N: usize, const NT: usize, const R: usize> {
    runs: Vec<Run<D, N, NT>>,
}

pub fn execute<D: Domain, T: Writer<D::Sharing>, P: Preprocessing<D>, const N: usize>(
    transcript: &mut T,
    wires: Vec<<D::Sharing as RingModule>::Scalar>,
    mut preprocessing: P,
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
) {
    let mut wires: VecMap<<D::Sharing as RingModule>::Scalar> = wires.into();
    for step in program {
        match *step {
            Instruction::AddConst(dst, src, c) => {
                let sw = wires.get(src);
                wires.set(dst, sw + c);
            }
            Instruction::MulConst(dst, src, c) => {
                let sw = wires.get(src);
                wires.set(dst, sw * c);
            }
            Instruction::Add(dst, src1, src2) => {
                let sw1 = wires.get(src1);
                let sw2 = wires.get(src2);
                wires.set(dst, sw1 + sw2);
            }
            Instruction::Mul(dst, src1, src2) => {
                let sw1 = wires.get(src1);
                let sw2 = wires.get(src2);

                // calculate reconstruction shares for every player
                let a: D::Sharing = preprocessing.mask(src1);
                let b: D::Sharing = preprocessing.mask(src2);
                let recon = a.action(sw1) + b.action(sw2) + preprocessing.next_ab_gamma();

                // append messages from all players to transcript
                #[cfg(test)]
                println!("{:?}", &recon);

                transcript.write(&recon);

                // reconstruct and correct share
                wires.set(dst, recon.reconstruct() + sw1 * sw2);
            }
            Instruction::Output(src) => (),
        }
    }

    println!("\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::gf2::*;
    use rand::thread_rng;
    use rand_core::RngCore;

    fn test_proof<D: Domain, const N: usize, const NT: usize, const R: usize>(
        program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
        inputs: &[<D::Sharing as RingModule>::Scalar],
    ) {
        let mut rng = thread_rng();
        let mut seeds: [[u8; KEY_SIZE]; R] = [[0; KEY_SIZE]; R];
        for i in 0..R {
            rng.fill_bytes(&mut seeds[i]);
        }

        let proof: Proof<D, N, NT, R> = Proof::new(&seeds, program, inputs);

        assert!(proof.verify(program));
    }

    #[test]
    fn test_online_gf2p8() {
        let program: Vec<Instruction<BitScalar>> = vec![Instruction::Mul(8, 0, 1)];

        let inputs: Vec<BitScalar> = vec![
            BitScalar::ONE,  // 0
            BitScalar::ONE,  // 1
            BitScalar::ONE,  // 2
            BitScalar::ONE,  // 3
            BitScalar::ZERO, // 4
            BitScalar::ZERO, // 5
            BitScalar::ZERO, // 6
            BitScalar::ZERO, // 7
        ];
        test_proof::<GF2P8, 8, 8, 1>(&program[..], &inputs[..]);
    }
}
