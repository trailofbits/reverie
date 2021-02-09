pub mod prover;
pub mod verifier;

/*
#[cfg(test)]
mod tests;
*/

use crate::algebra::{Domain, RingElement};
use crate::crypto::{Hash, MerkleSetProof, RingHasher, TreePRF, KEY_SIZE};

use crate::preprocessing;
use crate::Instruction;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

pub use prover::StreamingProver;
pub use verifier::StreamingVerifier;

#[derive(Debug, Serialize, Deserialize)]
pub struct Chunk {
    corrections: Vec<u8>,
    broadcast: Vec<u8>,
    witness: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnlineRun<D: Domain> {
    pub(crate) open: TreePRF,         // randomness for opened players
    pub(crate) proof: MerkleSetProof, // merkle proof for masked branch
    pub(crate) branch: Vec<u8>,       // masked branch (packed)
    pub(crate) commitment: Hash,      // commitment for hidden preprocessing player
    pub(crate) _ph: PhantomData<D>,
}

/// Online execution "proof header"
///
/// Holds the (constant sized) state required to initialize the streaming online verifier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<D: Domain> {
    pub(crate) runs: Vec<OnlineRun<D>>,
    _ph: PhantomData<D>,
}

impl<D: Domain + Serialize> Proof<D> {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<'de, D: Domain + Deserialize<'de>> Proof<D> {
    pub fn deserialize(encoded: &'de [u8]) -> Option<Self> {
        bincode::deserialize(encoded).ok()
    }
}

/// This struct ensures that the user can only get access to the output (private field)
/// by validating the online execution against a correctly validated and matching pre-processing execution.
///
/// Avoiding potential misuse where the user fails to check the pre-processing.
pub struct Output<D: Domain> {
    pub(crate) result: Vec<D::Scalar>, //TODO(gvl): make private again
    pp_hashes: Vec<Hash>,
}

impl<D: Domain> Output<D> {
    pub fn check(self, pp: &preprocessing::Output<D>) -> Option<Vec<D::Scalar>> {
        assert_eq!(pp.hidden.len(), D::ONLINE_REPETITIONS);
        assert_eq!(self.pp_hashes.len(), D::ONLINE_REPETITIONS);
        for i in 0..D::ONLINE_REPETITIONS {
            if pp.hidden[i] != self.pp_hashes[i] {
                return None;
            }
        }
        Some(self.result)
    }

    // TODO(ww): Re-add once the tests below are re-enabled.
    // // provides access to the output without checking the pre-processing
    // // ONLY USED IN TESTS: enables testing of the online phase separately from pre-processing
    // #[cfg(test)]
    // pub(super) fn unsafe_output(&self) -> &[D::Scalar] {
    //     &self.result[..]
    // }
}

// TODO(ww): Get these tests working, perhaps.
/*
#[cfg(test)]
mod test {
    use super::*;

    use crate::algebra::gf2::*;
    use crate::preprocessing::PreprocessingOutput;
    use crate::tests::*;
    use std::future::Future;

    use rand::thread_rng;
    use rand::Rng;
    use rand_core::RngCore;

    fn test_proof<D: Domain>(
        program: &[Instruction<D::Scalar>],
        inputs: &[D::Scalar],
    ) {
        let mut rng = thread_rng();
        const R: usize = 32;
        let mut seeds: [[u8; KEY_SIZE]; R] = [[0; KEY_SIZE]; R];
        for i in 0..R {
            rng.fill_bytes(&mut seeds[i]);
        }

        for seed in seeds.iter() {
            // create a proof of the program execution
            let (proof, _pp_output) =
                preprocessing::Proof::new(*seed, &[], program.iter().cloned());

            // evaluate program in the clear
            let correct_output = evaluate_program::<D>(program, inputs, &[]);

            // extract the output from the proof
            let proof_output = proof.verify(&[], program.iter().cloned());

            match proof_output.poll() {
                Poll::Pending => (),
                Poll::Ready(output) => {
                    // since the proof is generated correctly the proof output is "Some"
                    // with the same value as the clear evaluation
                    assert_eq!(
                        output.unsafe_output(),
                        &correct_output[..],
                        "program = {:?}, inputs = {:?}",
                        program,
                        inputs
                    );
                }
            }


        }
    }

    fn test_random_proof<D: Domain>() {
        let mut rng = thread_rng();

        let inputs = (rng.gen::<usize>() % 126) + 1;
        let length = (rng.gen::<usize>() % 1024) + 1;
        let (ninputs, nbranch, program) = random_program::<D, _>(&mut rng, inputs, length);
        for ins in program.iter() {
            println!("{:?}", ins);
        }

        let input = random_input::<D, _>(&mut rng, inputs);
        for val in input.iter() {
            println!("{:?}", val);
        }
        test_proof::<D>(&program[..], &input[..])
    }

    #[test]
    fn test_online_gf2p8() {
        for _ in 0..10 {
            let program: Vec<Instruction<BitScalar>> = vec![
                Instruction::Add(127, 10, 21),
                Instruction::AddConst(480, 6, BitScalar::ONE),
                Instruction::Output(24),
                Instruction::Mul(461, 480, 3),
                Instruction::Output(27),
                Instruction::AddConst(56, 25, BitScalar::ONE),
                Instruction::MulConst(68, 27, BitScalar::ONE),
                Instruction::Add(403, 56, 8),
                Instruction::AddConst(498, 11, BitScalar::ONE),
                Instruction::MulConst(537, 4, BitScalar::ONE),
                Instruction::Add(360, 537, 8),
                Instruction::Mul(55, 6, 461),
                Instruction::Output(461),
                Instruction::Mul(315, 403, 27),
                Instruction::Output(18),
                Instruction::MulConst(271, 68, BitScalar::ZERO),
                Instruction::AddConst(35, 13, BitScalar::ONE),
                Instruction::Mul(596, 360, 127),
                Instruction::AddConst(472, 68, BitScalar::ONE),
                Instruction::Output(26),
                Instruction::Mul(302, 24, 22),
                Instruction::Add(455, 8, 537),
                Instruction::Mul(222, 68, 271),
                Instruction::Output(19),
                Instruction::Output(6),
                Instruction::Mul(48, 315, 28),
                Instruction::AddConst(521, 25, BitScalar::ZERO),
                Instruction::Mul(47, 19, 2),
                Instruction::AddConst(242, 25, BitScalar::ONE),
                Instruction::MulConst(457, 13, BitScalar::ZERO),
                Instruction::Output(360),
                Instruction::AddConst(501, 5, BitScalar::ONE),
                Instruction::Add(275, 461, 6),
                Instruction::Add(296, 242, 275),
                Instruction::Add(108, 461, 498),
                Instruction::Output(68),
                Instruction::Mul(135, 222, 13),
                Instruction::Add(601, 403, 403),
                Instruction::Mul(401, 596, 21),
                Instruction::MulConst(475, 29, BitScalar::ZERO),
                Instruction::AddConst(273, 242, BitScalar::ZERO),
                Instruction::AddConst(444, 22, BitScalar::ONE),
                Instruction::Mul(492, 521, 3),
                Instruction::MulConst(436, 48, BitScalar::ZERO),
                Instruction::AddConst(246, 461, BitScalar::ZERO),
                Instruction::Mul(518, 11, 2),
                Instruction::MulConst(390, 30, BitScalar::ONE),
                Instruction::Output(68),
                Instruction::MulConst(450, 457, BitScalar::ZERO),
                Instruction::AddConst(358, 6, BitScalar::ZERO),
                Instruction::Output(30),
                Instruction::Output(492),
                Instruction::Mul(385, 14, 8),
                Instruction::Output(19),
                Instruction::AddConst(486, 518, BitScalar::ONE),
                Instruction::Mul(283, 302, 48),
                Instruction::Add(103, 436, 28),
                Instruction::Output(498),
                Instruction::AddConst(153, 27, BitScalar::ZERO),
                Instruction::Add(585, 475, 390),
                Instruction::Add(184, 11, 3),
                Instruction::AddConst(564, 26, BitScalar::ONE),
                Instruction::Mul(531, 20, 10),
                Instruction::MulConst(338, 8, BitScalar::ZERO),
                Instruction::Output(472),
                Instruction::MulConst(557, 7, BitScalar::ZERO),
                Instruction::Add(412, 338, 22),
                Instruction::Mul(477, 153, 412),
                Instruction::Mul(350, 283, 486),
                Instruction::MulConst(181, 275, BitScalar::ONE),
                Instruction::Add(448, 461, 531),
                Instruction::AddConst(522, 47, BitScalar::ZERO),
                Instruction::MulConst(463, 522, BitScalar::ZERO),
                Instruction::Output(498),
                Instruction::AddConst(361, 135, BitScalar::ZERO),
                Instruction::Mul(366, 0, 181),
                Instruction::MulConst(407, 338, BitScalar::ONE),
                Instruction::AddConst(388, 246, BitScalar::ZERO),
                Instruction::MulConst(549, 2, BitScalar::ZERO),
                Instruction::Mul(512, 16, 181),
                Instruction::Add(76, 13, 472),
                Instruction::AddConst(137, 20, BitScalar::ONE),
                Instruction::Output(585),
                Instruction::Add(587, 108, 492),
                Instruction::Output(350),
                Instruction::AddConst(89, 436, BitScalar::ONE),
                Instruction::MulConst(347, 16, BitScalar::ZERO),
                Instruction::Add(204, 498, 14),
                Instruction::MulConst(379, 521, BitScalar::ZERO),
                Instruction::MulConst(546, 448, BitScalar::ONE),
                Instruction::MulConst(170, 127, BitScalar::ZERO),
                Instruction::AddConst(580, 403, BitScalar::ZERO),
                Instruction::Add(466, 18, 390),
                Instruction::AddConst(140, 76, BitScalar::ZERO),
                Instruction::MulConst(607, 385, BitScalar::ZERO),
                Instruction::MulConst(84, 2, BitScalar::ZERO),
                Instruction::Add(353, 585, 11),
                Instruction::Mul(595, 181, 25),
                Instruction::Mul(186, 466, 18),
                Instruction::Mul(269, 448, 448),
                Instruction::AddConst(609, 537, BitScalar::ONE),
                Instruction::AddConst(578, 7, BitScalar::ZERO),
                Instruction::Mul(224, 366, 103),
                Instruction::Mul(175, 296, 11),
                Instruction::Add(162, 204, 609),
                Instruction::Output(578),
                Instruction::MulConst(197, 16, BitScalar::ONE),
                Instruction::Mul(413, 14, 135),
                Instruction::AddConst(356, 347, BitScalar::ONE),
                Instruction::MulConst(326, 48, BitScalar::ONE),
                Instruction::Mul(262, 388, 1),
                Instruction::Add(99, 283, 48),
                Instruction::MulConst(349, 379, BitScalar::ONE),
                Instruction::AddConst(54, 518, BitScalar::ONE),
                Instruction::MulConst(377, 512, BitScalar::ONE),
                Instruction::Output(578),
                Instruction::Mul(158, 14, 585),
                Instruction::Mul(247, 0, 501),
                Instruction::Mul(102, 30, 47),
                Instruction::AddConst(255, 353, BitScalar::ONE),
                Instruction::MulConst(146, 463, BitScalar::ZERO),
                Instruction::MulConst(211, 521, BitScalar::ZERO),
                Instruction::AddConst(394, 47, BitScalar::ZERO),
                Instruction::Mul(554, 531, 12),
                Instruction::Add(324, 403, 463),
                Instruction::MulConst(462, 25, BitScalar::ZERO),
                Instruction::AddConst(217, 472, BitScalar::ZERO),
                Instruction::Mul(351, 102, 366),
                Instruction::AddConst(144, 0, BitScalar::ONE),
                Instruction::Output(609),
                Instruction::Add(329, 444, 315),
                Instruction::MulConst(80, 390, BitScalar::ONE),
                Instruction::AddConst(34, 0, BitScalar::ONE),
                Instruction::Mul(470, 204, 462),
                Instruction::AddConst(107, 137, BitScalar::ONE),
                Instruction::Mul(603, 21, 609),
                Instruction::Mul(427, 607, 486),
                Instruction::AddConst(282, 28, BitScalar::ONE),
                Instruction::Mul(179, 19, 175),
                Instruction::MulConst(409, 181, BitScalar::ONE),
                Instruction::Mul(129, 103, 9),
                Instruction::Mul(372, 356, 12),
                Instruction::Mul(556, 54, 356),
                Instruction::Output(175),
                Instruction::Add(190, 135, 12),
                Instruction::Add(214, 557, 580),
                Instruction::Output(457),
                Instruction::Output(135),
                Instruction::AddConst(288, 12, BitScalar::ONE),
                Instruction::Output(358),
                Instruction::Output(356),
                Instruction::Add(203, 204, 103),
                Instruction::Output(175),
                Instruction::Mul(293, 103, 607),
                Instruction::MulConst(33, 601, BitScalar::ZERO),
                Instruction::Output(76),
                Instruction::Mul(567, 144, 358),
                Instruction::Add(579, 361, 146),
                Instruction::Output(48),
                Instruction::AddConst(550, 585, BitScalar::ZERO),
                Instruction::MulConst(301, 273, BitScalar::ZERO),
                Instruction::Add(352, 23, 17),
                Instruction::Output(19),
                Instruction::Mul(334, 450, 175),
                Instruction::MulConst(131, 181, BitScalar::ONE),
                Instruction::AddConst(284, 20, BitScalar::ZERO),
                Instruction::Mul(418, 518, 409),
                Instruction::AddConst(341, 444, BitScalar::ONE),
                Instruction::Output(14),
                Instruction::Add(200, 247, 595),
                Instruction::Output(462),
                Instruction::Add(328, 6, 108),
                Instruction::AddConst(600, 521, BitScalar::ONE),
                Instruction::Output(68),
                Instruction::Output(579),
                Instruction::Add(39, 580, 282),
                Instruction::MulConst(510, 200, BitScalar::ZERO),
                Instruction::Output(609),
                Instruction::Output(275),
                Instruction::Add(558, 413, 587),
                Instruction::MulConst(553, 554, BitScalar::ZERO),
                Instruction::AddConst(174, 39, BitScalar::ONE),
                Instruction::AddConst(163, 28, BitScalar::ONE),
                Instruction::Mul(210, 246, 328),
                Instruction::AddConst(605, 5, BitScalar::ONE),
                Instruction::Add(177, 579, 403),
                Instruction::Output(17),
                Instruction::MulConst(244, 601, BitScalar::ZERO),
                Instruction::MulConst(272, 288, BitScalar::ZERO),
                Instruction::AddConst(487, 444, BitScalar::ZERO),
                Instruction::Mul(555, 4, 413),
                Instruction::Output(302),
                Instruction::MulConst(73, 275, BitScalar::ONE),
                Instruction::MulConst(41, 26, BitScalar::ZERO),
                Instruction::Output(247),
                Instruction::Output(217),
                Instruction::Add(593, 76, 29),
                Instruction::Add(216, 288, 20),
                Instruction::MulConst(69, 470, BitScalar::ZERO),
                Instruction::AddConst(551, 35, BitScalar::ONE),
                Instruction::AddConst(424, 301, BitScalar::ZERO),
                Instruction::MulConst(573, 3, BitScalar::ONE),
                Instruction::MulConst(234, 315, BitScalar::ONE),
                Instruction::MulConst(375, 551, BitScalar::ZERO),
                Instruction::Add(198, 273, 16),
                Instruction::AddConst(123, 605, BitScalar::ONE),
                Instruction::Add(505, 214, 375),
                Instruction::Mul(474, 448, 487),
                Instruction::MulConst(223, 579, BitScalar::ONE),
                Instruction::Output(197),
                Instruction::Add(180, 463, 501),
                Instruction::AddConst(128, 28, BitScalar::ZERO),
                Instruction::Mul(429, 34, 600),
                Instruction::AddConst(230, 375, BitScalar::ZERO),
                Instruction::Output(108),
                Instruction::Output(1),
                Instruction::AddConst(252, 555, BitScalar::ONE),
                Instruction::Mul(237, 475, 144),
                Instruction::Mul(46, 7, 28),
                Instruction::Output(18),
                Instruction::Output(472),
                Instruction::AddConst(456, 284, BitScalar::ONE),
                Instruction::Add(313, 328, 27),
                Instruction::MulConst(94, 418, BitScalar::ONE),
                Instruction::Output(181),
                Instruction::Output(448),
                Instruction::Output(271),
                Instruction::Add(400, 564, 244),
                Instruction::AddConst(331, 7, BitScalar::ZERO),
                Instruction::Mul(229, 222, 198),
                Instruction::AddConst(583, 401, BitScalar::ZERO),
                Instruction::Mul(582, 89, 4),
                Instruction::MulConst(306, 372, BitScalar::ONE),
                Instruction::MulConst(205, 158, BitScalar::ONE),
                Instruction::AddConst(132, 328, BitScalar::ONE),
                Instruction::Output(94),
                Instruction::MulConst(65, 181, BitScalar::ZERO),
                Instruction::Output(474),
                Instruction::Output(11),
                Instruction::Add(152, 76, 131),
                Instruction::Add(565, 197, 184),
                Instruction::Add(122, 403, 99),
                Instruction::Mul(290, 564, 217),
                Instruction::Mul(155, 549, 583),
                Instruction::Add(227, 20, 252),
                Instruction::Mul(508, 255, 84),
                Instruction::Add(45, 605, 127),
                Instruction::Mul(291, 282, 567),
                Instruction::Output(80),
                Instruction::MulConst(238, 290, BitScalar::ONE),
                Instruction::Mul(71, 56, 214),
                Instruction::Output(222),
                Instruction::Add(240, 351, 162),
                Instruction::Add(83, 244, 128),
                Instruction::MulConst(97, 200, BitScalar::ONE),
                Instruction::Add(263, 131, 603),
                Instruction::MulConst(178, 587, BitScalar::ZERO),
                Instruction::Mul(357, 372, 351),
                Instruction::Mul(504, 282, 108),
                Instruction::Mul(467, 450, 237),
                Instruction::Add(258, 177, 200),
                Instruction::Mul(176, 84, 180),
                Instruction::Output(582),
                Instruction::Output(10),
                Instruction::Add(354, 210, 41),
                Instruction::Output(222),
                Instruction::Mul(78, 252, 352),
                Instruction::Output(263),
                Instruction::Mul(489, 504, 302),
                Instruction::Mul(374, 551, 18),
                Instruction::Output(24),
                Instruction::AddConst(459, 255, BitScalar::ONE),
                Instruction::Output(4),
                Instruction::MulConst(251, 240, BitScalar::ONE),
                Instruction::MulConst(112, 400, BitScalar::ONE),
                Instruction::Output(477),
                Instruction::MulConst(368, 429, BitScalar::ZERO),
                Instruction::AddConst(215, 174, BitScalar::ZERO),
                Instruction::Mul(114, 135, 394),
                Instruction::Output(122),
                Instruction::MulConst(544, 229, BitScalar::ZERO),
                Instruction::Output(510),
                Instruction::MulConst(502, 609, BitScalar::ONE),
                Instruction::Output(463),
                Instruction::MulConst(380, 424, BitScalar::ZERO),
                Instruction::Add(322, 502, 472),
                Instruction::Output(18),
                Instruction::Output(46),
                Instruction::Add(608, 0, 242),
                Instruction::Add(471, 361, 162),
                Instruction::Output(573),
                Instruction::Mul(133, 152, 55),
                Instruction::MulConst(532, 564, BitScalar::ZERO),
                Instruction::MulConst(465, 356, BitScalar::ONE),
                Instruction::AddConst(534, 177, BitScalar::ZERO),
                Instruction::Output(534),
                Instruction::Output(177),
            ];

            let inputs = vec![
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ZERO,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
                BitScalar::ONE,
            ];
            test_proof::<GF2P8>(&program[..], &inputs[..]);
        }

        for _ in 0..1000 {
            test_random_proof::<GF2P8>();
        }
    }
}
*/
