use super::*;

use crate::algebra::gf2::*;
use crate::algebra::Samplable;
use crate::util::VecMap;

use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use rand_core::RngCore;

fn random_scalar<D: Domain, R: RngCore>(rng: &mut R) -> <D::Sharing as RingModule>::Scalar {
    let mut share = vec![D::Sharing::ZERO; D::Batch::DIMENSION];
    let mut batch = vec![D::Batch::ZERO; D::Sharing::DIMENSION];
    batch[0] = D::Batch::gen(rng);
    D::convert(&mut share[..], &mut batch[..]);
    share[0].get(0)
}

fn random_input<D: Domain, R: RngCore>(
    rng: &mut R,
    length: usize,
) -> Vec<<D::Sharing as RingModule>::Scalar> {
    let mut input = Vec::with_capacity(length);
    for _ in 0..length {
        input.push(random_scalar::<D, _>(rng))
    }
    input
}

// Generates a random program for property based test
fn random_program<D: Domain, R: RngCore>(
    rng: &mut R,
    inputs: usize,
    length: usize,
) -> Vec<Instruction<<D::Sharing as RingModule>::Scalar>> {
    let mut program: Vec<Instruction<<D::Sharing as RingModule>::Scalar>> = Vec::new();
    let mut unassigned: Vec<usize> = (inputs..inputs + length).collect();
    let mut assigned: Vec<usize> = (0..inputs).collect();

    // we assign wires in random order
    unassigned.shuffle(rng);
    assert_eq!(unassigned.len(), length);

    for _ in 0..length {
        let choice = rng.gen::<usize>() % 5;

        // random source indexes
        let src1: usize = assigned[rng.gen::<usize>() % assigned.len()];
        let src2: usize = assigned[rng.gen::<usize>() % assigned.len()];

        match choice {
            0 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::Add(dst, src1, src2));
                assigned.push(dst);
            }
            1 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::Mul(dst, src1, src2));
                assigned.push(dst);
            }
            2 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::AddConst(dst, src1, random_scalar::<D, _>(rng)));
                assigned.push(dst);
            }
            3 => {
                let dst = unassigned.pop().unwrap();
                program.push(Instruction::MulConst(dst, src1, random_scalar::<D, _>(rng)));
                assigned.push(dst);
            }
            4 => {
                program.push(Instruction::Output(src1));
            }
            _ => unreachable!(),
        }
    }

    program
}

// Evaluates a program (in the clear)
fn evaluate<D: Domain>(
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    inputs: &[<D::Sharing as RingModule>::Scalar],
) -> Vec<<D::Sharing as RingModule>::Scalar> {
    let mut wires = VecMap::from(inputs.to_owned());
    let mut output = Vec::new();

    for step in program {
        match *step {
            Instruction::Add(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) + wires.get(src2));
            }
            Instruction::Mul(dst, src1, src2) => {
                wires.set(dst, wires.get(src1) * wires.get(src2));
            }
            Instruction::AddConst(dst, src, c) => {
                wires.set(dst, wires.get(src) + c);
            }
            Instruction::MulConst(dst, src, c) => {
                wires.set(dst, wires.get(src) * c);
            }
            Instruction::Output(src) => {
                output.push(wires.get(src));
            }
        }
    }

    output
}

fn test_proof<D: Domain, const N: usize, const NT: usize, const R: usize>(
    program: &[Instruction<<D::Sharing as RingModule>::Scalar>],
    inputs: &[<D::Sharing as RingModule>::Scalar],
) {
    let mut rng = thread_rng();
    let mut seeds: [[u8; KEY_SIZE]; R] = [[0; KEY_SIZE]; R];
    for i in 0..R {
        rng.fill_bytes(&mut seeds[i]);
    }

    // create a proof of the program execution
    let proof: Proof<D, N, NT, R> = Proof::new(&seeds, program, inputs);

    // evaluate program in the clear
    let correct_output = evaluate::<D>(program, inputs);

    // extract the output from the proof
    let proof_output = proof.verify(program).unwrap();

    // since the proof is generated correctly the proof output is "Some"
    // with the same value as the clear evaluation
    assert_eq!(
        proof_output.0, correct_output,
        "program = {:?}, inputs = {:?}",
        program, inputs
    );
}

fn test_random_proof<D: Domain, const N: usize, const NT: usize, const R: usize>() {
    let mut rng = thread_rng();

    let inputs = (rng.gen::<usize>() % 126) + 1;
    let length = (rng.gen::<usize>() % 1024) + 1;
    let program = random_program::<D, _>(&mut rng, inputs, length);
    for ins in program.iter() {
        println!("{:?}", ins);
    }

    let input = random_input::<D, _>(&mut rng, inputs);
    for val in input.iter() {
        println!("{:?}", val);
    }
    test_proof::<D, N, NT, R>(&program[..], &input[..])
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
        test_proof::<GF2P8, 8, 8, 1>(&program[..], &inputs[..]);
    }

    for _ in 0..1000 {
        test_random_proof::<GF2P8, 8, 8, 1>();
    }
}
