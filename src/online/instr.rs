use crate::algebra::RingElement;

#[derive(Copy, Clone)]
pub enum Instruction<E: RingElement> {
    AddConst(usize, usize, E), // addition of constant
    MulConst(usize, usize, E), // multiplication by constant
    Mul(usize, usize, usize),  // multiplication of two wires
    Add(usize, usize, usize),  // addition of two wires
    Output(usize),             // output wire (write wire-value to output)
}
