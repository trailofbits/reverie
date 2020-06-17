use super::RingElement;

#[derive(Copy, Clone)]
pub struct Src(usize);

#[derive(Copy, Clone)]
pub struct Dst(usize);

pub enum Instruction<E: RingElement> {
    AddConst(usize, usize, E), // addition of constant
    MulConst(usize, usize, E), // multiplication by constant
    Mul(usize, usize, usize),  // multiplication of two wires
    Add(usize, usize, usize),  // addition of two wires
    Ouput(usize),              // output wire (write wire-value to output)
}
