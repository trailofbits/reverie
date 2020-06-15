use super::RingElement;

#[derive(Copy, Clone)]
pub struct Src(usize);

#[derive(Copy, Clone)]
pub struct Dst(usize);

pub enum Instruction<E: RingElement> {
    AddConst(Dst, Src, E), // addition of constant
    MulConst(Dst, Src, E), // multiplication by constant
    Mul(Dst, Src, Src),    // multiplication of two wires
    Add(Dst, Src, Src),    // addition of two wires
    Input(Dst),            // input wire (read wire from encrypted witness)
    Ouput(Src),            // output wire (write wire-value to output)
}

impl Into<usize> for Src {
    fn into(self) -> usize {
        self.0
    }
}

impl Into<usize> for Dst {
    fn into(self) -> usize {
        self.0
    }
}
