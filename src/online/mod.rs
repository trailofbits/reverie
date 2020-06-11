use super::RingElement;

use std::ops::Deref;

struct Src(usize);

struct Dst(usize);

enum Instr<E: RingElement> {
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
