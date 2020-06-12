use super::algebra::{RingBatch, RingElement};

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

struct PlayerState<B: RingBatch> {
    // packed ring shares
    wires: Vec<B>,
}

impl<B: RingBatch> PlayerState<B> {
    fn get(&self, label: usize) -> B::Element {
        let rem = label % B::BATCH_SIZE;
        let div = label / B::BATCH_SIZE;
        self.wires[div].get(rem)
    }

    fn set(&self, label: usize, v: B::Element) {
        let rem = label % B::BATCH_SIZE;
        let div = label / B::BATCH_SIZE;

        // TODO: consider pre-allocating at instantiation to avoid reallocation
        if div >= self.wires.len() {
            self.wires.reserve_exact(div - self.wires.len() + 1);
            while div >= self.wires.len() {
                self.wires.push(B::zero())
            }
        }

        self.wires[div].set(rem, v)
    }
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
