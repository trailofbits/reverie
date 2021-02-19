# Reverie Companion

## Building

The companion is build by running: `cargo build --release`

## Circuits
Reverie accepts circuits in the [Bristol Fashion](https://homes.esat.kuleuven.be/~nsmart/MPC/) circuit format. 
It is _not_ compatible with circuits written in the older "Bristol Format" circuit format. 

The correct Bristol header conforms to the following format:
```
<Number of Gates> <Number of Wires>
<Number of inputs> [<Input bit size> ...]
<Number of outputs> [<Output bit size> ...]
```

### Circuit I/O
The Bristol fashion specification recommends the following convention for I/O wires:
* Wires `0` through `n-1` must correspond to the `n` bits of input
* Wires `<Number of Outputs> - n` through `<Number of outputs> - 1` must correspond to the n bits of output

Reverie will implicitly generate `INPUT` and `OUTPUT` gates according to this convention. 
To manually configure the circuit interface, one may set the numbers of inputs/outputs to zero and provide 
explicit `INPUT`/`OUTPUT` gates.

## Example Usage

A circuit example (circuit.txt) and a witness (input.txt) is provided for illustrational.
The circuit computes the SHA-256 compression function (no padding) of the input (512 bits) and outputs the resulting digest (256 bit).

Note that for many applications the output will simply be a single bit:
indicating whether the input satisfies a relation defined by the circuit.

### Proof Generation

```
$ ./target/release/reverie-companion --operation prove --program-format bristol --program-path circuit.txt --proof-path proof.out --witness-path witness.txt
```

### Proof Verification

Verification is very similar (but obviously you do not need to provide the witness).

```
$ ./target/release/reverie-companion --operation verify --program-format bristol --program-path circuit.txt --proof-path proof.out
[1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0]
```