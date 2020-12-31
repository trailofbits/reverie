# Reverie Companion

## Building

The companion is build by running: `cargo build --release`

## Circuits
Reverie accepts circuits in the [Bristol Fashion](https://homes.esat.kuleuven.be/~nsmart/MPC/) circuit format. 
It is _not_ compatible with circuits written in the older "Bristol Format" circuit format. 

### Circuit I/O
The Bristol fashion specification does not make any recommendations for marking wires as inputs or outputs.
Therefore, Reverie places some  additional constraints on the wire indices used.
* Wires `0` through `n-1` must correspond to the first `n` bits of input

Reverie does _not_ place any specific requirements on the indices of the output wires. The `OUTPUT` gate may be used to 
explicitly output the value of a given wire. If no `OUTPUT` gates are found, the values of all wires will be displayed. 

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