# Reverie

![Stable Rust CI Status](https://github.com/trailofbits/zk-proof/workflows/stable/badge.svg)
![Nightly Rust CI Status](https://github.com/trailofbits/zk-proof/workflows/nightly/badge.svg)

Reverie is a work-in-process implementation (prover and verifier) of the MPC-in-the-head NIZKPoK outlined in
[Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures](https://eprint.iacr.org/2018/475).
Reverie seeks to offer concrete prover efficiency (linear proving time with small constants) for complex predicates.
The implementation seeks to offer 128-bits of (classical) security and support arbitrary rings, most efficiently Z_2, Z_8, Z_16, Z_32 and Z_64.