# ZK Proof

![Stable Rust CI Status](https://github.com/rot256/zk-proof/workflows/stable/badge.svg)
![Nightly Rust CI Status](https://github.com/rot256/zk-proof/workflows/nightly/badge.svg)

A work-in-process implementation of the MPC-in-the-head NIZKPoK outlined in
[Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures](https://eprint.iacr.org/2018/475).
The implementation seeks to support the rings Z_2, Z_8, Z_16, Z_32 and Z_64,
while offering 128-bits of classical security.
