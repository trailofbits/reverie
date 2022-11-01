# Reverie

An efficient implementation of the NIZKPoK outlined in KKW 2018

[![CI](https://github.com/trailofbits/reverie/actions/workflows/ci.yml/badge.svg)](https://github.com/trailofbits/reverie/actions/workflows/ci.yml)

Reverie is an implementation (prover and verifier) of the MPC-in-the-head NIZKPoK outlined in
[Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures](https://eprint.iacr.org/2018/475).
Reverie seeks to offer concrete prover efficiency (linear proving time with small constants) for
complex predicates. The implementation seeks to offer 128-bits of (classical) security and support
arbitrary rings, most efficiently
Z<sub>2</sub> and Z<sub>64</sub>.

Reverie provides both a library (with a simplified and a streaming interface),
in addition to a CLI program for proving/verifying statements specified in Bristol format
to enable easy experimentation.

## Running
Reverie requires a relatively recent `nightly` Rust.

Using `SSE+AESNI`

    time RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+ssse3,+sse2" cargo run --release

Or even better with `AVX2+AESNI`

    time RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+ssse3,+sse2,+avx2" cargo run --release

## Improvements in 0.3+

- Pack 8 instances of 8 players over GF(2) into a single 64-bit integer (see [gist](https://gist.github.com/rot256/174fd53c0aac8cf04ef9810e8a10b0c0) for details).
- Switch to AES with AESNI
- Just-in-time preprocessing to condense proving into a single pass
