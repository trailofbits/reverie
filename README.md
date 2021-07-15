# Speed-Reverie

Playground for ideas on how to speedup and simplify Reverie.

## Running

Using `SSE+AESNI`

    time RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+ssse3,+sse2" cargo run --release

Or even better with `AVX2+AESNI`

    time RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+ssse3,+sse2,+avx2" cargo run --release

## Ideas

- Pack 8 instances of 8 players over GF(2) into a single 64-bit integer (see [gist](https://gist.github.com/rot256/174fd53c0aac8cf04ef9810e8a10b0c0) for details).
- Switch to AES (with AESNI)?
- Stream intermediate result to disk to avoid doing 2 passed when proving.
