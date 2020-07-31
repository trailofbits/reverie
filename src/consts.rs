/// Labels used in the Fiat-Shamir and "in-head" executions for domain-separation.

// RNG label for beaver triples
pub const LABEL_RNG_BEAVER: &'static [u8] = "beaver_rng".as_bytes();

// RNG label for beaver triples
pub const LABEL_RNG_INPUT: &'static [u8] = "input_rng".as_bytes();

// RNG label for openings
pub const LABEL_RNG_OPEN_PREPROCESSING: &'static [u8] = "open_preprocessing".as_bytes();

// RNG label for openings
pub const LABEL_RNG_OPEN_ONLINE: &'static [u8] = "open_online".as_bytes();

// Scope label for correction bits (Beaver triples)
pub const LABEL_SCOPE_ONLINE_TRANSCRIPT: &'static [u8] = "online_transcript".as_bytes();

// Scope label for correction bits (Beaver triples)
pub const LABEL_SCOPE_CORRECTION: &'static [u8] = "correction_elements".as_bytes();

// Scope label for aggregated commitment
pub const LABEL_SCOPE_AGGREGATE_COMMIT: &'static [u8] = "aggregate_commit".as_bytes();

// execute up to 10 000 000 instructions in a single batch
// this is sufficient for smaller proofs to fit inside a single batch,
// however still enables the providing of any relation even with limited memory.
pub const BATCH_SIZE: usize = 10_000_000;
