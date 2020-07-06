/// Labels used in the Fiat-Shamir and "in-head" executions for domain-separation.

// RNG label for beaver triples
pub const LABEL_RNG_PREPROCESSING: &'static [u8] = "beaver_rng".as_bytes();

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
