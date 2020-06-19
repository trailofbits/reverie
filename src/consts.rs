const PRF_TREE_LEFT: [u8; 16] = [1; 16];
const PRF_TREE_RIGHT: [u8; 16] = [2; 16];

/// Labels used in the Fiat-Shamir and "in-head" executions for domain-separation.

// RNG label for input masks
pub const LABEL_RNG_MASKS: &'static [u8] = "mask_rng".as_bytes();

// RNG label for beaver triples
pub const LABEL_RNG_BEAVER: &'static [u8] = "beaver_rng".as_bytes();

// RNG label for openings
pub const LABEL_RNG_OPEN_PREPROCESSING: &'static [u8] = "open_preprocessing".as_bytes();

// Scope label for correction bits (Beaver triples)
pub const LABEL_SCOPE_CORRECTION: &'static [u8] = "correction_elements".as_bytes();

// Scope label for aggregated commitment
pub const LABEL_SCOPE_AGGREGATE_COMMIT: &'static [u8] = "aggregate_commit".as_bytes();

// Scope label for correction bits (Beaver triples)
pub const LABEL_SCOPE_SENT: &'static [u8] = "sent_elements".as_bytes();
