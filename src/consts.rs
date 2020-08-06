/// Labels used in the Fiat-Shamir and "in-head" executions for domain-separation.

// RNG label for beaver triples
pub const LABEL_RNG_BEAVER: &'static [u8] = "beaver_rng".as_bytes();

// RNG label for beaver triples
pub const LABEL_RNG_INPUT: &'static [u8] = "input_rng".as_bytes();

// RNG label for branch information
pub const LABEL_RNG_BRANCH: &'static [u8] = "branch_rng".as_bytes();

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

// Number of instructions executed in a single batch
pub const BATCH_SIZE: usize = 10_000_000;

pub const CONTEXT_RNG_BEAVER: &'static str = "beaver_seed";

pub const CONTEXT_RNG_INPUT_MASK: &'static str = "input_mask_seed";

pub const CONTEXT_RNG_BRANCH_MASK: &'static str = "branch_mask_seed";

pub const CONTEXT_RNG_BRANCH_PERMUTE: &'static str = "branch_permute_seed";

pub const CONTEXT_RNG_CORRECTION: &'static str = "correction_seed";
