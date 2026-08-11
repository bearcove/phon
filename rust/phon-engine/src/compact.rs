//! The compact PHON storage profile.
//!
//! Physical schema-driven encoding, decoding, registry validation, and schema
//! resolution live in `phon-storage`; the engine re-exports that API for
//! compatibility planning and typed execution.

pub use phon_storage::compact::*;
