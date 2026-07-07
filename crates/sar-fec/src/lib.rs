#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Forward Error Correction (FEC) codecs for SAR Protocol v1.0 (Milestones 6–7).
//!
//! Implements archive-level Data Recovery TLVs (Section 9.2) and file-level
//! Selective FEC (Section 6.1.3) for the following algorithms:
//!
//! * XOR FEC `0x14` (Milestone 6)
//! * Reed-Solomon FEC `0x11` (Milestone 7)
//!
//! # FEC model
//!
//! SAR FEC is **erasure recovery**: callers must supply the explicit positions of
//! missing or corrupt blocks before invoking recovery. Unknown erasure locations
//! are not guessed; [`FecError::RecoveryUnavailable`] is returned instead.
//!
//! # Pipeline order (AEAD + FEC)
//!
//! ```text
//! stored payload → FEC repair (ciphertext only) → AEAD verify/decrypt
//!               → decompression → logical output
//! ```
//!
//! Without AEAD:
//!
//! ```text
//! stored payload → FEC repair → decompression/STORE → logical output
//! ```

/// FEC error type (no dependency on sar-core to avoid circular crate deps).
pub mod error;
/// Algorithm registry and validation.
pub mod registry;
/// Reed-Solomon FEC codec.
pub mod rs;
/// Shared FEC types and codec trait.
pub mod types;
/// XOR FEC codec.
pub mod xor;

pub use error::FecError;
pub use registry::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR, parse_fec_value, validate_fec_algo_id};
pub use rs::RsCodec;
pub use types::{
    Erasure, FecCodec, FecMeta, FecOptions, FecRecoverInput, FecValue, RsMeta, XorMeta,
};
pub use xor::XorCodec;
