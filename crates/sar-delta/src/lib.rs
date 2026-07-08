#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SAR Protocol v1.0 — Binary Delta & Patching support (Milestone 9b).
//!
//! This crate provides:
//! * patch algorithm identifier constants (`SAR_L_PATCH`, spec section 8.4);
//! * the [`PatchAlgoId`] enum for type-safe algorithm representation;
//! * [`validate_patch_algo_id`] for registry enforcement;
//! * a display helper [`patch_algo_name`].
//!
//! # Supported patch algorithms
//!
//! | ID       | Name         | Status                                               |
//! |----------|--------------|------------------------------------------------------|
//! | `0x00`   | `STORE_PATCH`| assigned, mandatory; application **not implemented** |
//! | `0x01`   | `VCDIFF`     | assigned, mandatory; application **not implemented** |
//! | `0x02`   | `BSDIFF`     | assigned, optional;  application **not implemented** |
//! | `0x03`   | `ZSTD_PATCH` | assigned, optional;  application **not implemented** |
//! | `0x04–0xEF` | reserved  | `SAR_ERR_RESERVED_VALUE`                             |
//! | `0xF0–0xFF` | CUSTOM    | `SAR_ERR_UNSUPPORTED` unless negotiated              |
//!
//! # Spec gaps
//!
//! The following items are **not implemented** due to unresolved specification
//! gaps.  See `docs/SPEC_QUESTIONS.md` for details.
//!
//! * **STORE_PATCH wire semantics**: The spec names `STORE_PATCH` as "Direct
//!   binary delta application" but does not define the on-wire format.
//!   Application is deferred until the format is normatively specified.
//!
//! * **VCDIFF, BSDIFF, ZSTD_PATCH application**: No application is implemented
//!   in this milestone.
//!
//! * **Delta Base Hash algorithm**: The `Delta Base Hash` 32-byte field carries
//!   no algorithm identifier.  The hash algorithm is unspecified by the spec;
//!   this implementation treats the field as opaque bytes and does **not**
//!   assume BLAKE3, SHA-256, or any other algorithm.
//!
//! * **Base object resolution**: The spec requires the base hash to uniquely
//!   identify a valid base object but does not define where base objects reside.
//!   Resolution is not implemented.
//!
//! * **Per-entry delta opt-out**: No `IS_DELTA` entry mode bit is defined.
//!   There is no spec-defined sentinel to indicate that an individual entry
//!   should bypass patching when `HAS_DELTA` is set globally.  All-zero
//!   `Delta Base Hash` has no special meaning unless the spec later defines one.

/// Patch algorithm ID constants (spec section 8.4, `SAR_L_PATCH`).
///
/// These are stored in the one-byte `Patch Algo ID` field of the Local File
/// Header when `HAS_DELTA` (Bit 9) is active globally.
pub mod algo;

pub use algo::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_CUSTOM_MAX, PATCH_ALGO_CUSTOM_MIN, PATCH_ALGO_STORE_PATCH,
    PATCH_ALGO_VCDIFF, PATCH_ALGO_ZSTD_PATCH, PatchAlgoId, PatchError, patch_algo_name,
    validate_patch_algo_id,
};
