#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SAR Protocol v1.0 — Binary Delta & Patching support (Milestone 9b).
//!
//! This crate provides:
//! * patch algorithm identifier constants (`SAR_L_PATCH`, spec section 8.4);
//! * the [`PatchAlgoId`] enum for type-safe algorithm representation;
//! * [`validate_patch_algo_id`] for registry enforcement;
//! * a display helper [`patch_algo_name`];
//! * [`apply_store_patch`] for `STORE_PATCH` (`0x00`) application;
//! * [`apply_bsdiff`] for `BSDIFF` (`0x02`) application (SAR BSDIFF40 profile);
//! * [`apply_vcdiff`] for `VCDIFF` (`0x01`) application (RFC 3284).
//!
//! # Supported patch algorithms
//!
//! | ID       | Name         | Status                                               |
//! |----------|--------------|------------------------------------------------------|
//! | `0x00`   | `STORE_PATCH`| assigned, mandatory; application **implemented**    |
//! | `0x01`   | `VCDIFF`     | assigned, mandatory; application **implemented**     |
//! | `0x02`   | `BSDIFF`     | assigned, optional;  application **implemented**     |
//! | `0x03`   | `ZSTD_PATCH` | assigned, optional;  application **not implemented** |
//! | `0x04–0xEF` | reserved  | `SAR_ERR_RESERVED_VALUE`                             |
//! | `0xF0–0xFF` | CUSTOM    | `SAR_ERR_UNSUPPORTED` unless negotiated              |
//!
//! # STORE_PATCH semantics
//!
//! `STORE_PATCH` (`0x00`) means:
//!
//! ```text
//! The decoded patch payload is the complete reconstructed target logical byte
//! sequence.
//! ```
//!
//! No base reads are performed.  No copy/insert instruction stream exists.
//! No external dictionary is used.  No external base object is required.
//!
//! The reconstructed output size MUST equal LFH `Uncompressed Size`.  If the
//! decoded patch payload length differs from `Uncompressed Size`,
//! [`apply_store_patch`] returns [`PatchError::PatchFailed`].
//!
//! All-zero `Delta Base Hash` is treated as "no base required" for
//! `STORE_PATCH` and is valid.
//!
//! # BSDIFF semantics
//!
//! `BSDIFF` (`0x02`) uses the SAR BSDIFF40 profile (spec §8.4.3).
//!
//! Base bytes MUST be supplied explicitly; automatic base discovery is not
//! performed.  All-zero `Delta Base Hash` MUST result in
//! [`PatchError::BaseMissing`]; this check belongs in the archive reader that
//! calls [`apply_bsdiff`].
//!
//! # VCDIFF semantics
//!
//! `VCDIFF` (`0x01`) follows RFC 3284 with the default code table
//! (s_near=4, s_same=3).
//!
//! Base bytes MUST be supplied explicitly; automatic base discovery is not
//! performed.  All-zero `Delta Base Hash` MUST result in
//! [`PatchError::BaseMissing`]; this check belongs in the archive reader.
//!
//! # Spec gaps
//!
//! * **ZSTD_PATCH application**: not implemented; the dictionary protocol is
//!   not defined by the spec.
//! * **Delta Base Hash algorithm**: treated as opaque bytes; no algorithm is
//!   assumed.
//! * **Base object resolution**: not implemented; callers must supply base
//!   bytes explicitly.

/// Patch algorithm ID constants (spec section 8.4, `SAR_L_PATCH`).
pub mod algo;

/// SAR BSDIFF40 profile patch application (spec §8.4.3).
pub mod bsdiff;

/// VCDIFF patch application per RFC 3284.
pub mod vcdiff;

pub use algo::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_CUSTOM_MAX, PATCH_ALGO_CUSTOM_MIN, PATCH_ALGO_STORE_PATCH,
    PATCH_ALGO_VCDIFF, PATCH_ALGO_ZSTD_PATCH, PatchAlgoId, PatchError, apply_store_patch,
    patch_algo_name, validate_patch_algo_id,
};
pub use bsdiff::{BsdiffLimits, apply_bsdiff, decode_bsdiff_int};
pub use vcdiff::{VcdiffLimits, apply_vcdiff};

