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
//! * [`generate_store_patch`] for `STORE_PATCH` (`0x00`) generation;
//! * [`apply_bsdiff`] for `BSDIFF` (`0x02`) application (SAR BSDIFF v1, `SARBSD01`);
//! * [`generate_bsdiff_patch`] for `BSDIFF` (`0x02`) generation;
//! * [`apply_vcdiff`] for `VCDIFF` (`0x01`) application (RFC 3284);
//! * [`generate_vcdiff_patch`] for `VCDIFF` (`0x01`) generation.
//!
//! # Supported patch algorithms
//!
//! | ID       | Name         | Status                                                        |
//! |----------|--------------|---------------------------------------------------------------|
//! | `0x00`   | `STORE_PATCH`| assigned, mandatory; application and generation **implemented**|
//! | `0x01`   | `VCDIFF`     | assigned, mandatory; application and generation **implemented**|
//! | `0x02`   | `BSDIFF`     | assigned, optional;  application and generation **implemented**|
//! | `0x03`   | `ZSTD_PATCH` | assigned, optional;  application **not implemented**           |
//! | `0x04–0xEF` | reserved  | `SAR_ERR_RESERVED_VALUE`                                      |
//! | `0xF0–0xFF` | CUSTOM    | `SAR_ERR_UNSUPPORTED` unless negotiated                       |
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
//! `BSDIFF` (`0x02`) uses SAR BSDIFF v1 (`SARBSD01`, spec §8.4.4).
//!
//! Base bytes MUST be supplied explicitly; automatic base discovery is not
//! performed.  All-zero `Delta Base Hash` MUST result in
//! [`PatchError::BaseMissing`]; this check belongs in the archive reader that
//! calls [`apply_bsdiff`].
//!
//! [`generate_bsdiff_patch`] produces a deterministic, bounded `SARBSD01`
//! patch using a single control triple.  Patch optimality is not guaranteed.
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
//! [`generate_vcdiff_patch`] produces a deterministic, bounded VCDIFF stream
//! using only ADD instructions.  COPY optimisation is not performed.
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

/// SAR BSDIFF v1 patch application and generation (`SARBSD01`, spec §8.4.4).
pub mod bsdiff;

/// VCDIFF patch application and generation per RFC 3284.
pub mod vcdiff;

pub use algo::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_CUSTOM_MAX, PATCH_ALGO_CUSTOM_MIN, PATCH_ALGO_STORE_PATCH,
    PATCH_ALGO_VCDIFF, PATCH_ALGO_ZSTD_PATCH, PatchAlgoId, PatchError, apply_store_patch,
    generate_store_patch, patch_algo_name, validate_patch_algo_id,
};
pub use bsdiff::{BsdiffLimits, apply_bsdiff, decode_bsdiff_int, generate_bsdiff_patch};
pub use vcdiff::{VcdiffLimits, apply_vcdiff, generate_vcdiff_patch};
