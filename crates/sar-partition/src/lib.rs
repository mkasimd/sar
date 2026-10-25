// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Partition/multi-volume archive-set support for SAR archives.
//!
//! # Current status: deliberately deferred (M11c)
//!
//! This crate is intentionally kept as a minimal stub.  Partition and
//! multi-volume behavior has not been fully specified for SAR v1.  The
//! following items remain in `sar-core` until partition support is implemented:
//!
//! * `PARTITIONED_ARCHIVE` global flag (the Global Header carries no inline
//!   partition descriptor; processing entry points return `Unsupported`);
//! * archive reader/writer integration for partitioned archives.
//!
//! This crate will be populated when partition support becomes an active
//! SAR v1 target.  Do not remove it; it marks the intended future
//! ownership boundary.

/// Marker for not-yet-implemented partition functionality.
///
/// Kept as a named type so the crate compiles cleanly and clearly
/// communicates that partition logic is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotImplemented;
