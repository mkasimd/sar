//! Fragment-group reassembly integration for SAR file-fragmentation (Section 19).
//!
//! This module re-exports the fragment descriptor model and validation/reassembly
//! functions from [`sar_fragmentation`].  Raw LFH fragment fields, `IS_FRAGMENT`,
//! `LAST_FRAGMENT`, and archive reader/writer integration remain in `sar-core`.
//!
//! The semantic reassembly logic lives in the `sar-fragmentation` crate.

pub use sar_fragmentation::{
    FragmentDescriptor, FragmentEntry, FragmentError, FragmentLimits, reconstruct_fragments,
    validate_fragment_group,
};
