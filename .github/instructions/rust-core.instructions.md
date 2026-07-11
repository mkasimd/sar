---
applyTo: "crates/**/*.rs"
---

# Rust crate implementation rules

* Keep SAR wire format stable unless explicitly asked to change it.
* Preserve LFH field order, Global Flags semantics, Entry Mode semantics, status/error semantics, and transform ordering.
* Prefer small, explicit crate boundaries.
* Do not add compatibility-only re-exports unless explicitly requested.
* `sar-core` should stay focused on canonical wire-format, status/error, limits, checked parsing/writing primitives, and low-level helpers.
* High-level archive integration belongs outside `sar-core` when the current milestone requires that split.

## Safety

* Use stable Rust.
* Avoid `unsafe`; justify and test it if unavoidable.
* Do not use raw `as usize` casts for wire sizes, offsets, payload sizes, fragment spans, sparse extents, or allocation sizes.
* Use `usize::try_from(...)` and checked arithmetic.
* Enforce resource limits before allocation, decompression, patching, sparse reconstruction, fragment reconstruction, or buffering.
* Do not introduce unbounded buffering for unknown-size streams.

## Transform invariants

* Decode order: FEC/repair before decrypt, decrypt before decompress, decompress before patch, patch before sparse reconstruction.
* Encode order: logical data to patch, then compression, then encryption.
* AEAD/authentication failure is never loss-tolerant.
* `LOSS_TOLERANT` must not suppress authentication, decompression, patch, sparse, fragment, structural, bounds, overflow, or validation failures unless explicitly specified.
