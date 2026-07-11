# SAR Crate Responsibilities (post-M11e)

This document records the current crate ownership boundaries in the monorepo.

## `sar-core`
Owns canonical wire format, status/error, limits, and low-level parse/write helpers.

Includes:
- Global Header/LFH/Central Dictionary/Footer/TLV wire structures and parsing/writing.
- Flag/entry-mode/status/error definitions and mapping.
- Resource-limit model and checked parsing/arithmetic helpers.
- Low-level sparse-map wire helpers.

Does not own:
- high-level archive reader/writer APIs,
- transform orchestration,
- archive-level recovery orchestration,
- stream-parser orchestration,
- crypto/KMS/key-provider APIs,
- delta/patch APIs,
- CLI filesystem behavior.

## `sar-archive`
Owns high-level archive behavior.

Includes:
- `ArchiveReader`/`ArchiveWriter` and options.
- Archive-level transform orchestration.
- Stream archive parser/profile APIs.
- Archive-level recovery/repair orchestration.
- Integration across compression/crypto/FEC/CDC/delta/fragment/sparse crates.

## `sar-cli`
Owns user-facing command behavior and extraction policy.

Includes:
- create/extract/list/verify/inspect/repair command surface.
- filesystem mutation behavior during extraction.
- metadata restoration policy gates and safe extraction defaults.

## `sar-crypto`
Owns crypto/KMS/key-provider/secret-buffer APIs.

Includes:
- KMS metadata and key-provider abstractions.
- secret-buffer types.
- cryptographic helper APIs used by archive/transport integration.

## `sar-delta`
Owns delta/patch algorithm APIs.

Includes:
- delta metadata and algorithm registry handling.
- implemented patch-application algorithms.

## `sar-stream`
Owns in-memory streaming/session semantics.

Boundary rule:
- `sar-stream` does **not** depend on `sar-archive`.

## Supporting crates
- `sar-compression`: compression codecs and bounded helpers.
- `sar-fec`: FEC algorithm and metadata helpers.
- `sar-cdc`: CDC metadata/chunk map support.
- `sar-fragmentation`: fragment semantics/reassembly helpers.
- `sar-sparse`: sparse semantic validation/reconstruction helpers.
- `sar-loss-tolerant`: loss-tolerant policy helpers.
- `sar-transport`: TCP/QUIC transport bindings over `sar-stream`.
- `sar-partition`: deferred placeholder crate.

## Re-export policy note
No compatibility re-export policy is implied by this document.
Ownership is determined by the current crate boundary and public surface in source/API inventory.
