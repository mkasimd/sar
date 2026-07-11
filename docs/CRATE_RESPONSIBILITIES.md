# SAR Crate Responsibilities

This document defines the intended crate ownership boundaries for the SAR reference implementation.

It is normative for repository architecture, but it does not define SAR wire format behavior. The SAR protocol specification remains authoritative for wire format, validation rules, status codes, and interoperability requirements.

When implementation logic appears in a crate different from the ownership described here, the implementation should either be moved during a modularity milestone or the crate responsibility should be deliberately revised.

`docs/MACHINE_READABLE_API.json` describes the currently exposed API surface. This document describes the intended final ownership model.

# Expected Final Crate Responsibilities

## `sar-core`

Final role: canonical SAR archive format crate.

`sar-core` should own the wire format, archive structure, shared status model, and high-level archive reader/writer integration. It should remain the crate that other SAR crates integrate through, but it should not own every domain-specific algorithm.

Should contain:

* SAR status/error registry.
* `SarError` / `SarStatus` mapping.
* Global Header parse/write.
* Global Flags model.
* LFH parse/write.
* Entry Mode semantics.
* Central Directory parse/write.
* Footer parse/write.
* TLV parse/write.
* KMS metadata structural parsing.
* archive-level resource limits.
* canonical little-endian parsing primitives.
* checked arithmetic helpers.
* bounded allocation helpers.
* raw metadata structs for:

  * sparse map fields;
  * fragment descriptor fields;
  * FEC metadata fields;
  * CDC LFH metadata;
  * delta LFH metadata;
  * encryption metadata;
  * stream ID / sequence number fields.
* archive reader/writer APIs.
* indexed archive validation.
* `NO_INDEX` archive processing.
* transform pipeline orchestration.
* integration with:

  * `sar-compression`;
  * `sar-crypto`;
  * `sar-fec`;
  * `sar-cdc`;
  * `sar-delta`;
  * `sar-fragmentation`;
  * `sar-sparse`;
  * `sar-loss-tolerant`.
* profile/conformance reporting hooks.
* high-level convenience APIs such as `ArchiveReader` and `ArchiveWriter`.

Should keep, at least as integration APIs:

* `ArchiveReader`.
* `ArchiveWriter`.
* `EntryInput`.
* `EntryMetadata`.
* `EntryReader`.
* `LogicalFile`.
* `ArchiveReaderOptions`.
* `ArchiveWriterOptions`.
* `ResourceLimits`.
* `VerificationReport`.

Should eventually move out or delegate:

* fragment grouping and reassembly logic → `sar-fragmentation`;
* sparse map semantic validation and reconstruction planning → `sar-sparse`;
* LOSS_TOLERANT degradation policy → `sar-loss-tolerant`;
* partition set discovery/validation/recovery → `sar-partition`.

Should not contain:

* compression algorithm implementations;
* AEAD/hash/signature algorithm implementations;
* FEC algorithms;
* CDC chunking algorithms;
* delta patch algorithms;
* real TCP/QUIC transport implementation;
* CLI behavior;
* language bindings.

Expected final shape:

```text
sar-core:
  owns canonical archive format and integration APIs.
  delegates specialized behavior to specialized crates.
```

---

## `sar-compression`

Final role: compression registry and bounded compression/decompression implementation.

Current state appears mostly correct.

Should contain:

* compression algorithm registry constants:

  * STORE;
  * DEFLATE;
  * ZSTD.
* `CompressionAlgorithm`.
* compression options.
* decompression options.
* bounded encode/decode helpers.
* reserved/unsupported algorithm handling.
* decompression output limits.
* expansion-bomb protections at compression layer.
* streaming encode/decode helpers over `Read`/`Write`.
* tests for:

  * STORE round trip;
  * DEFLATE round trip;
  * ZSTD round trip;
  * output limit failure;
  * malformed compressed payload;
  * unsupported/reserved IDs.

Should not contain:

* archive parsing;
* LFH parsing;
* encryption/decryption;
* FEC;
* sparse reconstruction;
* CLI behavior.

Expected final shape:

```text
sar-compression:
  pure transform crate for compression.
  no archive ownership.
```

---

## `sar-crypto`

Final role: cryptographic primitives, KMS metadata helpers, hash/signature/AEAD implementation.

Current state appears mostly correct, with M10e/M10h adding TLS_EXPORTER-related helper responsibility.

Should contain:

* hash registry:

  * SHA-256;
  * BLAKE3;
  * assigned-but-unsupported hash IDs.
* hash computation helpers.
* content hash validation helpers.
* AEAD registry:

  * AES-256-GCM;
  * XChaCha20-Poly1305 where implemented;
  * unsupported/reserved ID handling.
* AEAD encrypt/decrypt helpers.
* AAD construction helpers where crypto-specific.
* signature registry and verification helpers:

  * Ed25519;
  * RSA-PSS where supported;
  * unsupported assigned algorithms.
* KMS mode registry.
* KMS payload parsing/serialization.
* KMS validation:

  * no raw content-encryption keys in archive metadata;
  * no TLS exporter output in SAR frames;
  * no plaintext keys in KMS Data.
* key provider traits or future callback-neutral key resolution model.
* TLS_EXPORTER KMS helpers:

  * TLS exporter KMS payload parse/write;
  * context version parsing;
  * exporter context encoding;
  * key usage IDs;
  * SAR AEAD key derivation input validation.
* secret-handling hygiene.
* tests for:

  * AEAD auth failure;
  * AAD mismatch;
  * unsupported KMS;
  * malformed KMS;
  * TLS_EXPORTER context mismatch;
  * no plaintext exposure before auth.

Should not contain:

* actual QUIC/TCP transport;
* archive reader/writer ownership;
* file extraction;
* CLI;
* CDC/delta/FEC algorithms.

Expected final shape:

```text
sar-crypto:
  all cryptographic algorithms and KMS/key-derivation helpers.
  transport crates may supply TLS exporter bytes, but crypto derives/validates SAR keying material.
```

---

## `sar-fec`

Final role: FEC/recovery algorithms and FEC metadata validation.

Current state appears mostly correct.

Should contain:

* FEC algorithm registry.
* XOR FEC implementation.
* Reed-Solomon FEC implementation.
* FEC configuration parsing helpers.
* FEC payload validation.
* recovery/repair helpers.
* shard/parity validation.
* reserved/unsupported FEC ID handling.
* tests for:

  * XOR repair;
  * Reed-Solomon repair;
  * malformed FEC metadata;
  * too many missing shards;
  * reserved/unsupported IDs;
  * FEC-before-decrypt ordering integration through `sar-core`.

Should not contain:

* archive reader/writer ownership;
* fragmentation grouping;
* sparse reconstruction;
* transport logic.

Expected final shape:

```text
sar-fec:
  recovery coding algorithms and FEC-specific validation.
```

---

## `sar-cdc`

Final role: content-defined chunking algorithms and CDC metadata model.

Current state appears mostly correct. It already has FASTCDC, CDC_MAP structures, CDC_MAP parse/write, validation, and hash verification helpers according to the machine-readable API.

Should contain:

* CDC algorithm registry:

  * LITERAL;
  * FASTCDC;
  * assigned unsupported algorithms;
  * custom ranges.
* FASTCDC implementation.
* CDC chunk model.
* CDC metadata model.
* CDC_MAP parse/write.
* CDC_MAP record hash verification.
* CDC_EXT_PROVIDER inert metadata model if kept here or mirrored through `sar-core`.
* CDC recipe structural validation.
* CDC metadata validation.
* tests for:

  * FASTCDC deterministic local-profile behavior;
  * CDC_MAP parse/write;
  * CDC_MAP reserved fields;
  * CDC_MAP hash verification;
  * invalid chunk boundaries;
  * recipe payload length validation.
* clear documentation that stored CDC metadata is authoritative and FASTCDC boundary regeneration is not a portable conformance guarantee unless the spec later defines exact parameters.

Should not contain:

* full archive reader/writer;
* external provider network resolution;
* CAS fetching;
* delta patching;
* partition recovery.

Expected final shape:

```text
sar-cdc:
  CDC algorithms and CDC metadata.
  no external CAS/network resolution in baseline.
```

---

## `sar-delta`

Final role: delta patch algorithm crate.

Current state appears mostly correct after M9b.

Should contain:

* delta algorithm registry:

  * STORE_PATCH;
  * VCDIFF;
  * SAR BSDIFF v1;
  * assigned unsupported algorithms;
  * custom ranges.
* patch metadata validation.
* delta base identity helpers.
* delta base hash validation helpers.
* STORE_PATCH apply/create.
* VCDIFF apply/create where implemented.
* SAR BSDIFF v1 apply/create where implemented.
* decode-side patch application helpers.
* encode-side patch representation helpers.
* tests for:

  * STORE_PATCH;
  * VCDIFF;
  * SAR BSDIFF v1;
  * missing base;
  * mismatched base hash;
  * unsupported/reserved patch IDs;
  * transform-order integration.

Should not contain:

* compression implementation;
* encryption implementation;
* archive parsing;
* CDC recipe resolution;
* filesystem extraction.

Expected final shape:

```text
sar-delta:
  patch algorithms and base validation.
  `sar-core` decides where in the transform pipeline to invoke it.
```

---

## `sar-fragmentation`

Final role: fragment model, validation, grouping, and reassembly planning.

**M11c status: Implemented.** Fragment semantic logic has been moved from `sar-core` to this crate.

### What was moved from `sar-core` (M11c)

* `FragmentDescriptor` — fragment absolute-offset and size model.
* `FragmentEntry` — per-fragment payload and metadata envelope.
* `validate_fragment_group` — validates fragment count limits, fragment-group span limits, descriptor bounds, and descriptor non-overlap.
* `reconstruct_fragments` — validates duplicate `fragment_index`, payload length agreement, index gaps, missing `LAST_FRAGMENT`, descriptor byte-range gaps (initial/middle/tail), and reassembles payloads with LOSS_TOLERANT degraded-output policy.
* `FragmentError` — crate-local error type.
* `FragmentLimits` — resource limits for fragment operations (`max_fragment_count`, `max_fragment_group_span`, `max_decoded_entry_size`, `max_loss_tolerant_gap`, `max_allocation_bytes`).

### What remains in `sar-core`

* `LFH fragment descriptor fields` — raw LFH parse/write fields (fragment ID, index, absolute offset, fragment size, LAST_FRAGMENT bit).
* `FILE_FRAGMENTATION` / `IS_FRAGMENT` / `LAST_FRAGMENT` flag constants.
* `archive reader/writer fragment integration` — calls into `sar-fragmentation` via `limits.fragment_limits()`.
* `From<FragmentError> for SarError` — error propagation bridge.
* `ResourceLimits::fragment_limits()` — converts `ResourceLimits` to `FragmentLimits`.

**M11c corrective pass (M11c-cp):** The `sar_core::fragment` module has been **removed**. It was a thin compatibility re-export with no architectural justification. Callers must import fragment types directly from `sar-fragmentation`.

### Dependency direction

```
sar-core → sar-fragmentation  (one-way, no cycle)
sar-fragmentation has no dependency on sar-core
```

### Deferred

None. All identified semantic logic has been moved.

Should contain:

* fragment descriptor model:

  * Fragment ID;
  * Fragment Index;
  * absolute offset;
  * fragment size;
  * LAST_FRAGMENT state.
* fragment group model.
* fragment ordering helpers.
* duplicate fragment detection.
* overlap detection.
* missing fragment detection.
* fragment group span validation.
* fragment count limits.
* reassembly planning.
* reassembly execution over already-decoded logical payload fragments.
* integration hooks for LOSS_TOLERANT degraded output.
* validation that `LAST_FRAGMENT` requires `IS_FRAGMENT`.
* validation that `(Fragment ID, Fragment Index)` is unique.
* validation that fragment descriptors do not overlap.
* tests for:

  * complete reassembly;
  * missing fragment;
  * duplicate fragment;
  * overlapping fragments;
  * out-of-order fragments;
  * LAST_FRAGMENT without IS_FRAGMENT;
  * max fragment count;
  * max fragment group span.

Should not contain:

* LFH binary parser ownership;
* sparse map parser ownership;
* AEAD/decompression/patch/FEC implementations;
* CLI extraction behavior;
* transport session behavior.

Expected final shape:

```text
sar-fragmentation:
  semantic fragment validation and reassembly.
  raw LFH fields stay in `sar-core`; fragment algorithms live here.
```

---

## `sar-sparse`

Final role: sparse extent model, sparse map semantic validation, and sparse reconstruction planning.

**M11c status: Implemented.** Sparse semantic logic has been moved from `sar-core` to this crate.

### What was moved from `sar-core` (M11c)

* `SparseExtent` — offset/length model for a sparse data region.
* `validate_sparse_extents` — validates non-zero extent length, sorted order, non-overlap, bounds within logical size, arithmetic overflow safety, and descriptor-count limits.
* `apply_sparse_reconstruction` — scatter/gather reconstruction of logical file from payload and extent map; validates payload-length agreement because it receives payload bytes.
* `SparseError` — crate-local error type.
* `SparseLimits` — resource limits for sparse operations (`max_sparse_map_bytes`, `max_sparse_descriptors`, `max_decoded_entry_size`, `max_allocation_bytes`).

### What remains in `sar-core`

* `parse_sparse_map` / `write_sparse_map` — wire-format binary parse/write of the LFH sparse map blob; remain in `sar-core` because moving them would require `sar-sparse` to depend on `sar-core` (creating a cycle).
* `SparseExtent` — re-exported from `sar_core::sparse` because `parse_sparse_map` and `write_sparse_map` return/accept it; callers of those wire-format functions must not need a direct `sar-sparse` dependency to name the type.  This re-export is **architectural**, not a compatibility shim.
* `SPARSE_FILES` flag.
* `archive reader/writer sparse integration` — calls into `sar-sparse` via `limits.sparse_limits()`.
* `From<SparseError> for SarError` — error propagation bridge.
* `ResourceLimits::sparse_limits()` — converts `ResourceLimits` to `SparseLimits`.

**M11c corrective pass (M11c-cp):** Semantic sparse re-exports (`SparseError`, `SparseLimits`, `validate_sparse_extents`, `apply_sparse_reconstruction`) have been **removed** from `sar_core::sparse`. `SparseExtent` is kept as documented above. Callers must import semantic sparse types directly from `sar-sparse`.

### Dependency direction

```
sar-core → sar-sparse  (one-way, no cycle)
sar-sparse has no dependency on sar-core
```

### Deferred

`parse_sparse_map` / `write_sparse_map` remain in `sar-core`. Moving them would require `sar-sparse → sar-core` which creates a cycle. These are wire-format functions explicitly listed as "must remain in `sar-core`" by the spec boundary.

Should contain:

* sparse extent model.
* sparse map model.
* sparse map parse/write helpers if not kept as raw parsing in `sar-core`.
* sparse map semantic validation:

  * sorted extents;
  * non-overlap;
  * non-zero lengths;
  * bounds within logical size;
  * payload length equals sum of extents.
* sparse reconstruction planner.
* sparse reconstruction executor for in-memory/test use.
* scatter/gather write planning for extraction.
* expansion-bomb protection helpers.
* rules for fragmentation interaction:

  * sparse map describes fully reconstructed logical file;
  * if fragmentation is used, sparse map appears only on fragment index 0;
  * sparse map on non-zero fragment index returns `SAR_ERR_INVALID_MAP`.
* tests for:

  * valid sparse reconstruction;
  * trailing holes;
  * leading holes;
  * overlapping extents;
  * extent beyond logical size;
  * payload length mismatch;
  * sparse map on non-zero fragment;
  * expansion-bomb limit failure.

Should not contain:

* full archive reader/writer ownership;
* platform-specific file permission restoration;
* path traversal protection;
* fragmentation grouping;
* AEAD/decompression/patch logic.

Expected final shape:

```text
sar-sparse:
  sparse-file semantics and reconstruction planning.
  `sar-core` integrates it into archive read/write.
```

---

## `sar-loss-tolerant`

Final role: recoverable-vs-fatal degradation policy.

**M11c status: Implemented.** Policy helpers have been added to this crate. `sar-fragmentation` now depends on `sar-loss-tolerant` and calls `gap_degraded_output_permitted()` directly for missing-fragment gap decisions; LOSS_TOLERANT policy is no longer duplicated inline in `sar-fragmentation`.

### What was added (M11c)

* `RecoveryStatus` — enum: `Complete`, `Degraded`, `Failed`.
* `gap_degraded_output_permitted(is_loss_tolerant: bool) -> bool` — returns whether a missing-fragment gap may produce degraded output.
* `classify_recovery(has_gap: bool, failed: bool) -> RecoveryStatus` — classifies reconstruction outcome.
* Documented invariant: LOSS_TOLERANT never suppresses AEAD/authentication failures, signature failures, decompression failures, patch failures, malformed structure, invalid sparse maps, invalid fragment metadata, or deterministic reconstruction failures.

### What remains in `sar-core`

* `LOSS_TOLERANT` flag.
* Fail-closed behavior for auth/decompression/patch/structural failures.
* Archive reader/writer integration.
* Transform ordering (LOSS_TOLERANT never changes transform order).
* Status/error mapping.

### Dependency direction

```
sar-fragmentation → sar-loss-tolerant  (one-way; sar-fragmentation calls gap_degraded_output_permitted)
sar-loss-tolerant has no dependency on sar-core or sar-fragmentation
sar-core does not depend on sar-loss-tolerant directly
```

### Deferred

Integration of `RecoveryStatus` into archive reader return types is deferred. The current integration in `sar-core` uses its own `is_degraded: bool` flag. Migrating to `RecoveryStatus` would be an API-breaking change that can be done in a future milestone.

Should contain:

* LOSS_TOLERANT policy model.
* degraded reconstruction decision helpers.
* recoverable/fatal error classification.
* `SAR_WARN_INCOMPLETE` handling helpers if applicable.
* policy that LOSS_TOLERANT may permit degraded output only when meaningful output is possible.
* policy that LOSS_TOLERANT never suppresses:

  * AEAD/authentication failures;
  * signature failures;
  * decompression failures;
  * patch failures;
  * structural corruption;
  * malformed LFH/GH/CD/Footer;
  * invalid sparse maps;
  * deterministic reconstruction failures.
* integration helpers for:

  * missing fragments;
  * unavailable FEC;
  * partial recovery;
  * bounded gaps.
* tests for:

  * lossy missing fragment allowed;
  * non-lossy missing fragment rejected;
  * AEAD failure not suppressed;
  * decompression failure not suppressed;
  * patch failure not suppressed;
  * structural malformed data not suppressed;
  * max loss-tolerant gap limit.

Should not contain:

* fragment reassembly algorithm itself;
* sparse reconstruction algorithm itself;
* cryptographic verification;
* transport-level loss handling;
* CLI behavior.

Expected final shape:

```text
sar-loss-tolerant:
  degradation policy crate.
  other crates ask it whether a failure may produce degraded output.
```

---

## `sar-partition`

Final role: partition/multi-volume archive-set support, if SAR v1 keeps this as an active feature.

**M11c status: Deliberately deferred.** No partition/multi-volume behavior has been invented or implemented. The crate exists as a planned placeholder.

### What remains in `sar-core`

* `PartitionDescriptor` struct.
* `PARTITIONED_ARCHIVE` flag.

These must remain in `sar-core` because they are wire-format fields. Moving them to `sar-partition` would require `sar-core` to depend on `sar-partition` for integration, which creates a cycle, or require duplication of wire-format structs.

### Deferred reason

Partition/multi-volume spec behavior is not fully defined for SAR v1. No existing implementation to move. Partition functionality is explicitly listed as out-of-scope for M11c.

Should contain, if partition support remains in scope:

* partition descriptor model.
* partition descriptor parse/write.
* partition set UUID validation.
* partition index validation.
* partition count validation.
* previous/next partition hash validation.
* partition chain validation.
* partition discovery helpers that do not rely only on filenames.
* partition set recovery planning.
* partition consistency verification.
* rules:

  * Partition Descriptor fixed length if still defined as 96 bytes;
  * partition index zero-based;
  * partition 0 previous hash all zeroes;
  * non-final partitions set `NO_INDEX`;
  * non-final partitions do not contain CD/Footer;
  * if archive-wide `NO_INDEX` is set, no partition contains CD/Footer.
* tests for:

  * valid partition chain;
  * missing partition;
  * wrong partition UUID;
  * wrong previous hash;
  * duplicate partition index;
  * final/non-final CD/Footer rules;
  * filename-independent discovery.

Should be removed later if:

* partition/multi-volume behavior is not part of the active SAR v1 target;
* no spec section defines partition descriptors or recovery;
* no public API will expose partition sets;
* no conformance profile will require or optionally test it.

Should not contain:

* generic fragmentation behavior;
* FEC algorithms;
* CDC partition IDs unless explicitly tied by spec;
* transport streams;
* CLI extraction logic.

Expected final shape:

```text
sar-partition:
  keep only if partitioned/multi-volume SAR archives are real SAR v1 scope.
  otherwise retire deliberately during modularity consolidation.
```

---

## `sar-stream`

Final role: SAR Stateful Streaming Mode session semantics.

Current state appears mostly correct after M10b.

Should contain:

* session state machine.
* Stream ID lifecycle.
* Session UUID binding.
* SESSION_CONTROL parser/serializer at the semantic layer.
* SESSION_INIT.
* SESSION_CLOSE.
* SESSION_RESUME semantics or unsupported handling.
* SESSION_HEARTBEAT.
* SESSION_STATUS.
* SESSION_ACK.
* SESSION_METADATA.
* SESSION_CAPABILITIES.
* sequence number validation/continuity helpers.
* bidirectional control/session mode negotiation logic.
* LOSS_TOLERANT stream-boundary semantics where they are session-level.
* in-memory/session-only tests.
* no real transport I/O.

Should not contain:

* TCP sockets;
* QUIC sockets;
* TLS exporter extraction;
* archive compression/crypto/FEC algorithms;
* CLI.

Expected final shape:

```text
sar-stream:
  pure Stateful Streaming Mode session layer.
  transport-independent.
```

---

## `sar-transport`

Final role: transport abstraction plus concrete TCP/QUIC bindings.

Current state: M10i-complete.  `CTL!` was removed in M10h and remains absent.  `InMemoryTransport::with_key_provider` was added in M10i to support TLS_EXPORTER post-binding SAR-AEAD enforcement.

Should contain:

* transport abstraction traits/types.
* in-memory transport harness.
* TCP binding.
* QUIC binding behind feature flag.
* transport policy model.
* stream/session mapping.
* status/ack emission hooks.
* SAR-over-TCP rules:

  * sequential streams;
  * no byte interleaving;
  * invalid stream close behavior.
* SAR-over-QUIC rules:

  * primary stream begins with `SAR!` + Global Header;
  * additional control stream begins directly with LFH SESSION_CONTROL;
  * no `CTL!`;
  * no private envelope;
  * association by QUIC connection + LFH Stream ID.
* TLS_EXPORTER integration with QUIC/TLS exporter material.
* TLS_EXPORTER post-binding SAR-AEAD enforcement: after SESSION_INIT, all subsequent entries MUST carry EntryMode::ENCRYPTED; plaintext entries are rejected with AuthFailed.
* Key provider injection (`with_key_provider`) for SAR-layer AEAD decryption.
* PQ/hybrid TLS policy configuration.
* stream-local vs connection-fatal error behavior.
* loopback tests.
* transport docs.

Should not contain:

* compression algorithms;
* AEAD algorithms themselves;
* archive format parser duplication;
* session state duplication already owned by `sar-stream`;
* CDC/delta/FEC/sparse algorithms.

Expected final shape:

```text
sar-transport:
  concrete transport bindings.
  delegates session semantics to `sar-stream`, archive parsing to `sar-core`, crypto to `sar-crypto`.
```

---

## `sar-cli`

Final role: user-facing command-line interface over the library crates.

Current state is partial. It already exposes archive create/extract/list/verify/inspect/version style behavior and has some sparse/lossy/resource-limit flags according to the API inventory.

Should contain:

* CLI argument parsing.
* command dispatch.
* create.
* extract.
* list.
* verify.
* inspect.
* version.
* JSON output for inspect/list where supported.
* password/key-provider CLI integration.
* compression options.
* encryption options.
* FEC options.
* CDC options where useful.
* delta options where useful.
* sparse handling flags.
* symlink/directory/metadata handling flags after M11.
* safe extraction policy:

  * no path traversal;
  * no absolute path extraction unless explicitly allowed;
  * safe symlink policy;
  * safe permissions/UID/GID restoration policy;
  * temp-file behavior for sparse extraction.
* resource-limit flags:

  * archive size;
  * decoded entry size;
  * sparse map bytes;
  * fragment count;
  * loss-tolerant gap.
* streaming/transport commands only if product scope requires them.
* CLI integration tests.
* help-output tests.
* no false standard-compliance claims.

Should not contain:

* core archive parsing logic;
* cryptographic algorithm implementations;
* FEC algorithms;
* sparse/fragment algorithms;
* transport protocol logic.

Expected final shape:

```text
sar-cli:
  thin UX wrapper over library crates.
  no protocol logic duplicated in CLI.
```

---

# Final Ownership Summary

## Keep in `sar-core`

* wire format;
* canonical parsing/writing;
* archive integration;
* shared errors/status;
* raw LFH/GH/CD/Footer/TLV models;
* high-level reader/writer APIs;
* conformance hooks;
* transform orchestration.

## Move or delegate out of `sar-core`

* fragment reassembly → `sar-fragmentation`;
* sparse semantic validation/reconstruction → `sar-sparse`;
* loss-tolerant degradation policy → `sar-loss-tolerant`;
* partition chain validation/recovery → `sar-partition`;
* compression → `sar-compression`;
* crypto/KMS algorithms → `sar-crypto`;
* FEC algorithms → `sar-fec`;
* CDC algorithms → `sar-cdc`;
* delta patching → `sar-delta`;
* session state → `sar-stream`;
* TCP/QUIC → `sar-transport`;
* command-line UX → `sar-cli`.

## Marker-crate decision

Keep:

* `sar-fragmentation`;
* `sar-sparse`;
* `sar-loss-tolerant`.

Keep or remove after spec review:

* `sar-partition`.

Do not remove `sar-partition` merely because it is currently empty. Remove it only if partition/multi-volume behavior is not part of the active SAR v1 specification or near-term conformance target.
