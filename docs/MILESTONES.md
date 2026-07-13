<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR Implementation Milestones

This document records the intended implementation roadmap for the SAR Protocol v1.0 reference implementation.

It is a project-planning and implementation-guidance document, not the wire-format specification.

`specification.md` is the authoritative source of truth for SAR Protocol v1.0 wire-format behavior, validation rules, transform ordering, streaming/session semantics, and transport bindings.

`docs/MACHINE_READABLE_API.json` tracks the current public API surface exposed by the implementation.

`docs/CRATE_RESPONSIBILITIES.md` tracks intended Rust crate ownership boundaries.

`docs/LIBRARY_LAYOUT.md` tracks intended future shared-library/profile layout for C ABI, Python/PyO3, and other foreign-language bindings.

If this milestone document conflicts with `specification.md`, `specification.md` wins.

If this milestone document appears to describe APIs differently from `docs/MACHINE_READABLE_API.json`, treat `docs/MACHINE_READABLE_API.json` as the current implementation inventory and update whichever document is stale as part of the relevant milestone.

If this milestone document appears to describe crate ownership differently from `docs/CRATE_RESPONSIBILITIES.md`, treat the relevant implementation milestone as responsible for reconciling the two documents.

If this milestone document appears to describe library/profile layout differently from `docs/LIBRARY_LAYOUT.md`, treat `docs/LIBRARY_LAYOUT.md` as the intended profile-layout design and update whichever document is stale as part of the relevant milestone.

---

# Completed milestones

## M1: core primitives, error model, flags, and checked parsing foundations

* workspace/crate structure baseline
* SAR status/error types
* Global Flag definitions
* Entry Mode bit definitions
* checked integer parsing helpers
* checked size/offset arithmetic
* bounded byte readers/writers
* little-endian primitive encoding/decoding
* fail-closed reserved/unsupported handling foundations
* no unsafe parsing assumptions

## M2: Global Header, LFH, Central Dictionary, and Footer parsing

* Global Header parse/validate
* LFH parse/validate
* Central Dictionary parse/validate
* Footer parse/validate
* field presence from Global Flags
* LFH physical-field layout enforcement
* reserved value rejection
* structural error handling
* malformed/truncated archive tests
* deterministic parser behavior

## M3: minimal archive read/write with STORE and NO_INDEX

* minimal archive writer
* minimal archive reader
* STORE payload handling
* indexed archive path
* NO_INDEX forward-only archive path
* basic file entry round trips
* footer/CD consistency checks
* minimal CLI archive create/list/extract behavior where applicable
* deterministic archive encoding tests

## M4: compression and transform pipeline

* `sar-compression` crate
* STORE transform path
* DEFLATE support
* ZSTD support
* compression algorithm registry handling
* compression/decompression ordering
* unsupported compression fail-closed behavior
* decompressed-size validation
* expansion-limit protections
* compression round-trip tests

## M5: crypto, KMS, hashes, signatures, and AEAD

* `sar-crypto` crate
* hash registry support
* content hash validation
* AEAD encryption/decryption support
* AEAD AAD construction
* KMS metadata parsing
* KMS stores derivation/wrapping metadata, not plaintext keys
* signature metadata and validation scaffolding
* decrypt-before-plaintext enforcement
* AEAD-before-decompression ordering
* authentication failure is never loss-tolerant
* crypto negative tests

## M6: XOR FEC

* `sar-fec` crate foundation
* XOR parity generation
* XOR repair metadata
* selective FEC field handling
* FEC size/value parsing
* FEC-before-decrypt ordering
* missing/corrupt shard behavior
* FEC validation tests

## M7: Reed-Solomon FEC

* Reed-Solomon FEC support
* shard layout and repair behavior
* FEC algorithm registry expansion
* unsupported FEC fail-closed behavior
* Reed-Solomon reconstruction tests
* malformed FEC metadata tests
* repair-before-transform ordering validation

## M8: fragmentation, sparse files, recovery behavior, and security hardening

* file fragmentation metadata
* fragment ID / fragment index / fragment descriptor handling
* LAST_FRAGMENT behavior
* sparse map parsing
* sparse reconstruction behavior
* loss-tolerant entry boundaries
* recovery behavior for partial/corrupt fragments
* path traversal hardening foundations
* transform ordering hardening
* malformed sparse/fragment metadata tests
* no panic/DoS behavior for malformed metadata

## M9a: CDC metadata, chunk maps, FASTCDC, and CDC verification

* CDC algorithm registry
* CDC LFH metadata handling
* CDC_MAP TLV support
* CDC_EXT_PROVIDER TLV support
* CDC_CUSTOM TLV reservation
* FASTCDC metadata representation
* CDC chunk map parse/write
* chunk hash verification over stored byte ranges
* CDC map structural validation
* no false claim of FASTCDC boundary-regeneration verification
* external provider/CAS behavior left for future profile/spec clarification

## M9b: Delta metadata, base identity, and patch algorithms

* delta algorithm registry
* HAS_DELTA LFH behavior
* Delta Base Hash handling
* STORE_PATCH support
* VCDIFF support where available
* SAR BSDIFF v1 support
* base-required vs base-free patch rules
* transform domain: logical data → patch → compression → encryption
* decode ordering: decrypt → decompress → patch → sparse
* missing/zero base identity handling
* delta negative tests

## M10a: streaming-capable reader/writer state model

* stateless Section 11 byte-stream parser/writer phases
* forward-only NO_INDEX parsing
* partial input stepping
* structural writer state
* Entry Mode physical-field semantics
* LFH-by-LFH streaming parse model
* bounded incremental parsing
* no session semantics
* no transport implementation

## M10b: session semantics and loss-tolerant streaming behavior

* `sar-stream` crate
* SESSION_CONTROL state layer
* Stream ID lifecycle
* Session UUID binding
* sequence continuity
* SESSION_INIT
* SESSION_CLOSE
* SESSION_RESUME handling or unsupported response
* SESSION_HEARTBEAT
* SESSION_STATUS
* SESSION_ACK
* SESSION_METADATA
* SESSION_CAPABILITIES
* LOSS_TOLERANT streaming boundaries
* session state validation
* in-memory/session-only behavior
* no real transport implementation

## M10c: transport abstraction and in-memory harness

* `sar-transport` crate
* transport abstraction layer
* in-memory transport harness
* TCP policy model
* QUIC policy model
* bidirectional control model
* stream/session transport mapping model
* status/ack emission hooks
* transport error mapping
* no real network I/O
* no async/runtime dependency
* transport conformance tests

## M10d: SAR-over-TCP binding

* real TCP listener/client wrapper
* SAR-over-TCP stream handling
* sequential SAR streams on one TCP connection
* no TCP byte-interleaving
* invalid initial byte rejection
* duplicate Stream ID rejection
* too-many-streams handling
* SESSION_CLOSE unbind/reuse behavior
* SESSION_STATUS / SESSION_ACK over TCP when bidirectional control is active
* heartbeat/watchdog support without background timers
* read/write buffer limit enforcement
* plaintext TCP rejects TLS_EXPORTER KMS mode
* no TCP+TLS or STARTTLS implementation

## M10e: SAR-over-QUIC binding

* real QUIC binding behind `quic` feature
* quinn/rustls/tokio integration
* QUIC listener/client connection API
* QUIC primary stream handling
* QUIC transport-only mode
* TLS_EXPORTER SAR-AEAD support over QUIC
* TLS exporter KMS parsing/serialization support
* QUIC loopback tests
* same-stream bidirectional ACK/STATUS support
* additional QUIC control-stream support in initial form
* duplicate SESSION_INIT rejection
* sequence wrap handling
* TCP behavior preserved

## M10f: M10 transport closeout, hardening, and validation

* transport abstraction validation
* TCP binding validation
* QUIC binding validation
* TCP and QUIC loopback edge-case tests
* non-SAR initial byte rejection tests
* malformed SAR stream behavior
* stream-local vs connection-fatal error behavior
* client/server drop behavior
* sequence wrap tests
* docs/API update
* docs/CONFORMANCE update
* docs/SECURITY update
* workspace test/clippy validation
* CodeQL or equivalent security scan where available

## M10g: Section 18 transport/security specification refinement and initial implementation attempt

* revised Stateful Streaming Mode transport rules
* SAR-over-QUIC additional control stream semantics
* TLS_EXPORTER SAR-AEAD activation model
* KMS Mode `0x04 TLS_EXPORTER` as authoritative selector
* SESSION_INIT as sole mandatory SAR-layer plaintext bootstrap entry
* post-binding SAR entries encrypted/authenticated
* baseline control-message capability model
* PQ/hybrid TLS policy model
* `TlsPqPolicy` API introduction
* PQ-required fail-closed behavior
* initial additional-control-stream implementation attempted
* incorrect `CTL!` private envelope introduced and identified for removal

## M10h: M10g correction and revised Section 18 implementation alignment

* remove `CTL!` public API and internal parser paths
* remove `CTL!` docs/tests/machine-readable API entries
* reject `CTL!` streams explicitly
* implement LFH-direct additional QUIC control streams
* additional control stream association by QUIC connection + LFH Stream ID
* no SAR!, no Global Header, no private envelope on additional control streams
* baseline bidirectional control entries:

  * SESSION_ACK
  * SESSION_STATUS
  * SESSION_CAPABILITIES
* baseline session-control messages do not require capability advertisement
* optional control messages require capability advertisement where defined
* KMS Mode `0x04 TLS_EXPORTER` selects TLS-exporter SAR-AEAD
* CAP_TLS_EXPORTER_AEAD advertises support only
* SESSION_INIT plaintext bootstrap for TLS_EXPORTER Context Version `0x01`
* every post-binding SAR entry encrypted/authenticated
* AAD behavior for additional QUIC control streams
* PQ/hybrid policy alignment with revised specification
* docs/API, CONFORMANCE, SECURITY, and MACHINE_READABLE_API cleanup
* full workspace validation

## M10i: M10 final alignment: TLS_EXPORTER/AAD coverage and crate responsibility guardrails

* add transport-integrated tests for post-binding TLS_EXPORTER SAR-AEAD enforcement
* test that SESSION_INIT is plaintext bootstrap for KMS Mode 0x04 TLS_EXPORTER
* test that post-binding SESSION_CAPABILITIES / ACK / STATUS are encrypted/authenticated
* test that plaintext post-binding entries fail closed
* test additional QUIC control-stream AAD behavior
* test that additional control-stream AAD uses associated session Global Header bytes
* test that additional control-stream AAD uses physically present LFH bytes
* test that LFH tampering causes AEAD failure
* confirm `CTL!` remains removed and rejected
* add `docs/CRATE_RESPONSIBILITIES.md`
* document intended crate ownership boundaries
* inventory marker crates:

  * `sar-fragmentation`
  * `sar-loss-tolerant`
  * `sar-partition`
  * `sar-sparse`
* document which currently implemented `sar-core` behavior should eventually delegate to those crates
* do not move major functionality unless required for tests
* do not remove marker crates yet
* update `docs/API.md` and `docs/MACHINE_READABLE_API.json` only if public API descriptions change
* full workspace validation

## M10i.1: additional-control-stream TLS_EXPORTER AEAD decrypt/auth completion

* wire additional-control-stream payload AEAD decryption into the real transport path
* construct additional-control-stream AAD from active session Global Header bytes and physically present LFH bytes
* pass decrypted plaintext, not ciphertext, to session processing
* reject plaintext post-binding additional control entries
* reject bad tag/ciphertext
* reject wrong LFH AAD
* reject wrong Global Header AAD
* ensure AEAD failure does not expose plaintext
* keep `CTL!` removed and rejected
* full workspace validation

## M11a: LFH metadata API completeness

* expand `EntryInput` beyond name + payload
* expand `EntryMetadata` beyond the previous partial metadata summary
* add `EntryMetadata` / `EntryInput` support for:

  * path
  * permissions
  * UID/GID
  * timestamps
  * symlink entries
  * directory entries
  * hidden attribute
  * Stream ID / Sequence No exposure where appropriate
  * fragment metadata
  * sparse metadata
  * FEC metadata
  * CDC metadata
  * delta metadata
  * encryption metadata
  * compression metadata
  * file CRC32 / content hash metadata
* preserve Global Flags vs Entry Mode semantics
* distinguish physically present LFH fields from semantically active metadata
* ensure unsupported metadata is not silently dropped
* expose metadata in a way suitable for future C/Python bindings
* avoid filesystem restoration behavior
* no CLI extraction policy changes

## M11a.1: 64BIT_SIZE LFH layout audit, correction, and implementation default policy

* audit Global Flag `64BIT_SIZE` support
* verify LFH parser reads Uncompressed Size as 4 or 8 bytes based on Global Flags
* verify LFH parser reads Payload Size as 4 or 8 bytes based on Global Flags
* verify LFH writer emits 4 or 8 byte size fields based on Global Flags
* verify LFH Header Size calculation accounts for 32-bit vs 64-bit size fields
* verify `64BIT_SIZE` behavior in both indexed and `NO_INDEX` archives where applicable
* verify 64-bit sizes use checked arithmetic and `ResourceLimits` before allocation
* add or confirm direct tests for 32-bit LFH size fields
* add or confirm direct tests for 64-bit LFH size fields
* add or confirm direct tests proving 32-bit and 64-bit LFH layouts have different physical header sizes
* add negative tests for overflow/truncation
* define and document implementation writer default policy:

  * default writer behavior is `auto`
  * `auto` uses 32-bit LFH size fields when all per-entry Uncompressed Size and Payload Size values fit in `u32`
  * `auto` enables Global Flag `64BIT_SIZE` when any required LFH size value exceeds `u32::MAX`
  * `auto` may promote to 64-bit only before the Global Header is emitted
  * after the Global Header is emitted without `64BIT_SIZE`, entries requiring 64-bit LFH size fields must fail closed
  * forward-only / non-rewindable writers must not rewrite or retroactively change Global Flags
  * API callers may explicitly force 64-bit LFH size fields
  * API callers may explicitly require 32-bit LFH size fields and receive a fail-closed error if any value exceeds `u32::MAX`
* document this policy in `docs/API.md`
* document this policy in `docs/MACHINE_READABLE_API.json`
* do not make this policy normative in `specification.md`
* preserve existing wire format
* no new protocol features

## M11b: filesystem metadata encode/decode behavior

* HAS_PATH writer and reader support
* HAS_PERMS writer and reader support
* EXT_UID_GID writer and reader support
* EXT_TIME writer and reader support
* HAS_SYMLINKS writer and reader support
* IS_DIRECTORY writer and reader support
* HIDDEN_ATTR writer and reader support
* `FieldPresence` model for physically-present filesystem metadata
* deterministic round-trip tests
* zero/default handling when fields are physically present
* directory-entry payload rule: directory payload must be zero bytes
* symlink-entry payload/target rule: symlink target is UTF-8 payload
* `EntryMetadata::symlink_target`
* invalid path/symlink metadata validation
* strict UTF-8 behavior for metadata strings where required
* metadata interaction with encrypted/compressed entries
* metadata interaction with `NO_INDEX` archives
* metadata interaction with fragmented/sparse entries
* side-effect-free library parsing:

  * no chmod
  * no chown
  * no timestamp restoration
  * no directory creation
  * no symlink creation
  * no device/FIFO/socket creation
* filesystem mutation is reserved for explicit CLI/application/profile extraction behavior

## M11c: crate-boundary implementation cleanup

* complete the M11c corrective crate-boundary pass
* finish `sar-fragmentation` ownership of fragment semantic helpers
* finish `sar-sparse` ownership of sparse semantic helpers
* add or integrate `sar-loss-tolerant` policy helpers, or document integration deferral honestly
* keep `sar-partition` deliberately deferred unless partition behavior becomes specified
* remove compatibility-only semantic re-exports from `sar-core`
* keep physical wire-format parse/write helpers in `sar-core`
* keep LFH/GH/CD/Footer/TLV/status/error ownership in `sar-core`
* preserve SAR wire format and archive interoperability
* preserve status/error semantics unless a current error is clearly wrong
* preserve M8 sparse/fragment/loss-tolerant behavior
* preserve M10 streaming/transport behavior
* fix fragment semantic validation gaps:

  * payload length must match fragment descriptor size
  * shorter payload must fail closed
  * longer payload must fail closed
  * duplicate fragment indexes must fail closed
  * missing `LAST_FRAGMENT` behavior must be documented and tested
* fix sparse semantic validation/docs consistency:

  * zero-length sparse extents rejected unless explicitly allowed
  * ordering and overlap checks preserved
  * payload length agreement checked in the appropriate function
  * documentation must not overclaim validation scope
* fix 32-bit sparse-map write truncation:

  * 32-bit sparse-map mode rejects offset/length values greater than `u32::MAX`
  * 64-bit sparse-map mode preserves full `u64` values
  * no silent truncation
* verify `FragmentError` / `SparseError` conversions to `SarError`
* update `docs/CRATE_RESPONSIBILITIES.md`
* update `docs/API.md`
* update `docs/MACHINE_READABLE_API.json`
* update `docs/MILESTONES.md` only after milestone status is accurate
* no new protocol features
* full workspace validation
* CodeQL/security scan where available

## M11c.1: final fragment completeness and API/docs consistency correction

* finish the final M11c review corrections before starting M11d
* do not create `sar-archive`
* do not start the archive API architecture split
* do not change SAR wire format
* do not add protocol features
* preserve archive interoperability
* fix fragment descriptor byte-range gap handling:

  * descriptor byte-range gaps are missing data
  * initial descriptor gaps are missing data
  * tail descriptor gaps are missing data when `logical_size` exceeds the final descriptor end
  * descriptor gaps without `LOSS_TOLERANT` fail closed
  * descriptor gaps with `LOSS_TOLERANT` are bounded by `max_loss_tolerant_gap`
  * descriptor gaps with `LOSS_TOLERANT` return degraded output
  * descriptor gaps must never suppress payload-size mismatch, duplicate index, overlap, bounds, overflow, or limit errors
* add tests for:

  * descriptor gap without `LOSS_TOLERANT`
  * descriptor gap with `LOSS_TOLERANT`
  * initial descriptor gap without `LOSS_TOLERANT`
  * tail descriptor gap without `LOSS_TOLERANT`
  * descriptor gap exceeding `max_loss_tolerant_gap`
  * valid complete contiguous fragment reconstruction
* fix `docs/API.md` so fragment and sparse helper descriptions match actual ownership and behavior
* fix `docs/CRATE_RESPONSIBILITIES.md` so `validate_fragment_group`, `reconstruct_fragments`, `validate_sparse_extents`, and `apply_sparse_reconstruction` are described accurately
* fix `docs/MACHINE_READABLE_API.json` so moved/removed APIs and current signatures are accurate
* document removed APIs as removed, not as changed return types:

  * `sar_core::fragment::*`
  * `sar_core::sparse::validate_sparse_extents`
  * `sar_core::sparse::apply_sparse_reconstruction`
* ensure milestone/API inventory text does not describe return-type changes for removed symbols; removed symbols must be listed only under removal notes
* keep `sar_core::sparse::parse_sparse_map` and `sar_core::sparse::write_sparse_map` as physical LFH sparse-map helpers
* keep `sar_core::sparse::SparseExtent` only if still required by those wire-format helper signatures
* remove duplicate Cargo dev-dependencies if present and unnecessary
* full workspace validation
* CodeQL/security scan where available

## M11d: archive API architecture split

* separate canonical SAR wire-format ownership from high-level archive integration
* introduce preferred new integration crate: `sar-archive`
* keep `sar-core` focused on canonical wire-format, status/error, limits, and low-level parse/write helpers
* move high-level archive reader/writer integration out of `sar-core` where appropriate
* audit before moving code:

  * all current public APIs in `sar-core`
  * wire-format/status/limit APIs that must remain in `sar-core`
  * high-level archive APIs that should move to `sar-archive`
  * dependencies required by reader/writer logic
  * impact on `sar-stream`
  * impact on `sar-transport`
  * impact on `sar-cli`
  * circular dependency risk
  * duplicate type risk
* likely `sar-core` ownership:

  * Global Header structs and parse/write helpers
  * Local File Header structs and parse/write helpers
  * Central Dictionary and Footer structs and parse/write helpers
  * TLV parse/write helpers
  * Global Flags
  * Entry Mode
  * SAR status/error model
  * resource limits and checked-size helpers
  * raw wire-format metadata structs
  * canonical little-endian parsing/writing primitives
  * low-level validation required to parse SAR wire data safely
* likely `sar-archive` ownership:

  * `ArchiveReader`
  * `ArchiveWriter`
  * archive verification
  * `EntryInput`
  * `EntryReader`
  * `EntryMetadata`
  * `EntryWritten`
  * `LogicalFile`
  * archive-level read/write options
  * transform orchestration
  * compression/encryption/FEC/CDC/delta integration
  * sparse and fragment semantic integration
  * loss-tolerant reconstruction policy integration
  * indexed and `NO_INDEX` high-level archive flows
  * high-level archive metadata reporting
* prefer one `sar-archive` integration crate over immediate `sar-archive-reader` / `sar-archive-writer` split unless audit proves separate crates are cleaner
* crate/archive split must stay inside the monorepo
* preserve M11a.1 LFH size-field policy during the split:

  * `Auto` may promote to 64-bit only before the Global Header is emitted
  * after the Global Header is emitted without `64BIT_SIZE`, entries requiring 64-bit LFH size fields fail closed
  * forward-only / non-rewindable writers must not attempt to rewrite Global Flags
  * streaming writers must require explicit size policy or fail closed when size requirements cannot be known before header emission
  * unknown-size entries on forward-only / non-rewindable writers must not trigger implicit unbounded buffering
  * if entry size cannot be known before LFH emission, the caller must choose an explicit size policy that can safely encode the entry or the writer must fail closed
  * live pipes, sockets, stdin streams, and other dynamic sources must not rely on `Auto` promotion after the Global Header is emitted
* preserve side-effect-free library parsing:

  * parsing and metadata decoding must not chmod, chown, set timestamps, create directories, create symlinks, or create device/FIFO/socket nodes
  * filesystem mutations remain explicit CLI/application/profile extraction behavior
* preserve secret-handling boundaries during the crate split:

  * exporter-derived key material must remain inside crypto/transport security boundaries
  * ordinary public SAR metadata parsing is not treated as secret
  * AEAD/tag verification remains the authenticity oracle
  * authentication failures must not reveal which AAD/context component failed
* update `sar-cli`, `sar-stream`, `sar-transport`, tests, and docs for new ownership
* allow Rust API-breaking changes
* do not keep compatibility re-exports merely to avoid breakage
* preserve SAR wire format and archive interoperability
* preserve transform ordering
* preserve M10 streaming/transport behavior
* preserve M11a/M11b metadata behavior
* update `docs/CRATE_RESPONSIBILITIES.md`
* update `docs/API.md`
* update `docs/MACHINE_READABLE_API.json`
* update `docs/LIBRARY_LAYOUT.md` if the crate split changes intended profile/library boundaries
* no filesystem restoration
* no CLI metadata behavior
* no C ABI/Python/mobile bindings yet
* full workspace validation
* CodeQL/security scan where available

## M11e: CLI metadata support

* create archives preserving permissions where supported
* optional preserve owner/group flag
* optional preserve timestamps flag
* symlink handling policy
* directory entry handling
* list/inspect `--json` exposes metadata
* extraction applies metadata safely and optionally
* extraction rejects unsafe paths by default
* extraction does not restore UID/GID by default
* extraction does not restore setuid/setgid/sticky bits by default
* symlink extraction is opt-in or policy-gated
* directory permissions are applied after contents where applicable
* safe extraction staging policy:

  * create directories with restrictive temporary permissions, preferably `0700` on POSIX
  * apply final directory permissions only after child entries are written
  * reject absolute paths and path traversal by default
  * prevent symlink-following during extraction where platform APIs allow it
  * use directory-relative / `openat`-style operations where available
  * symlink creation remains opt-in and policy-gated
  * hardlink creation is rejected unless a future explicit profile allows it
  * device/FIFO/socket creation is rejected
  * UID/GID restoration is disabled by default
  * setuid/setgid/sticky bits are disabled by default
  * timestamps and permissions are applied only through explicit extraction policy
  * document platform-specific limitations and best-effort behavior
  * validate archive paths lexically before filesystem operations:
    * reject absolute paths
    * reject parent-directory components such as `..`
    * reject empty, ambiguous, or platform-reserved path components where applicable
  * do not rely only on string prefix checks after host path concatenation
  * prevent traversal through symlink components during extraction using platform-safe APIs where available
  * ensure every created/opened path remains confined to the extraction root after each path component is processed
* platform-specific behavior documented
* deterministic CLI round-trip tests
* hostile extraction tests where practical:

  * path traversal attempts
  * absolute path attempts
  * symlink traversal attempts
  * unsafe metadata combinations
  * directory permission ordering
  * path replacement attempts where the platform test environment supports them
* CLI metadata behavior uses library APIs rather than duplicating protocol logic
* library parsing remains side-effect-free; only explicit CLI extraction paths perform filesystem mutation
* update `docs/API.md`
* update `docs/SECURITY.md`
* update `docs/MACHINE_READABLE_API.json` if CLI/API surface changes

## M11f: API inventory, conformance profile, and security-doc refresh

* `docs/API.md` reconciled with post-M11e API/CLI ownership and command flags
* `docs/MACHINE_READABLE_API.json` reconciled with current ownership and CLI metadata surface
* `docs/CONFORMANCE.md` refreshed as implemented-profile coverage with known gaps
* `docs/SECURITY.md` refreshed for M11e extraction defaults and current confinement limitations
* `docs/CRATE_RESPONSIBILITIES.md` reconciled with M11d/M11e crate boundaries
* `docs/LIBRARY_LAYOUT.md` reconciled with current monorepo layout and future milestone scope
* `docs/SPEC_QUESTIONS.md` cleaned so resolved M11 items are not listed as open
* stale milestone wording corrected (C ABI/Python in M14; mobile packages in M16)
* no implementation behavior/wire-format changes in this documentation closeout pass

---

## M12a: conformance profile validator and official vectors

* `test-vectors/` directory structure created with `valid/`, `invalid/`, and `profiles/` subtrees
* `test-vectors/manifest.schema.json` JSON Schema for conformance vector manifests
* `test-vectors/README.md` and `test-vectors/profiles/README.md` documentation
* 76+ `manifest.json` files covering valid, invalid, and profile-specific vectors
* binary `.sar` fixture files generated deterministically via `generate_vectors` example
* `sar_archive::conformance` module with `ConformanceManifest`, `validate_manifest_schema()`, `run_conformance_check()`, `discover_manifests()`
* `sar_archive::profile::ComplianceProfile` extended with 6 profile variants and `canonical_name()` / `from_canonical_name()` methods
* `crates/sar-archive/tests/conformance_tests.rs` integration test suite (9 tests, all passing)
* canonical valid vectors at initial M12a completion: minimal, indexed, NO_INDEX, compression (STORE/DEFLATE/ZSTD), crypto (AES-256-GCM, XChaCha20-Poly1305), LFH selective FEC (XOR, RS), sparse reconstruction, CDC literal mode, delta `STORE_PATCH`, filesystem metadata (permissions, owner, timestamps, symlink, directory, combined, field-presence-inactive), size layout (32-bit, 64-bit)
* invalid vectors: truncated GH/LFH, invalid magic, unknown global flag, unsupported compression/crypto algo, bad AEAD tag
* profile-specific vectors: static-archive, stream-package acceptance/rejection; cold-storage/tape deferred with documented placeholder
* deferred/reference-only manifests at initial M12a completion document future fragment reassembly, LOSS_TOLERANT fragment gaps, sparse+delta ordering, FASTCDC `CDC_MAP`, generated VCDIFF, and generated SAR BSDIFF v1 without overclaiming fallback binaries
* known gaps documented in manifests (stream/session, unsafe metadata, resource limits, many invalid cases deferred)
* `docs/CONFORMANCE.md` updated with M12a vector structure, validator status, and known gaps
* no wire-format changes; no CLI behavior changes; no M12b work started

---

## M12a-M9b-cp: Delta patch generation corrective pass (complete)

* `sar-delta`: `generate_vcdiff_patch` and `generate_bsdiff_patch` public APIs implemented (RFC 3284 ADD-only VCDIFF stream; SARBSD01 single-control-triple BSDIFF)
* `sar-delta`: all generation functions use checked arithmetic; O(target.len()) memory only; no suffix arrays, BWT, or quadratic structures
* `sar-archive`: writer integrates VCDIFF and BSDIFF generation via `DeltaWriteOptions`; sets `HAS_DELTA`, `Patch Algo ID`, and `Delta Base Hash` in each LFH
* `sar-archive`: `DeltaWriteOptions` requires non-zero `delta_base_hash` for VCDIFF/BSDIFF (all-zero rejected as missing identity)
* `crates/sar-archive/tests/delta_writer_tests.rs`: 12 tests covering VCDIFF/BSDIFF round-trips, algo-ID wire checks, missing-base rejection, zero-hash rejection, flag-conflict rejection, STORE_PATCH default for no-delta entries
* `crates/sar-delta/tests/generate_tests.rs`: generation and apply/round-trip tests for VCDIFF and BSDIFF
* VCDIFF and BSDIFF manifests promoted from deferred/reference-only to real generated fixtures (`test-vectors/valid/delta/vcdiff/`, `test-vectors/valid/delta/bsdiff/`)
* this promotion updates the earlier M12a historical state without starting `M12a-M8-cp`, `M12b`, or later milestones
* `conformance_manifest_tests`: two new tests asserting promoted VCDIFF vector uses algo ID `0x01` and promoted BSDIFF vector uses algo ID `0x02`
* `conformance_manifest_tests`: `delta:vcdiff` and `delta:bsdiff` removed from deferred feature tag guard (no longer deferred)
* all targeted tests passing; workspace Clippy clean
## M12a-M8-cp: Archive-level Recovery TLV corrective pass (complete)

* `sar-archive`: `ArchiveWriterOptions::archive_recovery` and `ArchiveRecoverySettings` add explicit writer-side archive-level Recovery TLV generation without changing LFH Selective FEC behavior
* writer rejects `NO_INDEX` + archive-level recovery, sets `HAS_GLOBAL_EC` and `OPT_PRESENT` before the Global Header is emitted, and generates the RECOVERY TLV during `finish()`
* protected range tracking now follows the spec exactly: first byte of Global Flags through the final byte immediately before the Central Dictionary; Magic/Version/Reserved/Flags Size/CD/Footer remain excluded
* `crates/sar-archive/tests/archive_recovery_writer_tests.rs`: positive writer/inspect/verify/repair coverage including block-aligned XOR and Reed-Solomon repair round-trips and explicit protected-range assertions
* `test-vectors/valid/recovery/archive-xor/recovery_tlv_archive_xor.sar` and `test-vectors/valid/recovery/archive-rs/recovery_tlv_archive_rs.sar`: real generated indexed archive-level Recovery TLV fixtures, separated from LFH Selective FEC vectors
* docs/API inventory updated to describe indexed-only archive-level recovery generation and `NO_INDEX` rejection while preserving the distinction from LFH Selective FEC
* `inspect_recovery_metadata` now fails closed when RECOVERY TLVs are malformed (no `repair_possible=true` on malformed metadata)
* this corrective pass updates M8 recovery behavior discovered during M12a without starting `M12b`, `M12c`, `M13`, `M14`, `M15`, or `M16`

## M12a-negative-cp: deterministic invalid conformance-vector expansion (complete)

* added deterministic invalid archive-level recovery fixtures under `test-vectors/invalid/recovery/` for:
  * `HAS_GLOBAL_EC` without `OPT_PRESENT`
  * `NO_INDEX` with `HAS_GLOBAL_EC`
  * RECOVERY TLV present while `HAS_GLOBAL_EC` is unset
  * truncated RECOVERY TLV
  * reserved and unsupported RECOVERY TLV algorithm IDs
  * malformed XOR/RS recovery metadata
  * corruption-beyond-parity repair failure (`SAR_ERR_EC_FAILED`)
* added deterministic invalid delta fixtures under `test-vectors/invalid/delta/` for:
  * reserved patch algorithm ID
  * unsupported custom patch algorithm ID
  * all-zero Delta Base Hash for VCDIFF and BSDIFF
  * truncated VCDIFF and SAR BSDIFF v1 patch payloads
  * VCDIFF output limit and BSDIFF control-block limit failures
* `run_conformance_check()` expanded to recognize additional stable SAR statuses, honor delta limit keys (`max_vcdiff_output_size`, `max_bsdiff_control_bytes`, etc.), and run deterministic recovery repair checks for `recovery:repair-beyond-parity`
* global/CD validation hardened to fail closed for invalid recovery-flag and recovery-metadata combinations
* `conformance_manifest_tests` now audits invalid recovery/delta taxonomy, real fixture references, and non-placeholder language for non-deferred invalid vectors
* `docs/CONFORMANCE.md` and `test-vectors/README.md` updated to describe deterministic invalid-vector expansion explicitly (not fuzzing)
* this pass does not start `M12b` fuzzing and does not start `M12c`, `M13`, `M14`, `M15`, or `M16`

## M12a-stream-cp: Serialized SAR stream transcript conformance vectors (corrected)

* Added deterministic valid stream transcript fixtures under `test-vectors/valid/stream-session/`:
  * `session-init` - minimal: Global Header + SESSION_INIT
  * `session-capabilities` - SESSION_INIT + SESSION_CAPABILITIES
  * `ordered-data` - SESSION_INIT + two DATA_WRITE entries with sequence numbering
  * `heartbeat` - SESSION_INIT + SESSION_HEARTBEAT (zero-payload)
  * `sequence-wrap` - sequence number wraps from 0xFFFF to 0x0000
* Added deterministic invalid stream transcript fixtures under `test-vectors/invalid/stream-session/`:
  * `data-before-session-init` → `SAR_ERR_STREAM_STATE`
  * `duplicate-session-init` → `SAR_ERR_STREAM_STATE`
  * `bad-session-init-payload-length` → `SAR_ERR_INVALID_LENGTH`
  * `reserved-session-init-flags` → `SAR_ERR_RESERVED_VALUE`
  * `sequence-gap` → `SAR_ERR_STREAM_STATE`
  * `sequence-replay` → `SAR_ERR_STREAM_STATE`
  * `wrong-stream-id` → `SAR_ERR_STREAM_STATE`
  * `heartbeat-with-payload` → `SAR_ERR_INVALID_LENGTH`
  * `reserved-session-opcode` → `SAR_ERR_RESERVED_VALUE`
  * `session-control-without-no-index` → `SAR_ERR_FLAG_CONFLICT` (strict transcript mode)
  * `zero-stream-id` → `SAR_ERR_STREAM_STATE` (strict transcript mode)
* Added `test-vectors/profiles/static-archive/reject-session-control/`: references the same `session-init` fixture; asserts stream-session transcript bytes are structurally valid SAR and profile-rejected by static-archive
* Stream transcript semantic conformance now executes in `crates/sar-stream/tests/stream_transcript_conformance_tests.rs` (strict `NO_INDEX` + nonzero Stream ID + SESSION_INIT activation + sequence/session validation).
* `sar-archive` no longer depends on `sar-stream` for production conformance execution.
* Default `sar-archive` parsing rejects entries where `SESSION_CONTROL` is set or `OP_CODE` is nonzero (`SAR_ERR_UNSUPPORTED`), while preserving classic NO_INDEX archive parsing.
* `sar-archive` conformance tests skip `stream:transcript` semantic checks and leave transcript semantics to `sar-stream`.
* `sar-stream` default state manager behavior remains inert outside active stateful mode; strict transcript errors are enforced by transcript conformance tests.
* Added 4 new manifest audit tests in `conformance_manifest_tests`:
  * `stream_transcript_vectors_use_stream_tags_and_correct_paths`
  * `stream_transcript_profile_rejection_manifests_are_not_byte_invalid`
  * `minimum_required_valid_stream_transcript_vectors_present`
  * `minimum_required_invalid_stream_transcript_vectors_present`
* `valid_vectors_have_entries` exempts `stream:transcript` vectors (session transcripts have session frames, not traditional archive entries)
* `docs/CONFORMANCE.md`, `test-vectors/README.md`, and `docs/MILESTONES.md` updated to describe serialized SAR stream transcript fixtures, no live transport requirement, profile-rejection behavior, and strict invalid coverage
* These fixtures do not require live TCP/QUIC transport; they are parsed in-memory by `sar-stream`
* Additional QUIC control streams are not covered by this pass
* This pass does not start `M12b` fuzzing and does not start `M12c`, `M13`, `M14`, `M15`, or `M16`

## M12a-audit-cp: archive audit primitives and stream transcript recording

* Added `sar-archive` archive-audit APIs:
  * `ArchiveAuditOptions`
  * `ArchiveAuditReport` (+ per-entry/report enums for control/payload outcomes)
  * `ControlEntryPolicy` (`Reject` default, `PreserveInert` opt-in)
  * `PayloadAuditPolicy` (`MetadataOnly`, `DecodeWhenKeysAvailable`, `RequireDecode`)
* Default archive parsing behavior is unchanged:
  * reject `SESSION_CONTROL` entries by default
  * reject nonzero `OP_CODE` entries by default
  * continue accepting classic `NO_INDEX` archives without stream-session semantics
* Inert archive audit mode (`ControlEntryPolicy::PreserveInert`) performs structural auditing without executing stream-session semantics.
* Ordinary archive-entry payload auditing in `sar-archive` now supports metadata-only inspection and explicit decode policies while preserving key-provider/auth behavior.
* Added strict transcript validation + optional exact-byte transcript recording APIs in `sar-stream`:
  * `validate_stream_transcript`
  * `validate_stream_transcript_with_options`
  * `validate_stream_transcript_with_sink`
* Transcript recording is disabled by default, opt-in only, records exact received bytes, and surfaces I/O errors.
* Added targeted `sar-archive` and `sar-stream` tests for audit policies and transcript recording.
* No `sar-audit` crate was added in this pass.
* This pass does not start `M12b` fuzzing and does not start `M12c`, `M13`, `M14`, `M15`, or `M16`.

---

# Current and future milestones

## M12b: fuzzing and malicious corpus

* global header fuzzing
* LFH fuzzing
* CD/footer fuzzing
* TLV fuzzing
* low-level `sar-core` parser corpus
* high-level `sar-archive` orchestration corpus
* transform pipeline fuzzing
* transform-switching DoS corpus:

  * many small entries with alternating compression algorithms
  * alternating patch/compression/encryption combinations
  * repeated decompressor initialization
  * repeated patch-window initialization
  * bounded rejection tests for strict profiles
* crypto/auth ordering corpus
* TLS_EXPORTER/AAD negative corpus:

  * wrong Global Header AAD
  * wrong LFH AAD
  * wrong session binding
  * bad tag/ciphertext
  * generic authentication failure behavior
* decompression bomb corpus
* allocator-churn / repeated-initialization corpus
* FEC/fragmentation corpus
* CDC/delta corpus
* stream/session corpus
* metadata edge-case corpus
* malformed filesystem metadata corpus
* extraction-race malicious corpus where practical:

  * path replacement attempts
  * symlink traversal attempts
  * unsafe directory permission ordering
  * hostile metadata combinations
* profile-specific rejection corpus

## M12c: docs/API/security posture hardening

* conformance docs
* machine-readable API inventory
* security model docs
* CLI behavior docs
* compatibility notes
* spec-question cleanup
* public claims audit
* crate-boundary consistency audit
* library-layout consistency audit
* security-profile documentation draft if needed before M14a
* document which hardening behavior is implementation/profile policy rather than SAR wire-format behavior

## M13a: security audit

* cryptography
* parsing
* memory
* panic/DoS
* unsafe
* dependency risk
* metadata restoration risks
* path traversal / symlink hazards
* UID/GID/permission restoration hazards
* crate-boundary attack surface
* profile/library layout attack surface
* transport/session attack surface
* FFI readiness risks
* side-channel and secret-handling audit:

  * TLS_EXPORTER SAR-AEAD key derivation
  * AEAD tag failure behavior
  * constant-time handling of secret comparisons where comparison is unavoidable
  * zeroization of exporter-derived material where practical
  * no secret material exposed through logs/errors/debug APIs
* transform resource-accounting audit:

  * decompressor setup limits
  * patch setup limits
  * algorithm-switching profile limits
  * allocator churn / repeated initialization DoS
  * profile-specific strict-mode rejection behavior
* filesystem extraction TOCTOU audit:

  * directory staging permissions
  * symlink/hardlink/path replacement races
  * final metadata application ordering
  * platform-specific extraction safety
* cold-storage/tape resilience audit:

  * identify which structural anchor failures are unrecoverable in plain SAR v1.0
  * evaluate interoperable sidecar/container/profile approaches
  * do not require non-standard duplicate headers/footers in ordinary SAR v1.0 archives

## M13b: refactoring/remediation from M13a

* remove duplicated logic
* simplify risky abstractions
* strengthen invariants
* reduce attack surface
* harden crate boundaries
* harden profile/library boundaries
* harden transform resource accounting
* harden extraction staging and metadata restoration paths
* harden secret-handling and error-reporting paths
* prepare stable public API surface
* prepare C ABI/Python architecture after security findings
* preserve monorepo layout when preparing C ABI/Python architecture

## M14a: C ABI security profile and split-library design

* define C ABI security profiles before freezing the ABI
* align profile design with `docs/LIBRARY_LAYOUT.md`
* define intended shared-library/profile layout:

  * `libsar_core.so`
  * `libsar_archive.so`
  * `libsar_profile_static_archive.so`
  * `libsar_profile_tape.so`
  * `libsar_profile_static_package.so`
  * `libsar_profile_stream_package_quic.so`
  * `libsar_profile_backup.so`
  * `libsar_profile_backup_quic.so`
  * `libsar_profile_backup_tcp.so`
  * `libsar_profile_telemetry.so`
  * `libsar_profile_live_media_quic.so`
  * `libsar_profile_stream_generic.so`
  * `libsar_profile_full.so`
* decide which APIs are available in each profile
* define which features are excluded from privileged profiles
* define profile constructors for C callers
* define default-deny behavior for unsupported/custom features
* define FFI-safe metadata ownership:

  * do not expose Rust `String`, `Vec`, `Option<T>`, borrowed references, slices, or lifetime-bearing structs directly across C ABI
  * expose metadata through opaque handles or C-compatible owned mirror structs
  * provide explicit destructor functions for all heap-owned metadata/results
  * define string/buffer lifetime rules
  * define whether returned strings are UTF-8, nul-terminated, length-delimited, or both
  * define allocator/freeing side for every returned allocation
* define ownership and callback rules per profile
* define cancellation behavior for long-running operations
* define thread-safety expectations
* define dependency/linking expectations per profile
* define side-channel and secret-handling expectations for FFI-facing APIs:

  * secret/authentication material is not exposed through C ABI
  * authentication failures remain generic
  * no raw exporter-derived key material is returned to callers
  * debug/log APIs must not expose secret material
* evaluate cold-storage/tape structural-anchor resilience as profile design, not default SAR v1.0 wire-format behavior:

  * sidecar recovery index
  * external container parity
  * tape block parity
  * profile-defined redundant manifest
  * compatibility impact for specification-compliant readers
* document that shared libraries do not provide process isolation
* document helper-process model for high-risk/networked use
* C ABI source, headers, examples, tests, and packaging metadata live under a monorepo path such as `ffi/c/`
* update `SECURITY.md` / future `SECURITY_PROFILES.md`
* no stable ABI freeze yet unless the design is complete and reviewed

## M14b: stable C ABI

* define stable C header
* opaque handle model
* archive reader/writer C API
* profile constructors
* metadata handle API
* entry/result destructor API
* error/status mapping
* memory ownership rules
* callback conventions
* cancellation conventions
* thread-safety conventions
* no Rust panic across FFI
* ABI versioning
* ABI compatibility tests
* no raw Rust type layout exposed across C ABI
* C ABI errors do not reveal secret/AAD mismatch details
* C ABI APIs do not expose raw key/exporter-derived material

## M14c: C ABI examples/tests

* C build examples
* C archive read/write examples
* C metadata examples
* C streaming examples where supported
* C profile-selection examples
* C package-profile examples
* C backup-profile examples where supported
* C error-handling examples
* C ABI integration tests
* sanitizer-friendly FFI tests
* ownership/destructor misuse tests where practical
* no-panic-across-FFI tests
* secret material non-exposure tests where practical

## M14d: Python module

* Python bindings over stable API surface
* align Python package shape with `docs/LIBRARY_LAYOUT.md`
* do not mirror every Rust crate as a public Python module
* preferred Python package shape:

  * `sar.archive`
  * `sar.metadata`
  * `sar.verify`
  * `sar.profiles`
  * `sar.stream` where enabled
  * `sar.transport` where enabled
* archive read/write API
* metadata access API
* verification API
* profile-selection API
* streaming/session API where appropriate
* Python exceptions mapped from SAR status codes
* Python-owned metadata objects or safe opaque-handle wrappers
* PyO3 ownership conversion rules
* Python wrapper objects must release Rust-owned resources automatically when the Python object is dropped
* PyO3 classes wrapping opaque Rust handles must implement safe ownership/drop behavior and must not leak heap-owned Rust metadata, readers, writers, buffers, or stream handles
* long-lived readers/writers/streams should provide explicit close/release APIs or context-manager support where appropriate
* Python garbage collection behavior must be tested for repeated create/drop cycles and long-running streaming use
* no borrowed views into temporary archive buffers unless owner lifetime is enforced by Python object references
* optional extras/features for archive/package/quic/backup/full profiles where appropriate
* default Python install should not load transport, QUIC, or all-feature code unless explicitly selected
* Python exceptions must not reveal secret/AAD mismatch details
* Python APIs must not expose raw key/exporter-derived material
* Python binding source, packaging metadata, tests, and examples live under a monorepo path such as `bindings/python/`
* wheel/build documentation
* Python examples/tests

## M15a: monorepo packaging and CI layout

* keep all implementation, C ABI, Python, future mobile bindings, profiles, vectors, fuzzing harnesses, packaging metadata, and release scripts in one monorepo
* do not introduce Git submodules
* do not plan separate repositories for C ABI, Python, Swift/iOS, Kotlin/Java Android, conformance vectors, profile definitions, or release packaging
* define repository paths for packaging and generated artifacts, such as:

  * `ffi/c/`
  * `bindings/python/`
  * `bindings/swift/`
  * `bindings/android/`
  * `profiles/`
  * `vectors/`
  * `fuzz/`
  * `ci/`
  * `ci/scripts/`
  * `.github/workflows/`
* define CI job boundaries:

  * Rust workspace validation
  * CodeQL/security scan
  * C ABI build/test
  * Python wheel build/test
  * conformance vector validation
  * fuzz smoke tests
  * documentation/API inventory validation
* define which generated outputs are CI artifacts only and must not be committed:

  * `.so`
  * `.dll`
  * `.dylib`
  * `.a`
  * `.lib`
  * `.rlib`
  * `.whl`
  * generated binary archives
  * coverage reports
  * fuzz corpus build outputs
* define which generated or semi-generated files may be committed once stable:

  * canonical C headers
  * machine-readable API inventory
  * conformance vector manifests
  * package metadata templates
* document that package creation jobs may look only at their relevant subpaths but still operate inside the same monorepo
* update `docs/LIBRARY_LAYOUT.md`
* update `docs/SECURITY.md` or future `docs/SECURITY_PROFILES.md` if packaging profile behavior affects security posture

## M15b: release artifact automation design

* design GitHub Actions or equivalent CI/CD workflows for creating release artifacts from the monorepo
* release automation is planned but not required for earlier milestones
* define artifact matrix for:

  * Rust crates
  * CLI binaries
  * C ABI shared libraries
  * C ABI headers/packages
  * Python wheels
  * conformance vectors
  * documentation bundles
* define platform matrix where practical:

  * Linux
  * macOS
  * Windows
  * x86_64
  * aarch64
* define signing/checksum expectations for release artifacts
* define SBOM/provenance expectations where practical
* define versioning rules across Rust crates, C ABI, Python package, CLI, and conformance vectors
* define release notes expectations
* define how generated artifacts attach to GitHub Releases or equivalent release pages
* ensure release automation does not require splitting the repository
* ensure release automation does not commit generated binaries/modules back to source control
* update packaging docs and CI docs
* no requirement to publish packages automatically to external registries unless explicitly added by a later milestone

## M16a: Swift/iOS package

* Swift package wrapper
* iOS-compatible build configuration
* archive read/write APIs
* safe metadata handling
* mobile storage constraints documented
* profile selection documented
* Swift examples/tests
* keep Swift/iOS binding source, packaging metadata, tests, and examples inside this monorepo
* use a monorepo path such as `bindings/swift/`
* do not split Swift/iOS bindings into a separate Git repository
* generated Apple framework/package artifacts are release/CI outputs and must not be committed to source control

## M16b: Kotlin/Java Android package

* Kotlin/Java wrapper
* Android-compatible build configuration
* archive read/write APIs
* safe metadata handling
* mobile storage constraints documented
* profile selection documented
* Android examples/tests
* keep Android binding source, packaging metadata, tests, and examples inside this monorepo
* use a monorepo path such as `bindings/android/`
* do not split Android bindings into a separate Git repository
* generated Android package artifacts are release/CI outputs and must not be committed to source control
