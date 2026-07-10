# SAR Implementation Milestones

This document records the intended implementation roadmap for the SAR Protocol v1.0 reference implementation.

It is a project-planning and implementation-guidance document, not the wire-format specification.

`specification.md` is the authoritative source of truth for SAR Protocol v1.0 wire-format behavior, validation rules, transform ordering, streaming/session semantics, and transport bindings.

`docs/MACHINE_READABLE_API.json` tracks the current public API surface exposed by the implementation.

If this milestone document conflicts with `specification.md`, `specification.md` wins.

If this milestone document appears to describe APIs differently from `docs/MACHINE_READABLE_API.json`, treat `docs/MACHINE_READABLE_API.json` as the current implementation inventory and update whichever document is stale as part of the relevant milestone.

---

# Completed milestones

## M1:

core primitives, error model, flags, and checked parsing foundations

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

## M2:

Global Header, LFH, Central Directory, and Footer parsing

* Global Header parse/validate
* LFH parse/validate
* Central Directory parse/validate
* Footer parse/validate
* field presence from Global Flags
* LFH physical-field layout enforcement
* reserved value rejection
* structural error handling
* malformed/truncated archive tests
* deterministic parser behavior

## M3:

minimal archive read/write with STORE and NO_INDEX

* minimal archive writer
* minimal archive reader
* STORE payload handling
* indexed archive path
* NO_INDEX forward-only archive path
* basic file entry round trips
* footer/CD consistency checks
* minimal CLI archive create/list/extract behavior where applicable
* deterministic archive encoding tests

## M4:

compression and transform pipeline

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

## M5:

crypto, KMS, hashes, signatures, and AEAD

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

## M6:

XOR FEC

* `sar-fec` crate foundation
* XOR parity generation
* XOR repair metadata
* selective FEC field handling
* FEC size/value parsing
* FEC-before-decrypt ordering
* missing/corrupt shard behavior
* FEC validation tests

## M7:

Reed-Solomon FEC

* Reed-Solomon FEC support
* shard layout and repair behavior
* FEC algorithm registry expansion
* unsupported FEC fail-closed behavior
* Reed-Solomon reconstruction tests
* malformed FEC metadata tests
* repair-before-transform ordering validation

## M8:

fragmentation, sparse files, recovery behavior, and security hardening

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

## M9a:

CDC metadata, chunk maps, FASTCDC, and CDC verification

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

## M9b:

Delta metadata, base identity, and patch algorithms

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

## M10a:

streaming-capable reader/writer state model

* stateless Section 11 byte-stream parser/writer phases
* forward-only NO_INDEX parsing
* partial input stepping
* structural writer state
* Entry Mode physical-field semantics
* LFH-by-LFH streaming parse model
* bounded incremental parsing
* no session semantics
* no transport implementation

## M10b:

session semantics and loss-tolerant streaming behavior

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

## M10c:

transport abstraction and in-memory harness

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

## M10d:

SAR-over-TCP binding

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

## M10e:

SAR-over-QUIC binding

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

## M10f:

M10 transport closeout, hardening, and validation

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

## M10g:

Section 18 transport/security specification refinement and initial implementation attempt

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

## M10h:

M10g correction and revised Section 18 implementation alignment

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

## M10i:

M10 final alignment: TLS_EXPORTER/AAD coverage and crate responsibility guardrails

* add transport-integrated tests for post-binding TLS_EXPORTER SAR-AEAD enforcement
* test that SESSION_INIT is plaintext bootstrap for KMS Mode 0x04 TLS_EXPORTER
* test that post-binding SESSION_CAPABILITIES / ACK / STATUS are encrypted/authenticated
* test that plaintext post-binding entries fail closed
* test additional QUIC control-stream AAD behavior
* test that additional control-stream AAD uses associated session Global Header bytes
* test that additional control-stream AAD uses physically present LFH bytes
* test that LFH tampering causes AEAD failure
* confirm CTL! remains removed and rejected
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

## M10i.1:

additional-control-stream TLS_EXPORTER AEAD decrypt/auth completion

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

---

# Current and future milestones

## M11a:

LFH metadata API completeness

* expand `EntryInput` beyond name + payload
* expand `EntryMetadata` beyond the current partial metadata summary
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
* expose metadata in a way that is suitable for future C/Python bindings
* avoid filesystem restoration behavior in this milestone
* no CLI extraction policy changes yet

M11a.1:
64BIT_SIZE LFH layout audit, correction, and implementation default policy

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
  * API callers may explicitly force 64-bit LFH size fields
  * API callers may explicitly require 32-bit LFH size fields and receive a fail-closed error if any value exceeds `u32::MAX`
* document this policy in `docs/API.md`
* document this policy in `docs/MACHINE_READABLE_API.json`
* do not make this policy normative in `specification.md`
* preserve existing wire format
* no new protocol features


## M11b:

filesystem metadata encode/decode behavior

* HAS_PATH writer and reader support
* HAS_PERMS writer and reader support
* EXT_UID_GID writer and reader support
* EXT_TIME writer and reader support
* HAS_SYMLINKS writer and reader support
* IS_DIRECTORY writer and reader support
* HIDDEN_ATTR writer and reader support
* deterministic round-trip tests
* zero/default handling when fields are physically present but semantically inactive
* directory-entry payload rules
* symlink-entry payload/target rules
* invalid path/symlink metadata validation
* metadata interaction with encrypted/compressed entries
* metadata interaction with `NO_INDEX` archives
* metadata interaction with fragmented/sparse entries
* no unsafe restoration defaults

## M11c:

crate-boundary implementation cleanup

* populate or deliberately defer marker crates:

  * `sar-fragmentation`
  * `sar-sparse`
  * `sar-loss-tolerant`
  * `sar-partition`
* move or delegate semantic helper logic out of `sar-core` where appropriate
* keep canonical wire-format structs and archive integration APIs in `sar-core`
* preserve public high-level behavior
* preserve archive format and status codes
* preserve M8 sparse/fragment/loss-tolerant behavior
* preserve M10 streaming/transport behavior
* add focused crate-level tests for any moved logic
* update workspace dependencies
* update `docs/CRATE_RESPONSIBILITIES.md` only if final ownership changes
* update `docs/API.md` and `docs/MACHINE_READABLE_API.json` only if public API changes during this milestone
* no new protocol features
* no broad public API redesign unless required by M11a/M11b metadata model

## M11d:

CLI metadata support

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
* platform-specific behavior documented
* deterministic CLI round-trip tests
* CLI metadata behavior uses library APIs rather than duplicating protocol logic

## M11e:

API inventory, conformance profile, and security-doc refresh

* `docs/API.md` update
* `docs/MACHINE_READABLE_API.json` update
* `docs/CONFORMANCE.md` update
* `docs/SECURITY.md` metadata behavior update
* `docs/CRATE_RESPONSIBILITIES.md` consistency check
* `docs/SPEC_QUESTIONS.md` cleanup
* profile conformance checker refreshed for M1-M11
* metadata conformance profile added
* crate-boundary audit result documented
* no false Standard Compliance claims
* binding-readiness notes updated for C/Python future work
* full workspace validation
* CodeQL/security scan if available

## M12a:

conformance profile validator and official vectors

* canonical minimal archive vectors
* canonical indexed vectors
* canonical `NO_INDEX` vectors
* compression vectors
* crypto vectors
* FEC vectors
* fragmentation/sparse vectors
* CDC vectors
* delta vectors
* stream/session vectors
* filesystem metadata vectors
* negative/error vectors

## M12b:

fuzzing and malicious corpus

* global header fuzzing
* LFH fuzzing
* CD/footer fuzzing
* TLV fuzzing
* transform pipeline fuzzing
* crypto/auth ordering corpus
* decompression bomb corpus
* FEC/fragmentation corpus
* CDC/delta corpus
* stream/session corpus
* metadata edge-case corpus

## M12c:

docs/API/security posture hardening

* conformance docs
* machine-readable API inventory
* security model docs
* CLI behavior docs
* compatibility notes
* spec-question cleanup
* public claims audit

## M13a:

security audit

* cryptography
* parsing
* memory
* panic/DoS
* unsafe
* dependency risk
* metadata restoration risks
* path traversal / symlink hazards
* UID/GID/permission restoration hazards

## M13b:

refactoring/remediation from M13a

* remove duplicated logic
* simplify risky abstractions
* strengthen invariants
* reduce attack surface
* prepare stable public API surface

## M14a:

C ABI security profile and split-library design

* define C ABI security profiles before freezing the ABI
* define intended shared-library/profile layout:

  * core
  * static archive
  * tape
  * static package
  * stream package over QUIC
  * backup
  * telemetry
  * live media
  * generic stream
  * full/developer
* decide which APIs are available in each profile
* define which features are excluded from privileged profiles
* define profile constructors for C callers
* define default-deny behavior for unsupported/custom features
* define ownership and callback rules per profile
* define dependency/linking expectations per profile
* document that shared libraries do not provide process isolation
* document helper-process model for high-risk/networked use
* update `SECURITY.md` / future `SECURITY_PROFILES.md`

## M14b:

stable C ABI

* define stable C header
* opaque handle model
* archive reader/writer C API
* profile constructors
* error/status mapping
* memory ownership rules
* callback conventions
* no Rust panic across FFI
* ABI versioning

## M14c:

C ABI examples/tests

* C build examples
* C archive read/write examples
* C streaming examples where supported
* C profile-selection examples
* C package-profile examples
* C error-handling examples
* C ABI integration tests
* sanitizer-friendly FFI tests

## M14d:

Python module

* Python bindings over stable API surface
* archive read/write API
* metadata access API
* streaming/session API where appropriate
* Python exceptions mapped from SAR status codes
* wheel/build documentation
* Python examples/tests

## M15a:

Swift/iOS package

* Swift package wrapper
* iOS-compatible build configuration
* archive read/write APIs
* safe metadata handling
* mobile storage constraints documented
* Swift examples/tests

## M15b:

Kotlin/Java Android package

* Kotlin/Java wrapper
* Android-compatible build configuration
* archive read/write APIs
* safe metadata handling
* mobile storage constraints documented
* Android examples/tests

