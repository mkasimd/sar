# Library Layout

This document describes the intended future shared-library/profile layout for SAR.

It is not the Rust crate layout.

Rust crate boundaries answer:

> Where does implementation logic live?

Shared-library/profile boundaries answer:

> What functionality should a given external consumer be allowed to load and call?

The layout below assumes the planned post-M11d crate structure:

* `sar-core` — canonical wire-format, status/error, limits, low-level parse/write helpers
* `sar-archive` — high-level archive reader/writer/verify/integration
* `sar-stream` — Stateful Streaming Mode/session layer
* `sar-transport` — TCP/QUIC transport bindings
* specialized crates — compression, crypto, FEC, CDC, delta, sparse, fragmentation, loss-tolerant, partition

All C ABI and Python/PyO3 bindings must expose profile-shaped APIs, not the raw internal Rust crate graph.

Do not expose Rust `String`, `Vec`, `Option<T>`, borrowed references, or lifetime-bearing structs directly across C ABI.

FFI-facing metadata/results must use either:

* opaque heap-owned handles with explicit destructor functions; or
* C-compatible owned mirror structs with explicit string/buffer lifetime rules.

Example ownership rule:

```c
void sar_entry_metadata_free(sar_entry_metadata_t* handle);
```

---

# Core and archive foundations

## `libsar_core.so`

Canonical SAR wire-format and strict parsing foundation.

### Intended users

* all SAR profiles
* validators
* conformance tools
* fuzzing harnesses
* language bindings needing low-level inspection
* package/archive/backup/streaming profiles as a dependency

### Includes

* Global Header structs and parse/write helpers
* LFH structs and parse/write helpers
* Central Dictionary structs and parse/write helpers
* Footer structs and parse/write helpers
* TLV parse/write helpers
* SAR status/error registry
* `GlobalFlags`
* `EntryMode`
* canonical resource-limit model
* checked arithmetic helpers
* bounded parsing/writing helpers
* canonical little-endian primitives
* raw wire-format metadata structs
* strict unsupported/reserved fail-closed behavior
* low-level validation required to parse SAR wire data safely

### May include

* minimal registry constants needed for wire-format interpretation
* minimal hash/compression/crypto algorithm ID names if required for introspection
* no algorithm implementation unless it is unavoidable for canonical validation

### Excludes

* high-level archive reader/writer APIs
* archive extraction APIs
* archive verification orchestration
* transform execution
* compression/decompression implementation
* encryption/decryption implementation
* FEC repair implementation
* CDC chunking
* delta patch application
* sparse reconstruction
* fragment reassembly
* LOSS_TOLERANT degradation policy
* Stateful Streaming Mode session manager
* TCP/QUIC transport
* package-manager policy
* backup policy
* live-media policy
* CLI behavior
* plugin loading
* all-feature convenience APIs

### Security posture

Smallest shared-library foundation.

Designed for stable C ABI use.

Should remain deterministic, heavily fuzzed, and suitable for privileged consumers that only need strict parsing or inspection.

Should not automatically enable optional algorithms, transforms, transports, or filesystem effects.

---

## `libsar_archive.so`

High-level archive reader/writer and archive integration library.

### Intended users

* ordinary archive tools
* static archive profile
* package profile
* backup profile
* language bindings for archive read/write/list/verify
* CLI implementation
* tools that need actual payload decoding or archive construction

### Includes

* `libsar_core.so`
* high-level archive reader
* high-level archive writer
* archive verification
* archive listing/inspection
* `EntryInput`
* `EntryReader`
* `EntryMetadata`
* `EntryWritten`
* `LogicalFile`
* archive-level options
* indexed archive read/write
* `NO_INDEX` archive read/write where applicable
* transform orchestration
* compression integration
* crypto/KMS/hash/AEAD/signature integration
* FEC integration
* CDC metadata integration
* delta integration
* sparse semantic integration
* fragment semantic integration
* loss-tolerant policy integration where explicitly enabled
* safe path normalization helpers
* metadata decoding into memory-only structures

### Excludes by default

* TCP/QUIC transport
* Stateful Streaming Mode session manager
* package-manager install policy
* backup repository policy
* live-media flow policy
* automatic filesystem restoration
* plugin loading
* custom algorithm loading unless explicitly built

### Required invariants

* preserve M11a.1 LFH size-field policy:

  * `Auto` may promote to 64-bit only before the Global Header is emitted
  * after the Global Header is emitted without `SIZE_64BIT`, entries requiring 64-bit LFH sizes fail closed
  * forward-only / non-rewindable writers must not rewrite Global Flags
  * streaming/non-rewindable writers must require explicit size policy or fail closed when sizes cannot be known before header emission

* library parsing remains side-effect-free:

  * no chmod
  * no chown
  * no timestamp restoration
  * no directory creation
  * no symlink creation
  * no device/FIFO/socket creation

Filesystem mutations belong only in explicit CLI/application/profile extraction paths.

### Security posture

Main high-level archive library.

Larger than `libsar_core.so`, but still excludes transport/session/profile-specific behavior unless selected by a narrower profile.

Should be the base for most archive-oriented C/Python bindings.

---

# Static/archive profiles

## `libsar_profile_static_archive.so`

Simple cold-storage archival profile.

### Covers use cases

* simple cold storage archival
* local archive create/list/extract/verify
* static SAR files on disk
* non-streaming archival tools
* GUI/archive utilities

### Includes

* `libsar_archive.so`

* indexed archive read/write

* `NO_INDEX` read/write where appropriate

* STORE

* standard compression if enabled by build:

  * DEFLATE
  * ZSTD

* hash verification:

  * SHA-256
  * BLAKE3 where supported

* optional AEAD/signature verification for encrypted/authenticated cold archives

* bounded extraction helpers

* safe path handling

* safe metadata restoration defaults

### Excludes by default

* TCP/QUIC transport
* Stateful Streaming Mode
* `SESSION_CONTROL`
* `LOSS_TOLERANT`
* external CDC providers
* live recovery behavior
* package-manager install semantics
* live telemetry/video semantics
* plugin/custom algorithm loading
* custom KMS modes unless explicitly allowed by profile

### Rejects by default

* unsupported/custom algorithm IDs
* transport/session-only entries
* lossy recovery modes
* unbounded sparse maps or fragment sets
* unsafe extraction paths
* unsafe metadata restoration

### Security posture

Good default for ordinary archive tools.

Smaller than full profile.

No network code.

Not intended for live streaming or privileged package installation.

---

## `libsar_profile_tape.so`

Linear tape and sequential media profile.

### Covers use cases

* linear tape writing
* sequential `NO_INDEX` archive writing
* sequential tape restore
* append-only or forward-only storage media
* long-running offline archival jobs

### Includes

* `libsar_archive.so`

* strict `NO_INDEX` writer

* strict forward-only `NO_INDEX` reader

* partial-input stepping

* bounded sequential validation

* STORE

* optional standard compression:

  * DEFLATE
  * ZSTD

* optional archive-level recovery metadata if required by tape profile

* optional FEC only if explicitly enabled for tape recovery

* deterministic resume/reporting hooks for tape tooling

### Excludes by default

* Central Directory requirement
* random-access assumptions
* TCP/QUIC transport
* Stateful Streaming Mode
* live `SESSION_CONTROL`
* LOSS_TOLERANT streaming semantics
* CDC/delta unless explicitly enabled for a tape-dedup profile
* package installation policy
* live telemetry/video behavior

### Rejects by default

* features requiring backward seek unless explicitly supported by a tape-specific profile
* transport/session control entries
* custom KMS/custom algorithm IDs
* unbounded sparse/fragment maps
* unsafe metadata restoration

### Security posture

Optimized for sequential media.

Does not load live network or streaming-session code.

Separate from generic streaming because tape is forward-only storage, not an interactive session transport.

---

# Package profiles

## `libsar_profile_static_package.so`

Static package verification and extraction profile.

### Covers use cases

* package managers consuming static SAR package files
* offline package verification
* local package staging and extraction
* repository cache validation

### Includes

* `libsar_archive.so`
* strict package metadata profile
* deterministic archive verification
* required hash/signature/AEAD verification according to package policy
* standard compression algorithms allowed by the package format
* bounded extraction
* package-safe filesystem staging
* atomic-write/finalization helpers if required
* safe metadata restoration policy:

  * no path traversal
  * no absolute paths
  * no device nodes
  * no FIFOs/sockets
  * no UID/GID restoration by default
  * no setuid/setgid/sticky bits by default
  * symlinks only if explicitly allowed by package policy

### Excludes

* TCP/QUIC transport
* Stateful Streaming Mode
* `LOSS_TOLERANT`
* external CDC providers
* custom KMS modes
* custom algorithm IDs
* backup-specific recovery behavior
* live telemetry/video behavior
* plugin loading
* generic all-feature extraction APIs

### Rejects

* streaming/session entries
* lossy package data
* unsupported/custom crypto or transform modes
* unsafe filesystem metadata
* unsigned/unauthenticated package content where policy requires authentication

### Security posture

Package-manager-safe static profile.

Suitable for privileged local install paths that do not require live streaming.

Should expose package-specific APIs rather than generic “open anything” APIs.

---

## `libsar_profile_stream_package_quic.so`

Streamable package distribution profile over SAR-over-QUIC.

### Covers use cases

* `spkg`
* package managers whose package format is SAR-encoded over SAR-over-QUIC
* authenticated streaming package delivery
* live package staging from a QUIC source

### Includes

* `libsar_archive.so`
* `sar-stream`
* SAR-over-QUIC transport
* TLS exporter integration
* TLS_EXPORTER SAR-AEAD if selected by the package profile
* PQ/hybrid TLS policy if required by deployment
* strict package metadata/profile validation
* required hash/signature/AEAD verification
* package-safe extraction/staging
* bounded buffering
* bounded stream/session state
* deterministic fail-closed session handling
* baseline bidirectional control entries required by the package streaming profile:

  * `SESSION_ACK`
  * `SESSION_STATUS`
  * `SESSION_CAPABILITIES`

### May include

* standard compression algorithms required by the package format
* sparse support only if package profile explicitly permits sparse payloads
* fragmentation only if package profile explicitly requires it
* FEC only if package profile explicitly requires package-stream repair

### Excludes by default

* `LOSS_TOLERANT`
* TCP transport unless the package profile explicitly has a TCP variant
* external CDC providers
* custom KMS modes
* custom algorithm IDs
* backup-specific dedup/recovery modes
* live video/telemetry-specific relaxed policies
* generic full streaming APIs
* plugin loading

### Rejects

* `LOSS_TOLERANT` entries
* unauthenticated post-binding SAR entries
* unsupported/custom algorithms
* external-provider references
* reverse-direction filesystem entries unless explicitly required and safe
* unsafe filesystem metadata
* package data that violates strict staging policy

### Security posture

Appropriate for `spkg`-style streamable packages.

Includes QUIC because the package protocol requires it.

Still avoids unrelated SAR feature surface.

Should be usable in an unprivileged fetch/stage helper or in a carefully profiled privileged process.

Must not imply that all streaming features are safe for packages.

---

# Backup and recovery profiles

## `libsar_profile_backup.so`

Base backup and replication profile without transport by default.

### Covers use cases

* deduplicated archival
* filesystem snapshots
* sparse/fragmented backup storage
* local backup verification
* local backup restore/staging
* repository cache validation

### Includes

* `libsar_archive.so`
* sparse file support
* fragmentation support
* FEC where configured
* CDC metadata and chunking
* delta support
* standard compression
* AEAD/signature support
* backup-safe metadata preservation policy
* optional `NO_INDEX` sequential archive support
* bounded recovery behavior
* resumable local operation helpers where supported

### May include

* `LOSS_TOLERANT`, but only as an explicit backup-recovery profile option
* external CDC provider metadata, but inert by default
* repository/object-store integration only outside the core SAR library or behind strict profile gates

### Excludes by default

* TCP/QUIC transport
* Stateful Streaming Mode
* package-manager install semantics
* live video-specific latency policy
* telemetry-specific append-only semantics
* plugin/custom algorithm loading
* unsafe metadata restoration
* privileged package extraction APIs

### Rejects by default

* custom algorithms unless explicitly enabled
* external providers unless explicitly enabled
* unbounded CDC/delta/FEC metadata
* unsafe symlink/path metadata
* auth failures even when `LOSS_TOLERANT` is enabled

### Security posture

Larger attack surface than static archive/package profiles.

Appropriate for backup tools that need sparse, fragment, CDC, delta, and recovery behavior.

Should not be loaded by minimal package managers unless their format genuinely requires these features.

---

## `libsar_profile_backup_quic.so`

Backup and replication profile over SAR-over-QUIC.

### Covers use cases

* authenticated backup transfer
* remote backup replication
* resumable backup sessions
* backup stream verification over QUIC

### Includes

* `libsar_profile_backup.so`
* `sar-stream`
* SAR-over-QUIC transport
* TLS exporter integration
* optional TLS_EXPORTER SAR-AEAD
* optional PQ/hybrid TLS policy
* bounded stream/session state
* SESSION_ACK / STATUS / HEARTBEAT / CAPABILITIES as required by backup profile
* explicit backup recovery policy

### Excludes by default

* TCP transport unless using a TCP-specific backup profile
* package-manager install semantics
* live video/telemetry-specific relaxed policies
* generic full streaming APIs
* plugin loading
* unsafe metadata restoration

### Rejects by default

* unauthenticated post-binding entries
* custom algorithms unless explicitly enabled
* external providers unless explicitly enabled
* auth failures even when `LOSS_TOLERANT` is enabled
* unbounded recovery state

### Security posture

Networked backup profile.

Broader than static backup because it includes transport/session code.

Should be deployed as a distinct profile rather than folding transport into the base backup library.

---

## `libsar_profile_backup_tcp.so`

Backup and replication profile over SAR-over-TCP.

### Covers use cases

* controlled-network backup transfer
* legacy or constrained deployments where QUIC is unavailable
* sequential backup streams over TCP

### Includes

* `libsar_profile_backup.so`
* `sar-stream`
* SAR-over-TCP transport
* bounded stream/session state
* SESSION_ACK / STATUS / HEARTBEAT / CAPABILITIES as required by backup profile
* explicit backup recovery policy

### Excludes by default

* QUIC transport
* TLS_EXPORTER SAR-AEAD unless a future TCP+TLS profile explicitly exists
* package-manager install semantics
* live video/telemetry-specific relaxed policies
* generic full streaming APIs
* plugin loading
* unsafe metadata restoration

### Rejects by default

* TLS_EXPORTER KMS mode over plaintext TCP
* unauthenticated entries where backup policy requires authentication
* custom algorithms unless explicitly enabled
* unbounded recovery state

### Security posture

TCP-specific backup profile.

Should be used only where the deployment security model is explicit about TCP/plaintext or external channel protection.

---

# Telemetry and live streaming profiles

## `libsar_profile_telemetry.so`

Industrial telemetry streaming profile.

### Covers use cases

* industrial telemetry data streaming
* structured event/log streams
* sensor data streams
* append-oriented machine data
* bounded low-latency authenticated streams

### Includes

* `libsar_archive.so` only if archive entry construction/decoding is needed
* `sar-stream`
* SAR-over-TCP and/or SAR-over-QUIC depending on build profile
* SESSION_ACK
* SESSION_STATUS
* SESSION_HEARTBEAT
* SESSION_CAPABILITIES
* bounded stream/session buffers
* strict heartbeat/watchdog policy
* AEAD/signature support where required
* TLS_EXPORTER SAR-AEAD where used by deployment
* resource-limit enforcement tuned for long-running streams
* append/event-oriented entry handling

### May include

* compression if latency budget permits
* FEC if deployment requires lossy-link repair
* `LOSS_TOLERANT` only if explicitly enabled by telemetry policy and only for authenticated data
* CDC/delta only if explicitly useful for telemetry compression/dedup, otherwise excluded

### Excludes by default

* package-manager extraction/staging
* filesystem metadata restoration
* symlink/UID/GID/permissions restoration
* backup-specific sparse reconstruction
* package-manager install policy
* live video frame policy
* external CDC providers
* custom KMS/custom algorithms
* plugin loading

### Rejects

* unauthenticated post-binding stream entries
* custom/unsupported algorithms
* unsafe filesystem entries
* lossy behavior unless explicitly enabled
* unbounded session metadata
* payloads exceeding telemetry resource policy

### Security posture

Intended for long-running industrial streams.

May include transport and session code, but avoids package, backup, and filesystem restoration complexity.

Should have TCP-only and QUIC-only build/profile variants if deployment needs strict dependency control.

---

## `libsar_profile_live_media_quic.so`

Live media/feed streaming profile over SAR-over-QUIC.

### Covers use cases

* military live video feed streaming
* industrial live video
* high-rate sensor feeds
* latency-sensitive authenticated media streams

### Includes

* `sar-stream`
* SAR-over-QUIC as preferred transport
* strict session lifecycle
* heartbeat/watchdog
* bounded buffering and frame/message limits
* AEAD/signature support
* TLS_EXPORTER SAR-AEAD where selected
* PQ/hybrid TLS policy where required
* optional FEC for media loss recovery
* optional fragmentation for large frames
* optional `LOSS_TOLERANT` only for authenticated media payloads where policy explicitly permits degradation
* status/ack/capabilities suited for live media flow control

### May include

* `libsar_archive.so` only if media entries use high-level archive decoding/encoding
* compression only if deployment requires it and accepts latency/security tradeoffs
* FEC profiles tuned for media recovery
* frame metadata helpers if represented as SAR session metadata

### Excludes by default

* package-manager extraction
* filesystem metadata restoration
* CDC/delta backup deduplication
* static archive indexing assumptions
* external CDC providers
* custom KMS/custom algorithms
* plugin loading
* general-purpose archive extraction APIs
* TCP transport unless a specific TCP live-media variant is defined

### Rejects

* unauthenticated data
* custom unsupported crypto/transport modes
* unbounded frame payloads
* unbounded FEC/recovery state
* filesystem-mode entries unless the live-media profile explicitly uses them as payload containers
* `LOSS_TOLERANT` for unauthenticated, structurally invalid, or failed-AEAD data

### Security posture

Specialized high-rate stream profile.

Bigger than telemetry because it may need FEC/fragmentation and media-specific buffering.

Still much smaller and more predictable than full SAR.

---

# Generic and full profiles

## `libsar_profile_stream_generic.so`

Generic SAR streaming profile for non-specialized applications.

### Covers use cases

* applications needing SAR Stateful Streaming Mode but not package, backup, telemetry, or live-media profiles
* developer integration
* controlled internal streaming applications

### Includes

* `sar-stream`
* optional SAR-over-TCP
* optional SAR-over-QUIC
* TLS_EXPORTER integration when QUIC/TLS is enabled
* ACK/STATUS/HEARTBEAT/CAPABILITIES
* bounded session metadata
* strict stream/session validation
* `libsar_archive.so` only if entry payload archive decoding/encoding is required

### May include

* compression
* crypto
* FEC
* fragmentation
* sparse
* `LOSS_TOLERANT` only when explicitly enabled

### Excludes by default

* package-manager-safe extraction policy
* backup-specific CDC/delta assumptions
* live-media-specific flow policy
* telemetry-specific append policy
* plugin loading
* custom KMS/custom algorithms unless explicitly built

### Rejects

* features not enabled by the selected build profile
* unsupported/custom IDs by default
* unsafe filesystem restoration behavior
* unauthenticated post-binding entries

### Security posture

Useful for application developers.

Not recommended for privileged infrastructure when a narrower profile exists.

Still preferable to `libsar_profile_full.so`.

---

## `libsar_profile_full.so`

All-feature developer and integration profile.

### Covers use cases

* test harnesses
* conformance testing
* fuzzing builds
* developer tools
* compatibility experiments
* non-privileged integration environments

### Includes

* `libsar_core.so`
* `libsar_archive.so`
* all implemented compression
* all implemented crypto/KMS helpers
* all implemented FEC
* CDC
* delta
* sparse
* fragmentation
* `LOSS_TOLERANT`
* Stateful Streaming Mode
* TCP
* QUIC
* TLS_EXPORTER
* PQ/hybrid TLS policy
* package/static/backup/telemetry/live-media helpers where implemented

### Excludes

Nothing intentionally, except features not implemented by the repository.

### Rejects

* reserved values and malformed data according to the spec
* unsupported algorithms unless the full profile explicitly supports them
* auth failures
* unsafe behavior forbidden by core policy

### Security posture

Maximum feature surface.

Not recommended for privileged system infrastructure.

Useful for integration and conformance only.

Should not be the default shared library installed for system components.

---

# Binding layout guidance

## C ABI

The C ABI should not expose raw Rust crate internals.

Preferred C ABI layers:

```text
libsar_core.so
  low-level parse/status/limits/wire-format handles

libsar_archive.so
  archive reader/writer/list/verify handles

libsar_profile_static_archive.so
  safe local archive profile

libsar_profile_static_package.so
  static package profile

libsar_profile_stream_package_quic.so
  stream package over QUIC profile

libsar_profile_backup*.so
  backup profiles

libsar_profile_telemetry*.so
  telemetry profiles

libsar_profile_live_media*.so
  live media profiles

libsar_profile_full.so
  development/conformance only
```

All C ABI results that contain strings, buffers, vectors, metadata, or nested objects must define:

* ownership
* allocator/freeing side
* destructor function
* length-delimited buffer rules
* string encoding
* nul-termination policy, if any
* thread-safety expectations
* cancellation behavior for long-running operations
* no-panic-across-FFI guarantee

Do not expose Rust `String`, `Vec`, `Option<T>`, slices, references, or lifetime-bearing types directly.

## Python / PyO3 / maturin

The Python package should not mirror every Rust crate as a public module.

Preferred public Python package shape:

```text
sar
  archive
  metadata
  verify
  profiles
  stream        optional
  transport     optional
```

Python objects should own or reference opaque Rust handles safely.

Python APIs should convert Rust metadata into Python-owned objects or dictionaries where appropriate.

PyO3 wrappers must not return borrowed views into temporary archive buffers unless the owner object lifetime is enforced by Python object references.

Profile-specific Python extras may be used:

```text
sar[archive]
sar[package]
sar[quic]
sar[backup]
sar[full]
```

The default Python install should not load transport, QUIC, or all-feature code unless explicitly selected.

---

# General profile rules

All profiles must preserve these invariants:

* SAR wire format remains specification-defined.
* Reserved and unsupported values fail closed unless a profile explicitly supports them.
* AEAD/authentication failures are never suppressed by `LOSS_TOLERANT`.
* Signature failures are never suppressed by `LOSS_TOLERANT`.
* Decompression failures are never suppressed by `LOSS_TOLERANT`.
* Patch failures are never suppressed by `LOSS_TOLERANT`.
* Malformed structure is never suppressed by `LOSS_TOLERANT`.
* Invalid sparse maps are never suppressed by `LOSS_TOLERANT`.
* Invalid fragment metadata is never suppressed by `LOSS_TOLERANT`.
* Deterministic reconstruction failures are never suppressed by `LOSS_TOLERANT`.
* Filesystem mutation is never performed by core parsing.
* Privileged extraction profiles must use explicit safe defaults.
* Full/developer profile must not be the default for privileged consumers.
* Transport profiles must be explicit.
* QUIC/TLS_EXPORTER behavior must remain fail-closed.
* Plaintext TCP must reject TLS_EXPORTER KMS mode.
