<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# sar-rust

Rust reference implementation for the **SAR Protocol v1.0**.

> **Status: experimental / in development**
>
> SAR is under active development and has not yet undergone independent security audit, production hardening, or multi-implementation interoperability testing. Bounded local fuzzing campaigns were completed during M12b; exhaustive fuzzing is not claimed.
>
> Do **not** use this implementation in environments requiring stable production-grade behavior, regulatory assurance, long-term archival guarantees, or security certification.

SAR is an experimental archive, replication, recovery, and streaming container format.

It is designed for cases where archive bytes are not just "a compressed bag of files," but part of a larger integrity, recovery, synchronization, or transport workflow: explicit metadata, bounded parsing, deterministic validation, authenticated transforms, sparse/delta/FEC handling, archive-level recovery metadata, and stream/session-aware profiles.

This repository contains the Rust workspace for the SAR Protocol v1.0 reference implementation, including the wire-format layer, high-level archive APIs, feature crates, CLI tooling, conformance vectors, audit primitives, and stream/transport components.

## Why SAR exists

Most archive tools are optimized for one primary job: package files, compress them, and unpack them later. That is often exactly what you want.

SAR explores a different problem space: **archives that also need explicit integrity, recovery, replication, and streaming semantics inside the format itself**.

The motivation is not that `tar`, `zip`, `gzip`, `gpg`, `rsync`, parity files, or transport protocols are bad. They are mature, useful, and usually the better choice for ordinary workflows. The motivation is that once these tools are combined into larger systems, important behavior often moves outside the archive format and into scripts, conventions, sidecar files, application-specific metadata, or operational assumptions.

For example, a pipeline such as:

```bash
tar | gzip | gpg
```

can be simple and effective, but the resulting byte stream does not natively describe things like:

* which transform order is valid and required
* which metadata is authenticated
* how sparse files, deltas, fragments, and recovery data interact
* which parts are recoverable and which failures must remain fatal
* how archive-level recovery metadata is bound to the protected byte range
* how a receiver should fail closed on reserved, unsupported, or ambiguous features
* how to distinguish ordinary archive content from stream/session/control content
* how to produce machine-readable conformance evidence for the exact behavior being tested

SAR is intended to make those choices explicit in one profile-governed format.

Potential future use cases, if the implementation matures, include:

* **high-integrity backup containers** where compression, encryption, sparse files, delta patches, and recovery metadata need deterministic ordering and fail-closed validation
* **cold-storage or offline transfer packages** where archive-level recovery metadata and explicit conformance profiles are more useful than ad-hoc sidecar conventions
* **replication-oriented archives** where unchanged base data, patch data, sparse reconstruction, and content hashes need to be represented as first-class archive semantics
* **auditable delivery bundles** where validators need a machine-readable report of structure, algorithms, metadata, recovery information, and payload verification status
* **stream transcript capture and validation** where received SAR-shaped stream bytes need to be recorded exactly and later validated semantically
* **profile-restricted environments** where unsupported transforms, stream/session entries, metadata classes, or recovery features must be rejected deterministically rather than ignored

The tradeoff is complexity. SAR intentionally accepts more format and implementation complexity in order to make these behaviors explicit, testable, and profile-governed.

That does not mean every use case needs SAR. For ordinary archiving, existing tools are simpler, more stable, and more widely supported.

## What SAR is not intended to replace

SAR is not intended to replace established formats and tools for general-purpose use.

Use existing tools when they fit the job:

* use `tar` when you need a simple, widely supported archive stream
* use `zip` when you need broad desktop/tooling compatibility and random-access archive support
* use `tar | gzip`, `tar | zstd`, or similar pipelines when simple compression pipelines are sufficient
* use `gpg`, age, or dedicated encryption tools when mature file encryption is the main requirement
* use `rsync`, object storage replication, or existing backup systems when those already satisfy your synchronization or recovery model
* use established production backup/archive software when stability, support, and ecosystem compatibility matter more than SAR's experimental design goals

SAR is aimed at workflows where the archive/container itself needs to carry more of the system contract: deterministic parsing rules, transform ordering, authenticated metadata behavior, recovery metadata, sparse/delta/FEC semantics, profile-specific rejection policy, and stream/session-aware validation.

It is not yet a production archival standard, a certified security product, or a drop-in replacement for existing archive ecosystems.

## Project status

This repository is under active development and should be treated as an experimental reference implementation.

The implementation currently includes:

* SAR v1.0 archive parsing and writing
* indexed and `NO_INDEX` archive flows
* low-level Global Header, Local File Header, Central Dictionary, Footer, and TLV parsing/writing
* status/error mapping
* resource limits and bounded parsing
* compression support for STORE, DEFLATE, and ZSTD
* hashing and AEAD encryption support
* KMS parameter parsing and key-provider abstraction
* selective LFH FEC metadata and XOR/Reed-Solomon codecs
* archive-level Recovery TLV inspection, generation, repair planning, and repair execution
* sparse file metadata and sparse reconstruction
* fragment validation and reassembly
* loss-tolerant degraded reconstruction policy helpers
* CDC metadata, CDC map parsing/writing, FASTCDC chunking helpers, and CDC validation helpers
* delta metadata, patch application, and generated STORE_PATCH/VCDIFF/BSDIFF fixture coverage
* high-level archive audit primitives in `sar-archive`
* explicit inert container/transcript audit mode for SAR-shaped bytes in `sar-archive`
* stateful streaming session semantics in `sar-stream`
* serialized stream transcript validation and optional exact-byte transcript recording in `sar-stream`
* TCP and QUIC transport bindings in `sar-transport`
* deterministic conformance-vector framework under `test-vectors/`
* a command-line tool, `sar`

The implementation is not yet a finished stable release. Public APIs, packaging, conformance profiles, fuzzing, security audit, and foreign-language bindings are still being developed.

For the detailed milestone roadmap, see:

* `docs/MILESTONES.md`
* `docs/API.md`
* `docs/CONFORMANCE.md`
* `docs/SECURITY.md`
* `docs/machine-readable/MACHINE_READABLE_API.json`

## What this repository is

This repository is:

* a Rust reference implementation for the SAR Protocol v1.0
* a conformance-vector and implementation testbed
* an archive/container, recovery, streaming/session, and transport experimentation workspace
* a pre-stable implementation intended for review, testing, and further hardening

This repository is not yet:

* a production-ready archival system
* a certified security product
* a stable ABI/API platform
* a multi-implementation standard with demonstrated interoperability
* a replacement for established production archive formats in high-assurance environments

## Workspace layout

```text
crates/
  sar-core/            canonical wire format, status/error, limits, low-level helpers
  sar-archive/         high-level archive reader/writer/verify/list/recovery/audit APIs
  sar-compression/     compression registry and bounded encode/decode helpers
  sar-crypto/          hashing, AEAD, KMS types, key-provider abstraction
  sar-fec/             XOR and Reed-Solomon FEC codecs and metadata parsing
  sar-cdc/             CDC metadata, CDC map, FASTCDC, and validation helpers
  sar-delta/           patch algorithm registry and implemented patch application/generation
  sar-fragmentation/   fragment semantic validation and reassembly
  sar-sparse/          sparse extent validation and sparse reconstruction
  sar-loss-tolerant/   degraded reconstruction policy helpers
  sar-partition/       future partition/multi-volume support placeholder
  sar-stream/          stateful streaming session semantics and transcript validation/recording
  sar-transport/       transport abstraction, TCP binding, QUIC binding
  sar-cli/             command-line tool

docs/
  API.md
  CONFORMANCE.md
  CRATE_RESPONSIBILITIES.md
  LIBRARY_LAYOUT.md
  MACHINE_READABLE_API.json
  MILESTONES.md
  SECURITY.md
  SPEC_QUESTIONS.md

test-vectors/
  valid/
  invalid/
  profiles/

fuzz/
```

Future foreign-language binding work is planned inside this monorepo rather than in separate repositories. Planned paths include:

* `ffi/c/` for future C ABI headers, sources, examples, and tests
* `bindings/python/` for future Python/PyO3 packaging, examples, and tests
* `bindings/swift/` for future Swift/iOS bindings
* `bindings/android/` for future Kotlin/Java Android bindings

These paths are future M14/M16 scope and are not part of the current stable API surface.

## Crate responsibilities

### `sar-core`

`sar-core` owns the canonical SAR wire-format layer:

* global header, local file header, central dictionary, footer, and TLV structures
* global flags and entry mode validation
* status and error types
* resource limits
* low-level parsing and writing helpers
* low-level sparse-map wire helpers
* narrow error-conversion bridges used by the rest of the workspace

It does not own high-level archive reader/writer behavior.

### `sar-archive`

`sar-archive` owns the high-level archive/container API:

* `ArchiveReader`
* `ArchiveWriter`
* `EntryInput`
* `EntryReader`
* `EntryMetadata`
* archive verification and listing
* archive structural audit
* inert container/transcript audit for SAR-shaped bytes
* ordinary archive-entry payload verification
* logical file reconstruction
* transform orchestration
* archive stream parsing
* profile validation
* archive-level recovery and repair orchestration

Application code that wants to create, read, verify, audit, or inspect SAR archives should usually start with `sar-archive`.

`sar-archive` does not process stream/session semantics. It classifies LFH `EntryMode` bits for archive safety policy, but it does not interpret `DATA_WRITE`, `SESSION_*`, stream lifecycle, sequence continuity, or transport semantics.

### Feature crates

Specialized crates own their own domains:

* `sar-compression`: compression algorithms and bounded compression/decompression helpers
* `sar-crypto`: hash, AEAD, KMS, secret-buffer, and key-provider APIs
* `sar-fec`: FEC metadata and codecs
* `sar-cdc`: content-defined chunking metadata and helpers
* `sar-delta`: delta/patch registry and implemented patch application
* `sar-fragmentation`: fragment validation and reassembly
* `sar-sparse`: sparse extent validation and reconstruction
* `sar-loss-tolerant`: degraded reconstruction policy helpers

The high-level archive crate composes these feature crates where appropriate.

### Streaming and transport crates

* `sar-stream` implements in-memory stateful streaming session semantics, stream transcript semantic validation, and optional exact-byte transcript recording.
* `sar-transport` implements transport abstractions plus TCP and QUIC bindings over the streaming/session layer.

Transport and streaming code are separated from archive code and from the low-level wire-format crate. Stream/session semantics belong to `sar-stream`, not `sar-archive`.

## Basic Rust usage

### Writing an archive

```rust
use std::fs::File;

use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput};

fn main() -> Result<(), sar_core::SarError> {
    let file = File::create("example.sar")?;
    let mut writer = ArchiveWriter::new(file, ArchiveWriterOptions::default())?;

    writer.add_entry(EntryInput::file("hello.txt", b"hello world".to_vec()))?;
    writer.finish()?;

    Ok(())
}
```

### Reading an archive

`ArchiveReader` is the high-level archive reader for seekable inputs. Its input type must implement both `std::io::Read` and `std::io::Seek`, because indexed archives require random access to the trailing Footer and Central Dictionary.

Use `ArchiveReader` for files and other seekable containers. For forward-only byte streams, pipes, sockets, or partial input, use `sar_archive::StreamArchiveParser` instead.

```rust
use std::fs::File;
use std::io::BufReader;

use sar_archive::ArchiveReader;

fn main() -> Result<(), sar_core::SarError> {
    let file = File::open("example.sar")?;
    let mut reader = ArchiveReader::new(BufReader::new(file))?;

    reader.read_global_header()?;

    while let Some(entry) = reader.next_entry()? {
        println!("{}: {} bytes", entry.metadata.name, entry.payload.len());
    }

    Ok(())
}
```

### Auditing an archive

Use `sar-archive` audit APIs when you want a deterministic, machine-readable report about archive/container structure and payload verification status.

```rust
use std::fs::File;
use std::io::BufReader;

use sar_archive::{ArchiveAuditOptions, ArchiveReader};

fn main() -> Result<(), sar_core::SarError> {
    let file = File::open("example.sar")?;
    let mut reader = ArchiveReader::new(BufReader::new(file))?;

    let report = reader.audit(ArchiveAuditOptions::default())?;

    println!("archive mode: {:?}", report.mode);
    println!("entries seen: {}", report.entry_count_seen);

    Ok(())
}
```

Explicit inert audit mode can structurally inspect SAR-shaped bytes containing session-control or opcode-bearing entries without executing stream/session/opcode semantics.

```rust
use std::fs::File;
use std::io::BufReader;

use sar_archive::{
    ArchiveAuditOptions,
    ArchiveReader,
    ControlEntryPolicy,
    PayloadAuditPolicy,
};

fn main() -> Result<(), sar_core::SarError> {
    let file = File::open("transcript-or-container.sar")?;
    let mut reader = ArchiveReader::new(BufReader::new(file))?;

    let options = ArchiveAuditOptions {
        control_entry_policy: ControlEntryPolicy::PreserveInert,
        payload_policy: PayloadAuditPolicy::MetadataOnly,
        include_inert_payload_bytes: false,
        ..ArchiveAuditOptions::default()
    };

    let report = reader.audit(options)?;

    for entry in report.entries {
        println!(
            "offset={} kind={:?} status={:?}",
            entry.lfh_offset,
            entry.kind,
            entry.payload_status,
        );
    }

    Ok(())
}
```

### Validating a stream transcript

Use `sar-stream` for stream transcript semantics. `sar-archive` can structurally audit SAR-shaped bytes, but it does not validate session lifecycle, Stream ID binding, sequence continuity, or `SESSION_*` semantics.

```rust
use sar_stream::validate_stream_transcript;

fn main() -> Result<(), sar_core::SarError> {
    let bytes = std::fs::read("stream-transcript.sar")?;
    let report = validate_stream_transcript(&bytes)?;

    println!("entries processed: {}", report.entry_count);

    Ok(())
}
```

Optional transcript recording preserves the exact received bytes before semantic validation. A recorded transcript is evidence of received bytes, not proof of validity.

```rust
use sar_stream::{
    StreamTranscriptValidationOptions,
    TranscriptRecording,
    validate_stream_transcript_with_options,
};

fn main() -> Result<(), sar_core::SarError> {
    let bytes = std::fs::read("incoming-stream.sar")?;

    let options = StreamTranscriptValidationOptions {
        recording: TranscriptRecording::Path {
            path: "recorded-transcript.sar".into(),
            overwrite: false,
        },
        ..StreamTranscriptValidationOptions::default()
    };

    let report = validate_stream_transcript_with_options(&bytes, &options)?;

    println!("entries processed: {}", report.entry_count);

    Ok(())
}
```

### Low-level parsing

Use `sar-core` directly when you need wire-format parsing/writing primitives rather than high-level archive behavior.

```rust
use sar_core::{
    ResourceLimits,
    format::{parse_global_header, parse_lfh},
};

fn inspect_first_lfh(bytes: &[u8]) -> Result<(), sar_core::SarError> {
    let limits = ResourceLimits::default();

    let (gh, header_len) = parse_global_header(bytes, &limits)?;
    let (lfh, _) = parse_lfh(&bytes[header_len..], &gh.flags, &limits)?;

    println!("first entry: {}", String::from_utf8_lossy(&lfh.name));

    Ok(())
}
```

## CLI

The workspace includes a command-line tool in `crates/sar-cli`.

Common operations include creating, listing, extracting, verifying, inspecting, and repairing SAR archives. Exact flags may change while the implementation remains pre-stable.

Typical commands:

```bash
sar create <input> <output.sar>
sar extract <archive.sar> <output-dir>
sar list <archive.sar>
sar verify <archive.sar>
sar inspect <archive.sar> --json
sar repair <archive.sar> <output.sar>
sar version
```

Compression examples:

```bash
sar create input-dir archive.sar --compression store
sar create input-dir archive.sar --compression deflate
sar create input-dir archive.sar --compression zstd --compression-level 9
```

Encryption example:

```bash
sar create input-dir encrypted.sar --encrypt aes256-gcm --password "test-password"
sar extract encrypted.sar output-dir --password "test-password"
```

Resource limits can be configured for extraction, verification, and repair. These limits are part of the implementation's fail-closed resource model and help bound allocation, decompression, sparse reconstruction, fragment handling, and repair behavior.

Example bounded extraction:

```bash
sar extract asset.sar ./target \
  --max-decoded-entry-size 1073741824 \
  --max-in-memory-buffer 268435456 \
  --max-loss-tolerant-gap 65536
```

The exact limits should be selected for the deployment environment and profile. The CLI uses conservative defaults and fails closed on configured limit violations.

FEC/recovery examples depend on the selected profile and current CLI surface. See `docs/API.md` and `docs/CONFORMANCE.md` for the current implemented behavior.

## Security posture

The implementation is designed around fail-closed behavior, bounded parsing, and explicit transform ordering.

Important security properties:

* resource limits are enforced before dangerous allocation paths
* checked arithmetic and checked conversions are used in parser and reconstruction paths
* malformed, unsupported, reserved, ambiguous, or conflicting inputs fail closed
* AEAD authentication failure is never loss-tolerant
* plaintext is not released before successful authentication
* loss-tolerant reconstruction does not suppress authentication, decompression, patch, sparse, fragment, or structural failures
* archive repair works on explicit erasure descriptions and does not guess missing ranges
* library parsing does not create files, directories, symlinks, devices, or filesystem metadata side effects
* `sar-archive` inert audit mode is structural/reporting-only and does not execute stream/session/opcode semantics

This project is still pre-stable and has not yet completed independent security audit or multi-implementation interoperability validation. Bounded local fuzzing campaigns were completed during M12b; exhaustive fuzzing is not claimed. Do not treat it as audited production security software.

For details, see:

* `docs/SECURITY.md`
* `docs/CONFORMANCE.md`
* `docs/SPEC_QUESTIONS.md`

## Validation

Recommended Rust workspace validation:

```bash
cargo fmt --all
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Conformance manifest validation is covered by the Rust test suite, including `sar-archive` conformance manifest tests.

Optional documentation/JSON validation, if Python is available:

```bash
python -m json.tool docs/machine-readable/MACHINE_READABLE_API.schema.json > /dev/null
python tools/check_api_schema.py
python tools/generate_api_md.py --check
python -m json.tool docs/machine-readable/MACHINE_READABLE_API.json > /dev/null
python -m json.tool test-vectors/manifest.schema.json > /dev/null
find test-vectors -name manifest.json -print0 | xargs -0 -n1 python -m json.tool > /dev/null
```

Optional dependency and policy checks, depending on local tooling and CI setup:

```bash
cargo audit
cargo deny check
```

## Feature flags

Most crates currently expose no Cargo feature flags.

`sar-transport` exposes:

* `quic`: enables the QUIC transport binding using `quinn`, `rustls`, and `tokio`

Without the `quic` feature, TCP and in-memory transport behavior remain available where supported.

## Documentation

Primary documentation files:

* `specification.md` - SAR Protocol v1.0 specification document
* `docs/machine-readable/MACHINE_READABLE_API.json` - authoritative machine-readable public API inventory
* `docs/machine-readable/MACHINE_READABLE_API.schema.json` - schema for the machine-readable API inventory
* `docs/API.md` - generated human-readable subset of the API inventory
* `docs/CONFORMANCE.md` - conformance notes and profile status
* `docs/COMPATIBILITY.md` - compatibility notes, pre-stable status, and deferred functionality
* `docs/CRATE_RESPONSIBILITIES.md` - crate ownership boundaries
* `docs/LIBRARY_LAYOUT.md` - workspace and library layout
* `docs/MILESTONES.md` - milestone roadmap and completion status
* `docs/SECURITY.md` - security posture and constraints
* `docs/SPEC_QUESTIONS.md` - open specification questions and implementation gaps
* `test-vectors/README.md` - conformance vector layout and manifest conventions
* `AI_DISCLOSURE.md` - AI-assisted development disclosure

The root README intentionally avoids duplicating the milestone tracker. Use `docs/MILESTONES.md` for roadmap state.

## AI-assisted development

This project was developed with substantial AI assistance.

AI agents were used for implementation drafts, refactoring suggestions, test generation, documentation updates, conformance-vector scaffolding, and review assistance. The human maintainer retained responsibility for protocol design, architectural constraints, security invariants, crate-boundary decisions, milestone scope, review, acceptance, licensing, and release decisions.

See [`AI_DISCLOSURE.md`](AI_DISCLOSURE.md).

## Licensing

Copyright © 2026 M. Kasim Dönmez.

This repository is multi-licensed:

* Source code, tests, examples, tools, conformance manifests, and implementation documentation are licensed under the Apache License 2.0.
* `specification.md`, the SAR Protocol v1.0 specification document, is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).

See:

* `LICENSES/Apache-2.0.txt`
* `LICENSES/CC-BY-4.0.txt`

Unless a file contains a different SPDX license identifier, implementation files are Apache-2.0.

## Contributing

Contributions are welcome while the project remains experimental and milestone-driven.

Before making substantial changes, read `CONTRIBUTING.md` and the authoritative project documents it links to.

AI-assisted contributions are acceptable, but generated code remains the contributor's responsibility. Material AI assistance should be disclosed in the pull request.

## Current limitations

Notable limitations include:

* no stable production release yet
* no independent security audit yet
* bounded local fuzzing campaigns have been completed (M12b); exhaustive fuzzing coverage is not claimed
* multi-implementation interoperability has not been demonstrated
* public APIs may still change before stabilization
* no stable C ABI yet
* no Python bindings yet
* no Swift/iOS or Kotlin/Java Android bindings yet
* packaging and release artifact automation are not finalized
* some assigned algorithm IDs are recognized but intentionally unsupported
* some profile-specific conformance and external audit work remains pending

See the documentation in `docs/` for the detailed and current status.
