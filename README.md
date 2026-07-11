# sar-rust

Rust reference implementation for the **SAR Protocol v1.0**.

SAR is an archive and transport-oriented format designed around explicit metadata, bounded parsing, optional compression, authenticated encryption, selective FEC, sparse files, fragmentation, recovery metadata, and streaming/transport profiles.

This repository contains the Rust workspace for `libsar`, including the core wire-format implementation, high-level archive APIs, feature crates, CLI tooling, and transport/session components.

## Project status

This repository is under active development.

The current implementation includes:

* SAR v1.0 archive parsing and writing
* indexed and `NO_INDEX` archive flows
* low-level GH/LFH/CD/Footer/TLV parsing and writing
* status/error mapping
* resource limits and bounded parsing
* compression support for STORE, DEFLATE, and ZSTD
* hashing and AEAD encryption support
* KMS parameter parsing and key-provider abstraction
* selective FEC metadata and XOR/Reed-Solomon codecs
* sparse file metadata and sparse reconstruction
* fragment validation and reassembly
* loss-tolerant degraded reconstruction policy helpers
* archive-level recovery metadata inspection, repair planning, and repair execution
* CDC metadata, CDC map parsing/writing, FASTCDC chunking helpers, and CDC validation helpers
* delta metadata and patch application for implemented algorithms
* stateful streaming session semantics
* TCP and QUIC transport bindings in `sar-transport`
* a command-line tool, `sar`

The implementation is not yet a finished stable release. Public APIs, packaging, conformance profiles, and foreign-language bindings are still being developed.

For the detailed milestone roadmap, see:

* `docs/MILESTONES.md`
* `docs/API.md`
* `docs/CONFORMANCE.md`
* `docs/SECURITY.md`
* `docs/MACHINE_READABLE_API.json`

## Workspace layout

```text
crates/
  sar-core/            canonical wire format, status/error, limits, low-level helpers
  sar-archive/         high-level archive reader/writer/verify/list/recovery APIs
  sar-compression/     compression registry and bounded encode/decode helpers
  sar-crypto/          hashing, AEAD, KMS types, key-provider abstraction
  sar-fec/             XOR and Reed-Solomon FEC codecs and metadata parsing
  sar-cdc/             CDC metadata, CDC map, FASTCDC, and validation helpers
  sar-delta/           patch algorithm registry and implemented patch application
  sar-fragmentation/   fragment semantic validation and reassembly
  sar-sparse/          sparse extent validation and sparse reconstruction
  sar-loss-tolerant/   degraded reconstruction policy helpers
  sar-partition/       future partition/multi-volume support placeholder
  sar-stream/          stateful streaming session semantics
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

fuzz/
```

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

`sar-archive` owns the high-level archive API:

* `ArchiveReader`
* `ArchiveWriter`
* `EntryInput`
* `EntryReader`
* `EntryMetadata`
* archive verification and listing
* logical file reconstruction
* transform orchestration
* archive stream parsing
* profile validation
* archive-level recovery and repair orchestration

Application code that wants to create, read, verify, or inspect SAR archives should usually start with `sar-archive`.

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

* `sar-stream` implements in-memory stateful streaming session semantics.
* `sar-transport` implements transport abstractions plus TCP and QUIC bindings over the streaming/session layer.

Transport code is separated from archive code and from the low-level wire-format crate.

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

### Low-level parsing

Use `sar-core` directly when you need wire-format parsing/writing primitives rather than high-level archive behavior:

```rust
use sar_core::{
    ResourceLimits,
    format::{parse_global_header, parse_lfh},
};

fn inspect_first_lfh(bytes: &[u8]) -> Result<(), sar_core::SarError> {
    let limits = ResourceLimits::default();
    let (gh, rest) = parse_global_header(bytes, &limits)?;
    let (lfh, _) = parse_lfh(rest, gh.flags, &limits)?;

    println!("first entry: {}", lfh.name);
    Ok(())
}
```

## CLI

The workspace includes a command-line tool in `crates/sar-cli`.

Common commands:

```bash
sar create <input> <output.sar>
sar extract <archive.sar> <output-dir>
sar list <archive.sar>
sar verify <archive.sar>
sar inspect <archive.sar> --json
sar repair <archive.sar> <output.sar> --fec --erasures erasures.json
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
sar create input-dir encrypted.sar --encrypt aes256-gcm --password "password"
sar extract encrypted.sar output-dir --password "password"
```

FEC example:

```bash
sar create input-dir archive.sar --fec rs
sar verify archive.sar --recovery
```

Resource limits can be configured for extraction, verification, and repair. The CLI uses conservative defaults and fails closed on configured limit violations.

## Security posture

The implementation is designed around fail-closed behavior and bounded parsing.

Important security properties:

* resource limits are enforced before dangerous allocation paths
* checked arithmetic and checked conversions are used in parser and reconstruction paths
* malformed, unsupported, reserved, ambiguous, or conflicting inputs fail closed
* AEAD authentication failure is never loss-tolerant
* plaintext is not released before successful authentication
* loss-tolerant reconstruction does not suppress authentication, decompression, patch, sparse, fragment, or structural failures
* archive repair works on explicit erasure descriptions and does not guess missing ranges
* library parsing does not create files, directories, symlinks, devices, or filesystem metadata side effects

This project is still pre-stable. Do not treat it as audited production security software until the security and conformance milestones are complete.

For details, see:

* `docs/SECURITY.md`
* `docs/CONFORMANCE.md`
* `docs/SPEC_QUESTIONS.md`

## Validation

Recommended local validation:

```bash
cargo fmt
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check
```

Some optional checks require additional tools or CI setup.

## Feature flags

Most crates currently expose no Cargo feature flags.

`sar-transport` exposes:

* `quic`: enables the QUIC transport binding using `quinn`, `rustls`, and `tokio`

Without the `quic` feature, TCP and in-memory transport behavior remain available where supported.

## Documentation

Primary documentation files:

* `docs/API.md` — audited API inventory and current public surface
* `docs/CONFORMANCE.md` — conformance notes and profile status
* `docs/CRATE_RESPONSIBILITIES.md` — crate ownership boundaries
* `docs/LIBRARY_LAYOUT.md` — workspace and library layout
* `docs/MACHINE_READABLE_API.json` — machine-readable API inventory
* `docs/MILESTONES.md` — milestone roadmap and completion status
* `docs/SECURITY.md` — security posture and constraints
* `docs/SPEC_QUESTIONS.md` — open specification questions and implementation gaps

The root README intentionally avoids duplicating the milestone tracker. Use `docs/MILESTONES.md` for roadmap state.

## Licensing

The Rust reference implementation is licensed under the Apache License, Version 2.0.

The SAR Protocol specification is intended to be distributed separately under Creative Commons Attribution 4.0 International (CC BY 4.0).

Check the repository license files and specification distribution for the authoritative license text.

## Contributing

This repository is currently being developed toward a stable reference implementation.

Before making substantial changes:

* review `docs/CRATE_RESPONSIBILITIES.md`
* review `docs/API.md`
* preserve the SAR v1.0 wire format unless a milestone explicitly changes it
* keep parser and reconstruction paths bounded
* avoid compatibility re-exports that blur crate ownership
* keep high-level archive behavior in `sar-archive`
* keep wire-format/status/limits helpers in `sar-core`
* avoid introducing filesystem side effects into library parsing code

Run the validation commands before opening a pull request.

## Current limitations

Notable limitations include:

* no stable C ABI yet
* no Python bindings yet
* no Swift/iOS or Kotlin/Java Android bindings yet
* packaging and release artifact automation are not finalized
* some assigned algorithm IDs are recognized but intentionally unsupported
* some conformance, fuzzing, and external audit work remains pending

See the documentation in `docs/` for the detailed and current status.
