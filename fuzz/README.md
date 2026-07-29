<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Fuzzing

This directory contains cargo-fuzz/libFuzzer harnesses for SAR parser and
archive-processing hardening work.

M12b.1 only establishes the fuzzing workspace and policy. It does not claim
parser, archive, stream, transform, malicious-corpus, or security-audit
coverage.

## Run logs and findings

Bounded local fuzzing pass records are kept in [`RUNS.md`](RUNS.md).

Generated `fuzz/corpus/**`, `fuzz/artifacts/**`, and `fuzz/target/**` outputs are not committed. Minimized crash inputs are promoted into normal crate regression tests only after review.

## Toolchain requirement

Normal `cargo-fuzz` build and run commands require a nightly Rust toolchain.

Installing `cargo-fuzz` alone is not sufficient. Some systems provide a stable
distro-packaged `cargo` and `rustc` that can run:

```bash
cargo fuzz --version
```

but still fail when building fuzz targets because cargo-fuzz invokes sanitizer
and coverage instrumentation that requires nightly-only Rust compiler flags.

Use `rustup` or an equivalent nightly Rust toolchain before running fuzz
targets.

## Installing rustup and nightly

`rustup` is the recommended Rust toolchain manager. It can install and select
stable, beta, nightly, and pinned Rust toolchains.

### Arch Linux / Manjaro / pacman-based systems

```bash
sudo pacman -S rustup
rustup default stable
rustup toolchain install nightly
```

### Debian / Ubuntu / apt-based systems

If your distribution provides a suitable `rustup` package:

```bash
sudo apt update
sudo apt install rustup
rustup default stable
rustup toolchain install nightly
```

If the packaged `rustup` is unavailable or unsuitable, use the upstream rustup
installer instead:

```bash
curl -sSf https://sh.rustup.rs | sh
rustup default stable
rustup toolchain install nightly
```

### Fedora / RHEL / Rocky Linux / Oracle Linux / dnf-based systems

If your distribution provides a suitable `rustup` package:

```bash
sudo dnf install rustup
rustup default stable
rustup toolchain install nightly
```

If the packaged `rustup` is unavailable or unsuitable, use the upstream rustup
installer instead:

```bash
curl -sSf https://sh.rustup.rs | sh
rustup default stable
rustup toolchain install nightly
```

## Installing cargo-fuzz

Install cargo-fuzz with Cargo:

```bash
cargo install cargo-fuzz
```

Verify that cargo-fuzz is available:

```bash
cargo fuzz --version
```

Verify that nightly Cargo is available:

```bash
cargo +nightly --version
```

If `cargo +nightly ...` fails with an error such as `no such command: +nightly`,
your active `cargo` binary is probably not the rustup proxy. Check:

```bash
which cargo
cargo --version
which rustup
rustup which cargo
```

Fix your shell `PATH` so that the rustup-managed Cargo, usually
`$HOME/.cargo/bin/cargo`, is used before any distro-packaged Cargo.

As an alternative to the `cargo +nightly ...` shorthand, use:

```bash
rustup run nightly cargo --version
```

## Local fuzzing workflow

Build a target:

```bash
cargo +nightly fuzz build smoke_core
```

Run a short local smoke execution:

```bash
cargo +nightly fuzz run smoke_core -- -runs=100
```

Run a longer local session manually when working on a specific target:

```bash
cargo +nightly fuzz run smoke_core
```

Stop long-running fuzzing manually with `Ctrl-C`.

## CI smoke policy

CI fuzzing, when enabled, should be short and deterministic enough to avoid
turning normal CI into a long-running fuzzing campaign.

Recommended CI behavior:

```bash
cargo +nightly fuzz build smoke_core
cargo +nightly fuzz run smoke_core -- -runs=100
```

Long-running fuzzing belongs in scheduled, dedicated, or local campaigns, not in
the default workspace test path.

## Corpus taxonomy

The M12b.5 malicious corpus categories, their purpose, example input shapes,
expected fail-closed behavior, and current status are documented in
[`CORPUS.md`](CORPUS.md).

## Corpus policy

Generated libFuzzer corpora are not committed by default.

Ignored generated corpus path:

```text
fuzz/corpus/
```

Hand-curated seed inputs may be committed separately in a clearly named tracked
location, for example:

```text
fuzz/seeds/
```

A seed file should be small, deterministic, and documented by target or purpose.

## Artifact policy

Generated fuzz artifacts are not committed.

Ignored generated artifact paths include:

```text
fuzz/artifacts/
fuzz/target/
```

Crash artifacts should be minimized before being promoted into normal regression
tests.

## Crash triage

For every crash or panic:

1. Confirm the crash reproduces.
2. Minimize the input.
3. Identify the affected parser or higher-level API.
4. Decide whether the correct fix is parser hardening, resource-limit handling,
   validation tightening, or a regression test for an already-correct error.
5. Add a normal Rust regression test for useful minimized inputs.
6. Keep the original fuzz artifact out of git unless it is intentionally
   promoted into a curated seed or fixture location.

## Minimization workflow

Use cargo-fuzz minimization:

```bash
cargo +nightly fuzz tmin smoke_core fuzz/artifacts/smoke_core/<crash-file>
```

Then rerun the minimized input:

```bash
cargo +nightly fuzz run smoke_core fuzz/artifacts/smoke_core/<minimized-file>
```

## Promotion into regression tests

Useful minimized crashes should become ordinary tests in the owning crate:

* `sar-core` parser crashes -> `crates/sar-core/tests/`
* `sar-archive` structural/archive crashes -> `crates/sar-archive/tests/`
* `sar-stream` transcript/stream validation crashes -> `crates/sar-stream/tests/`

Regression tests should assert the stable expected behavior, usually that
malformed input returns a deterministic error instead of panicking.

## M12b.3 smoke-run commands

Build all M12b.3 targets:

```bash
cargo +nightly fuzz build archive_structural
cargo +nightly fuzz build archive_entry_decode
cargo +nightly fuzz build archive_audit
cargo +nightly fuzz build stream_transcript
```

Run short smoke executions with seed corpus:

```bash
mkdir -p fuzz/corpus/archive_structural
cp fuzz/seeds/archive_structural/*.bin fuzz/corpus/archive_structural/
cargo +nightly fuzz run archive_structural -- -runs=100

mkdir -p fuzz/corpus/archive_entry_decode
cp fuzz/seeds/archive_entry_decode/*.bin fuzz/corpus/archive_entry_decode/
cargo +nightly fuzz run archive_entry_decode -- -runs=100

mkdir -p fuzz/corpus/archive_audit
cp fuzz/seeds/archive_audit/*.bin fuzz/corpus/archive_audit/
cargo +nightly fuzz run archive_audit -- -runs=100

mkdir -p fuzz/corpus/stream_transcript
cp fuzz/seeds/stream_transcript/*.bin fuzz/corpus/stream_transcript/
cargo +nightly fuzz run stream_transcript -- -runs=100
```

Do not use tracked `fuzz/seeds/...` directories directly as writable libFuzzer
corpus directories. Copy seeds to `fuzz/corpus/` first, which is gitignored.

## M12b.3 coverage and limitations

The following applies to all four M12b.3 targets:

* Malformed input returning errors is expected and correct.
* Panics on malformed input are treated as bugs and should be minimized and
  promoted into regression tests.
* Resource limits are applied before allocation or expansion.
* No exhaustive fuzzing coverage is claimed.
* No production hardening or security audit completion is claimed.
* No malicious corpus family coverage is claimed.
* Does not execute stream/session side effects.
* Does not perform filesystem extraction.
* Does not require key material or external delta bases.

### `archive_structural`

Covers: high-level archive structural parsing via `ArchiveReader::read_global_header`.

Does not cover: entry payload decoding, stream/session execution, CD offset
verification, control entry walking, FEC repair, delta reconstruction, CDC
chunk resolution.

### `archive_entry_decode`

Covers: global header parsing plus bounded ordinary entry walking and decoding
via `ArchiveReader::next_entry`, stopping at 16 entries or on error.

Does not cover: encrypted entries (no key provider), delta entries requiring
external bases, stream/session entries, filesystem extraction, full archive
verification.

### `archive_audit`

Covers: archive audit metadata walking via `ArchiveReader::audit` with
`PayloadAuditPolicy::MetadataOnly` and `ControlEntryPolicy::Reject`. Exercises
LFH parsing, entry classification, and CD parsing without payload decoding.

Does not cover: payload decoding, key providers, control entry preservation,
inert payload inspection, FEC repair.

### `stream_transcript`

Covers: `sar-stream` transcript semantic validation via
`validate_stream_transcript_with_options`. Stream transcript semantic
validation is delegated to `sar-stream`; this fuzz target does not reimplement
transcript rules.

Does not cover: archive stream parser (`StreamArchiveParser`), session
execution, filesystem side effects, long-running campaigns.

## Current targets

### `smoke_core`

Minimal M12b.1 workspace-wiring target.

This target calls `sar_core::format::parse_global_header` with bounded
`ResourceLimits`. It exists only to verify that the fuzz workspace builds and
runs.

### `parse_global_header`

M12b.2 parser target for `sar_core::format::parse_global_header`.

Covers Global Header structure, magic/version validation, global flag byte
length handling, optional partition descriptor parsing, and optional KMS
extension length handling.

### `parse_lfh`

M12b.2 parser target for `sar_core::format::parse_lfh`.

The first input byte selects a bounded subset of Global Flags used to interpret
the LFH layout. The remaining bytes are parsed as LFH bytes.

### `parse_tlv`

M12b.2 parser target for `sar_core::tlv::parse_tlvs`.

Covers TLV type classification, value length handling, count limits, and
8-byte alignment padding validation.

### `parse_cd_footer`

M12b.2 parser target for `sar_core::format::parse_footer` and
`sar_core::format::parse_central_dictionary`.

The target always attempts footer parsing, then uses the first input byte to
select a bounded subset of Central Dictionary flags before parsing the remaining
bytes as a Central Dictionary.

### `archive_structural`

M12b.3 high-level structural parsing target using `ArchiveReader`.

Treats input as arbitrary archive bytes. Constructs `ArchiveReader` with strict
resource limits and calls `read_global_header`. Does not decode entry payloads.
Does not execute stream/session semantics.

Malformed input returning errors is expected. Panics on malformed input are
treated as bugs and should be minimized and promoted into regression tests.

### `archive_entry_decode`

M12b.3 archive ordinary entry walking target using `ArchiveReader`.

Treats input as arbitrary archive bytes. After parsing the global header, walks
at most 16 ordinary entries via `next_entry`. Stops on the first error. Does
not perform filesystem extraction. Does not require key providers or external
delta bases.

Malformed input returning errors is expected. Panics on malformed input are
treated as bugs and should be minimized and promoted into regression tests.

### `archive_audit`

M12b.3 archive audit metadata walking target using `ArchiveReader::audit`.

Treats input as arbitrary archive bytes. Calls `audit` with
`PayloadAuditPolicy::MetadataOnly` and `ControlEntryPolicy::Reject`. Does not
decode encrypted payloads or execute control entries.

Malformed input returning errors is expected. Panics on malformed input are
treated as bugs and should be minimized and promoted into regression tests.

### `stream_transcript`

M12b.3 stream transcript semantic validation target using
`sar_stream::validate_stream_transcript_with_options`.

Treats input as arbitrary stream transcript bytes. Transcript recording is
disabled so no files are written to disk. Stream transcript semantic
validation is delegated to `sar-stream`; this fuzz target does not reimplement
transcript rules.

Malformed input returning errors is expected. Panics on malformed input are
treated as bugs and should be minimized and promoted into regression tests.

### `archive_writer_state_machine`

M12b.4 stateful `ArchiveWriter` operation-sequence target.

Drives `ArchiveWriter<Vec<u8>>` through arbitrary bounded sequences of
`AddEntry`, `AddSparseEntry`, `CheckState`, and `Finish` operations to exercise
writer lifecycle state transitions.  Uses `sparse = true` and indexed output so
both sparse entries and CD/Footer finalization paths are reachable.

Does not cover: encryption, key providers, delta entries, FEC, filesystem
extraction, compression other than STORE.

### `stream_archive_parser_state_machine`

M12b.4 stateful `StreamArchiveParser` forward-only push-parsing target.

Drives `StreamArchiveParser` through arbitrary bounded sequences of
`PushChunk`, `Step`, `FinalizeInput`, and `CheckState` operations to exercise
push-parse state transitions at unusual chunk boundaries.  Resource limits are
applied before every allocation and buffer expansion.

Does not cover: encryption, key providers, delta entries, filesystem
extraction.

### `transport_tcp_connection_state_machine`

M12b.4 stateful in-memory transport write/process/close state-machine target.

Drives `TransportHarness` (TCP-policy in-memory binding) through arbitrary
bounded sequences of `Open`, `Feed`, `Close`, `Reset`, `CheckInactivity`, and
`DrainActions` operations.  Session behavior is exercised indirectly through
`InMemoryTransport`'s internal `SessionManager` calls.  No real sockets, no
async runtime, no QUIC features.

Direct `SessionManager` fuzzing is not included; session state is covered
through `sar-transport`.

Does not cover: real TCP networking, QUIC transport, async runtime, TLS
exporter material, encrypted entry decryption.

## Hand-curated seed inputs

Small deterministic seed inputs live under:

```text
fuzz/seeds/<target-name>/
```
