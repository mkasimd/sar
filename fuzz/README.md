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

## Current targets

### `smoke_core`

Minimal M12b.1 workspace-wiring target.

This target calls `sar_core::format::parse_global_header` with bounded
`ResourceLimits`. It exists only to verify that the fuzz workspace builds and
runs. Real parser coverage starts in M12b.2.
