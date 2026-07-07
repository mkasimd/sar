# sar-rust

Production-oriented Rust workspace for **SAR Protocol v1.0** foundations.

## Current MVP (this session)

Implemented milestones:

- **Milestone 1**: SAR error/status registry, global flags model, checked LE parsing/writing primitives, overflow/length/bounds/flag validators.
- **Milestone 2**: parser/writer for Global Header, Local File Header, Central Dictionary, Footer, and metadata TLV blocks (with alignment/padding checks).
- **Milestone 3**: minimal archive reader/writer for **STORE-only** payloads in sequential `NO_INDEX` and indexed modes.
- **Milestone 4**: compression + transform-pipeline foundation.
  - STORE (`0x00`)
  - DEFLATE (`0x01`)
  - ZSTD (`0x02`)
- **Milestone 5**: crypto + KMS foundation.
  - SHA-256 and BLAKE3 hashing
  - AES-256-GCM and XChaCha20-Poly1305 entry encryption
  - PBKDF2-HMAC-SHA256 and Argon2id KMS parsing/derivation
  - `KeyProvider` abstraction for password/external key resolution
- **MVP CLI** (`sar-cli`) built on `sar-core`.

## Workspace layout

```text
crates/
  sar-core/
  sar-compression/
  sar-crypto/
  sar-cdc/
  sar-delta/
  sar-fec/
  sar-fragmentation/
  sar-partition/
  sar-sparse/
  sar-loss-tolerant/
  sar-stream/
  sar-transport/
  sar-cli/
docs/
tests/
fuzz/
```

Placeholder crates compile but intentionally do not implement later milestones yet.

## CLI

```text
sar create <input> <output.sar> [--indexed|--no-index] [--compression store|deflate|zstd] [--compression-level 0..9] [--encrypt aes256-gcm|xchacha20-poly] [--password PASSWORD]
sar extract <archive.sar> <output-dir> [--password PASSWORD]
sar list <archive.sar>
sar verify <archive.sar> [--password PASSWORD]
sar inspect <archive.sar> --json
sar version

# shorthand aliases:
sar -c <input> -f <output.sar>
sar -x -f <archive.sar> -C <dir>
sar -t -f <archive.sar>
sar -v -f <archive.sar>
sar -V

# create compression shortcuts:
sar create <input> <output.sar> -S
sar create <input> <output.sar> -z
sar create <input> <output.sar> -Z -9
```

## Examples

```bash
cargo run -p sar-cli -- create ./input ./archive.sar --no-index
cargo run -p sar-cli -- create ./input ./archive.enc.sar --encrypt aes256-gcm --password secret123
cargo run -p sar-cli -- extract ./archive.enc.sar ./out --password secret123
cargo run -p sar-cli -- verify ./archive.enc.sar --password secret123
cargo run -p sar-cli -- inspect ./archive.sar --json
```

## Limitations

- No built-in signature cryptography yet.
- Asymmetric wrap is modeled via `KeyProvider` hooks only.
- Unsupported/reserved features fail closed with SAR-specific errors.
- Later milestones still need FEC, CDC resolution, delta reconstruction, sparse reconstruction, fragmentation reassembly, and streaming transport.

## CI

GitHub Actions CI lives at `.github/workflows/ci.yml` and runs on pull requests only:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`

See `docs/CONFORMANCE.md` for implemented vs planned scope.
