# sar-rust

Production-oriented Rust workspace for **SAR Protocol v1.0** foundations.

## Current MVP (this session)

Implemented milestones:

- **Milestone 1**: SAR error/status registry, global flags model, checked LE parsing/writing primitives, overflow/length/bounds/flag validators.
- **Milestone 2**: parser/writer for Global Header, Local File Header, Central Dictionary, Footer, and metadata TLV blocks (with alignment/padding checks).
- **Milestone 3**: minimal archive reader/writer for **STORE-only** payloads in:
  - sequential `NO_INDEX` mode;
  - minimal indexed mode with Central Dictionary + Footer.
- **Milestone 4**: compression + transform-pipeline foundation:
  - STORE (`0x00`), DEFLATE (`0x01`), ZSTD (`0x02`) implemented;
  - assigned unsupported compression IDs return `SAR_ERR_UNSUPPORTED`;
  - reserved compression IDs return `SAR_ERR_RESERVED_VALUE`;
  - bounded decompression by configured maximum decoded entry size.
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

Placeholder crates compile but intentionally do not implement future milestones.

## CLI

```text
sar create <input> <output.sar> [--indexed|--no-index] [--compression store|deflate|zstd] [--compression-level 0..9]
sar extract <archive.sar> <output-dir>
sar list <archive.sar>
sar verify <archive.sar>
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
cargo run -p sar-cli -- list ./archive.sar
cargo run -p sar-cli -- extract ./archive.sar ./out
cargo run -p sar-cli -- verify ./archive.sar
cargo run -p sar-cli -- inspect ./archive.sar --json
```

## Limitations (intentional for Milestones 1–3)

- No encryption/decryption, KMS execution, signatures, FEC recovery, CDC, delta reconstruction, sparse reconstruction, fragmentation reassembly, stream transport.
- Unsupported/reserved features fail closed with SAR-specific errors.

## CI

GitHub Actions CI lives at `.github/workflows/ci.yml` and runs on pull requests only:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`

See `docs/CONFORMANCE.md` for implemented vs planned scope.
