# sar-rust

Rust workspace for the **SAR Protocol v1.0** reference implementation.

## Implemented milestones

- **Milestones 1–3**: archive format parsing/writing, indexed and `NO_INDEX` archive flows, TLV support, status/error mapping
- **Milestone 4**: compression registry and transform-pipeline foundation
  - STORE (`0x00`)
  - DEFLATE (`0x01`)
  - ZSTD (`0x02`)
- **Milestone 5**: crypto + KMS foundation
  - SHA-256 and BLAKE3 hashing
  - AES-256-GCM and XChaCha20-Poly1305 entry encryption
  - PBKDF2-HMAC-SHA256 and Argon2id KMS parsing/derivation
  - `KeyProvider` abstraction for password/external key resolution
- **Milestones 6–7**: Selective FEC and codec implementation
  - XOR FEC (`0x14`)
  - Reed-Solomon FEC (`0x11`)
  - FEC validation and CLI create/inspect/verify/extract coverage for current FEC archives
- **Milestone 8**: sparse files, fragmentation reassembly, loss-tolerant semantics, archive-level repair
  - Sparse file map parsing, writing, validation, and scatter-gather reconstruction
  - Sparse reconstruction uses LFH `Uncompressed Size` as the final logical file size; trailing holes beyond the last extent are filled with `0x00`
  - Empty Areas (`Name Length == 0`, `IS_FRAGMENT == 0`) excluded from logical file output
  - Fragment group reassembly with `FragmentDescriptor`-based absolute-offset placement
  - LOSS_TOLERANT degraded reconstruction (zero-fill gaps, `WarnIncomplete`); AEAD auth not bypassed
  - Archive-level Data Recovery TLV inspection (`inspect_recovery_metadata`)
  - Archive-level repair planning and XOR/RS erasure repair (`plan_archive_repair`, `repair_archive`)
  - CLI `repair` command with temp-file safety pattern
  - CLI `verify --recovery` for recovery metadata validation
  - CLI `extract --allow-lossy` for archives with LOSS_TOLERANT entries
  - Enhanced `inspect --json` output with fragment, sparse, and recovery metadata
- **Milestone 8 final pass**: sparse+fragment, writer sparse, CRC32 verification
  - Sparse reconstruction across fragment groups: Sparse Map must appear only on fragment index 0 and applies to the entire reassembled group; non-zero index returns `SAR_ERR_INVALID_MAP`
  - `ArchiveWriter::write_sparse_entry` — writer-side sparse creation with validation; round-trips through reader
  - `ArchiveWriterOptions::sparse` field — enables `SPARSE_FILES` global flag
  - CRC32 verification in `read_all_logical_files` — verified over fully reconstructed bytes including sparse holes

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
fuzz/
```

Placeholder crates compile but intentionally expose only a `NotImplemented` marker until later milestones.

## CLI

Current command surface:

```text
sar create <input> <output.sar> [--indexed|--no-index]
    [--compression store|deflate|zstd | -S | -z | -Z]
    [--compression-level 0..9 | -0..-9]
    [--encrypt aes256-gcm|xchacha20-poly] [--password PASSWORD]
    [--fec xor|rs]

sar extract <archive.sar> <output-dir> [--password PASSWORD] [--allow-lossy]
sar list <archive.sar>
sar verify <archive.sar> [--password PASSWORD] [--recovery]
sar inspect <archive.sar> [--json]
sar repair <archive.sar> <output.sar> --fec [--erasures erasures.json]
sar version

# shorthand aliases
sar -c <input> -f <output.sar>
sar -x -f <archive.sar> -C <dir>
sar -t -f <archive.sar>
sar -v -f <archive.sar>
sar -V
```

Notes:

- `create` supports per-entry Selective FEC via `--fec xor|rs`.
- `extract` and `verify` can load passwords from `--password`, `SAR_PASSWORD`, or an interactive prompt.
- `extract --allow-lossy` permits archives with LOSS_TOLERANT entries (warns if present).
- `verify --recovery` additionally validates fragmentation, sparse, and Data Recovery TLV metadata.
- `repair` applies archive-level XOR/RS erasure repair using explicit erasure positions from `--erasures`.
- `list` and `inspect` do **not** currently accept passwords, so encrypted archives are not fully supported by those commands.

## Validation

Full-workspace validation commands:

```bash
cargo fmt
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

See `docs/API.md`, `docs/CONFORMANCE.md`, `docs/SECURITY.md`, and `docs/MACHINE_READABLE_API.json` for the current audited API surface and limitations.
