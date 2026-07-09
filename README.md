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
- **Milestone 9a — Content-Defined Chunking (CDC)**: CDC metadata parsing/writing/validation, FASTCDC algorithm, resource limits, CLI support
  - `CDC_SUPPORT` global flag (Bit 5) activates CDC: `cdc_algo_id` parsed from every LFH when active; validated against algorithm registry
  - Supported CDC algorithms: `LITERAL_MODE (0x00)` and `FASTCDC (0x02)`
  - FASTCDC: deterministic two-level gear-hash chunking with SHA-256 per-chunk hashes; no zero-length chunks; no unbounded allocation; **treated as implementation-defined/local-profile until the spec fully defines or encodes normative parameters**
  - `0x31` remains `DATA_HASH/BLAKE3`, **not** CDC metadata
  - CDC metadata registry: `0x40` = `CDC_MAP`, `0x41` = inert `CDC_EXT_PROVIDER`, `0x42–0x4E` = reserved, `0x4F` = `CDC_CUSTOM`
  - `CDC_MAP` uses a **v1 header format** (16 bytes: `Map_Version`, `Hash_Algorithm_ID`, `Flags`, `Record_Count`, `Record_Size`, `Reserved`) followed by 48-byte records (`Hash` 32 B + `Partition_ID` u32 4 B + `Absolute_Offset` u64 8 B + `Compressed_Size` u32 4 B)
  - `CDC_MAP` is **self-describing** via `Hash_Algorithm_ID` in the header; BLAKE3 (`0x31`) is required, SHA-256 (`0x30`) is supported; parsers MUST NOT hard-code an unnamed hash algorithm
  - FASTCDC controls chunk **boundaries**; `Hash_Algorithm_ID` controls how CDC_MAP record hashes are computed — these are independent fields
  - `CDC_MAP` parse/write/hash-verification available; readers validate stored metadata directly and do **not** need to regenerate FASTCDC boundaries to parse or use `CDC_MAP`; CDC_MAP hash verification (`verify_cdc_map_record_hash`) verifies stored chunk hashes against archive bytes and is **not** FASTCDC boundary-regeneration verification
  - `CDC_EXT_PROVIDER` is parsed as UTF-8 URI metadata only; external provider/CAS recipe resolution remains unsupported unless the provider protocol, hash algorithm, record layout, and CDC transformation domain are normatively specified
  - Recipe Mode: `validate_recipe_payload` and `recipe_hashes` for ordered 32-byte chunk hash lists; recipe-hash verification is unavailable because the spec does not yet fully define the recipe-hash algorithm and portable external resolution contract
  - `ResourceLimits`: `max_cdc_chunk_count` and `max_cdc_metadata_bytes` fields added; all CDC parse paths are bounded
  - `EntryMetadata.cdc_algo_id` exposes CDC algorithm per entry; `VerificationReport.cdc_support` and `cdc_entry_count` added
  - `inspect --json` includes `cdc_support`, `cdc_metadata_tlvs`, and per-entry `cdc_algo_id`; `verify --cdc` performs structural CDC validation only and does **not** claim boundary regeneration or external-CAS recipe verification
  - CDC does not bypass AEAD authentication, sparse reconstruction, fragment reassembly, or resource limits
  - Delta encoding (VCDIFF, BSDIFF) is **not** implemented in M9a
- **Milestone 9b — Delta Metadata, Patch Algorithm Registry, STORE_PATCH, BSDIFF, and VCDIFF Application**: complete delta patch pipeline
  - `HAS_DELTA` global flag (Bit 9) activates delta fields: `Patch Algo ID` (1 B) and `Delta Base Hash` (32 B) parsed from every LFH when active
  - SAR patch algorithm registry: `0x00` = `STORE_PATCH` (implemented), `0x01` = `VCDIFF` (implemented), `0x02` = `BSDIFF` (implemented), `0x03` = `ZSTD_PATCH` (blocked — protocol not specified), `0x04–0xEF` = reserved → `SAR_ERR_RESERVED_VALUE`, `0xF0–0xFF` = custom → `SAR_ERR_UNSUPPORTED`
  - `EntryMetadata.patch_algo_id` exposes raw algorithm byte per entry; `EntryMetadata.delta_base_hash` exposes 32-byte opaque hash
  - `Delta Base Hash` is preserved as opaque bytes; **no hash algorithm is assumed** (BLAKE3, SHA-256, etc. are NOT guessed); no verification is performed
  - `inspect --json` includes `has_delta` at archive level; per-entry `patch_algo_id`, `delta_base_hash` (hex), and `patch_algorithm` name
  - **`STORE_PATCH` (`0x00`) application**: decoded patch payload is the complete reconstructed target; no base reads; length must equal LFH `Uncompressed Size`; `SAR_ERR_PATCH_FAILED` returned on mismatch
  - **`BSDIFF` (`0x02`) application** (SAR BSDIFF v1): magic `SARBSD01`, uncompressed Control/Diff/Extra blocks in decoded patch payload; explicit base bytes required via `ArchiveReaderOptions.delta_base`; base reads beyond end use `0x00`
  - **`VCDIFF` (`0x01`) application** (RFC 3284): standard header/window/instruction decoding; VCD_SOURCE and VCD_TARGET windows; ADD/COPY/RUN instructions; explicit base bytes required via `ArchiveReaderOptions.delta_base`
  - `ArchiveReaderOptions.delta_base: Option<Vec<u8>>` — caller supplies base bytes explicitly; **no automatic discovery, no network access, no CAS access**
  - All-zero `Delta Base Hash` with BSDIFF or VCDIFF → `SAR_ERR_BASE_MISSING`; missing `delta_base` → `SAR_ERR_BASE_MISSING`
  - All-zero `Delta Base Hash` accepted for `STORE_PATCH` (no base required)
  - Legacy `BSDIFF40` decode support is not implemented in this profile; `BSDIFF40` magic is rejected as `SAR_ERR_PATCH_FAILED`
  - `LOSS_TOLERANT` does not suppress `SAR_ERR_PATCH_FAILED`
  - BSDIFF/VCDIFF `ResourceLimits`: `max_bsdiff_control_bytes`, `max_bsdiff_diff_bytes`, `max_bsdiff_extra_bytes`, `max_bsdiff_control_triples`, `max_vcdiff_window_count`, `max_vcdiff_instruction_count`, `max_vcdiff_output_size`
- **Stage 2 security hardening**: unified `ResourceLimits` model and bounded parsing
  - `ArchiveReaderOptions` carries `ResourceLimits` for archive size, LFH, TLV, Central Dictionary, sparse, fragment, FEC, and repair limits
  - configured limits are enforced before dangerous allocation and return `SAR_ERR_LIMIT_EXCEEDED`
  - checked arithmetic and checked conversions now gate LFH, TLV, sparse, fragment, and recovery parsing paths
- **Stage 3 pipeline memory accounting and expansion-bomb protection**
  - in-memory reconstruction APIs enforce configured limits before allocating any reconstruction buffer
  - **sparse expansion-bomb protection**: `tiny stored payload + huge Uncompressed Size + sparse extent near end` is rejected with `SAR_ERR_LIMIT_EXCEEDED` before any large allocation; this applies to non-fragmented and fragmented sparse entries alike
  - decompression bounded by `max_decoded_entry_size` to prevent decompression-bomb attacks
  - fragment group span, loss-tolerant gap filling, and FEC/recovery working sets are all bounded before allocation
  - runtime memory budget not implemented by design; configured `ResourceLimits` are the deterministic protection
- **Stage 4 CLI and file extraction resource-safety**
  - `sar extract`, `sar verify`, and `sar repair` now accept shared `ResourceLimits` override flags and use safe defaults when not overridden
  - CLI sparse extraction writes sparse files with bounded scatter-gather output to temp files instead of reconstructing the apparent sparse size in memory
  - fragmented sparse extraction keeps fragment-span checks and sparse-output checks under the same `ResourceLimits` model
  - CLI repair pre-checks archive size, enforces repair working-set limits, and never finalizes output after resource-limit failure
  - CLI resource-limit failures are reported clearly as `resource-limit error (SAR_ERR_LIMIT_EXCEEDED)`

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
    [--max-archive-size BYTES]
    [--max-decoded-entry-size BYTES]
    [--max-in-memory-buffer BYTES]
    [--max-total-pipeline-memory BYTES]
    [--max-sparse-map-bytes BYTES]
    [--max-sparse-descriptors COUNT]
    [--max-fragment-count COUNT]
    [--max-fragment-group-span BYTES]
    [--max-loss-tolerant-gap BYTES]

sar list <archive.sar>
sar verify <archive.sar> [--password PASSWORD] [--recovery]
    [--max-archive-size BYTES]
    [--max-decoded-entry-size BYTES]
    [--max-in-memory-buffer BYTES]
    [--max-total-pipeline-memory BYTES]
    [--max-sparse-map-bytes BYTES]
    [--max-sparse-descriptors COUNT]
    [--max-fragment-count COUNT]
    [--max-fragment-group-span BYTES]
    [--max-loss-tolerant-gap BYTES]
sar inspect <archive.sar> [--json]
sar repair <archive.sar> <output.sar> --fec [--erasures erasures.json]
    [--max-archive-size BYTES]
    [--max-decoded-entry-size BYTES]
    [--max-in-memory-buffer BYTES]
    [--max-total-pipeline-memory BYTES]
    [--max-sparse-map-bytes BYTES]
    [--max-sparse-descriptors COUNT]
    [--max-fragment-count COUNT]
    [--max-fragment-group-span BYTES]
    [--max-loss-tolerant-gap BYTES]
    [--max-recovery-protected-range BYTES]
    [--max-repair-working-set BYTES]
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
- `extract` writes sparse outputs via temp files plus scatter-gather seeks, so sparse holes are not materialized as a full in-memory buffer before writing.
- `verify --recovery` additionally validates fragmentation, sparse, and Data Recovery TLV metadata.
- `repair` applies archive-level XOR/RS erasure repair using explicit erasure positions from `--erasures`.
- `extract`, `verify`, and `repair` use default `ResourceLimits` safety caps unless CLI overrides are supplied. Relevant defaults include `max_decoded_entry_size = 1 GiB`, `max_in_memory_buffer = 1 GiB`, `max_fragment_group_span = 1 GiB`, `max_archive_size = 16 GiB`, and `max_repair_working_set = 2 GiB`.
- sparse apparent-size failures and repair working-set failures return `SAR_ERR_LIMIT_EXCEEDED` and do not leave final output files behind
- `list` and `inspect` do **not** currently accept passwords, so encrypted archives are not fully supported by those commands.

## Validation

Full-workspace validation commands:

```bash
cargo fmt
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

See `docs/API.md`, `docs/CONFORMANCE.md`, `docs/SECURITY.md`, and `docs/MACHINE_READABLE_API.json` for the current audited API surface and limitations.
