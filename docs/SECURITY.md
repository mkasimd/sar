# Security Notes (Current Milestones 1–4)

- `unsafe` is forbidden across crates (`#![forbid(unsafe_code)]`).
- Parsing is deterministic and condition-driven from global flags.
- Lengths, offsets, and sizes use checked arithmetic with overflow errors mapped to SAR codes.
- Alignment and padding are validated (TLV and CD-footer boundary rules).
- Parsers fail closed on malformed/reserved/unsupported values.
- Extraction rejects absolute paths and parent-directory traversal (`..`).
- Decompression is bounded using configured per-entry decoded-size limits to mitigate decompression-bomb abuse.

## Bounded allocation

All decoded length/count fields are converted via checked integer conversions before allocation.

Decoded payloads are additionally constrained by `ArchiveReaderOptions.max_decoded_entry_size`; entries declaring larger uncompressed sizes fail with `SAR_ERR_LIMIT_EXCEEDED`.

## Crypto scope in this session

Real crypto operations are intentionally not implemented yet.

KMS is parsed structurally only for format validation and unsupported-feature signaling.

SAR archives must **not** embed raw CEKs, decrypted keys, or trivially reconstructable key material. Key handling remains external for future milestones.

## Transform pipeline scope

Current transform pipeline is intentionally minimal:

`logical payload -> compression/STORE -> encoded payload` on write, and inverse on read.

Crypto/FEC/CDC/delta/fragmentation/sparse/streaming transforms are not implemented yet and should fail closed when encountered.
