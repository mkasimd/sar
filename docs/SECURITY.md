# Security Notes (Current Milestones 1–3)

- `unsafe` is forbidden across crates (`#![forbid(unsafe_code)]`).
- Parsing is deterministic and condition-driven from global flags.
- Lengths, offsets, and sizes use checked arithmetic with overflow errors mapped to SAR codes.
- Alignment and padding are validated (TLV and CD-footer boundary rules).
- Parsers fail closed on malformed/reserved/unsupported values.
- Extraction rejects absolute paths and parent-directory traversal (`..`).

## Bounded allocation

All decoded length/count fields are converted via checked integer conversions before allocation.

## Crypto scope in this session

Real crypto operations are intentionally not implemented yet.

KMS is parsed structurally only for format validation and unsupported-feature signaling.

SAR archives must **not** embed raw CEKs, decrypted keys, or trivially reconstructable key material. Key handling remains external for future milestones.
