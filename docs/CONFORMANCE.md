# Conformance Statement

## Implemented now

- Global header parsing/writing with required fields and flag validation.
- Partition descriptor structural parsing/writing.
- KMS structural parsing sufficient for validation/erroring; encrypted payload processing is unsupported.
- LFH deterministic parsing/writing based on global flags.
- Header-size and bounds validation logic.
- Central Dictionary + Footer parsing/writing for minimal indexed archives.
- TLV parsing/writing with 8-byte alignment and zero-padding checks.
- STORE-only archive reader/writer for `NO_INDEX` and indexed modes.
- CLI MVP commands and shorthand aliases.

## Partial

- Signed-archive anchor validation checks (`SIGNED` requires metadata and `DATA_HASH` presence during verify), but no signature cryptography.
- CD metadata TLV parsing for accepted implemented type ranges only.

## Unsupported (explicitly rejected)

- Compression beyond STORE.
- Encrypted payload decoding and cryptographic key handling.
- FEC decode/repair, CDC resolution, delta patch execution.
- Sparse reconstruction, fragmentation reassembly, lossy modes.
- Streaming session protocol and transport layers.

## Planned

Milestones 4–11 per roadmap in `specification.md`.
