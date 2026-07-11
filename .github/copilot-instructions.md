# SAR repository instructions

This repository is the Rust reference implementation for SAR Protocol v1.0.

## Authority

* `specification.md` is authoritative for SAR wire format, validation rules, transform ordering, streaming/session semantics, and transport bindings.
* `docs/API.md` and `docs/MACHINE_READABLE_API.json` track the current public API.
* `docs/CRATE_RESPONSIBILITIES.md` tracks crate ownership.
* `docs/LIBRARY_LAYOUT.md` tracks future shared-library/profile layout.
* `docs/MILESTONES.md` tracks roadmap scope.

If docs conflict with `specification.md` on protocol behavior, follow `specification.md` and update stale docs.

## Global rules

* Preserve SAR wire format unless the task explicitly changes the spec.
* Fail closed for malformed, reserved, unsupported, overflowing, or ambiguous input.
* Use stable Rust and avoid `unsafe`.
* Use checked arithmetic and checked numeric conversions.
* Enforce resource limits before allocation or expansion.
* Keep library parsing, metadata decoding, reading, listing, and verification side-effect-free.
* Do not expose raw keys, exporter-derived material, or AEAD internals through APIs, logs, debug output, docs, or errors.
* Update relevant docs/API inventory when public APIs, crate ownership, or behavior change.

Prefer targeted instructions in `.github/instructions/` for crate-specific work.
