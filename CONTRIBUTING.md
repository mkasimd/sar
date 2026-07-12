<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Contributing to SAR

Thank you for your interest in contributing to SAR.

SAR is an experimental archive, replication, recovery, and streaming container format with a Rust reference implementation. The project is under active development and is not yet a stable production release.

This document explains contribution process and review expectations. It does not replace the project's authoritative design and status documents.

## Authoritative project documents

Before making substantial changes, consult the documents that define the relevant area:

* `specification.md` - SAR Protocol v1.0 wire-format and protocol behavior
* `docs/CRATE_RESPONSIBILITIES.md` - crate ownership and architectural boundaries
* `docs/API.md` - current public API inventory
* `docs/MACHINE_READABLE_API.json` - machine-readable public API inventory
* `docs/CONFORMANCE.md` - conformance status and vector expectations
* `docs/SECURITY.md` - security posture and constraints
* `docs/MILESTONES.md` - milestone roadmap and implementation status
* `docs/LIBRARY_LAYOUT.md` - intended future library/profile/binding layout
* `AI_DISCLOSURE.md` - project-level AI-assisted development disclosure

If this file appears to conflict with one of those documents, treat the more specific authoritative document as controlling and update whichever file is stale.

## Project status

SAR is pre-stable.

Public APIs, packaging, conformance profiles, fuzzing, security audit, and foreign-language bindings are still being developed. Contributors should avoid presenting the implementation as production-ready, independently audited, certified, or fully ecosystem-proven.

The protocol target is **SAR Protocol v1.0**, but the Rust implementation should still be treated as experimental unless the project documentation explicitly says otherwise.

## Contribution scope

Good contributions include:

* bug fixes
* tests and regression tests
* conformance-vector improvements
* documentation corrections
* security-hardening improvements
* crate-boundary cleanups
* parser/resource-limit hardening
* API inventory corrections
* CI/tooling improvements
* issue reproduction cases

Larger feature work should be discussed before implementation, especially if it affects:

* SAR wire format
* public Rust API
* crate dependencies
* archive/security behavior
* streaming/session semantics
* transport bindings
* conformance profiles
* test-vector format
* CLI behavior
* future FFI or binding layout

## Milestone discipline

SAR development is milestone-driven.

When opening a pull request, identify the milestone, issue, or cleanup category the work belongs to.

Examples:

```text
M12a-audit-cp
public-release-hygiene
docs-only cleanup
bug fix
```

Do not start unrelated future milestone work in the same pull request.

If a change reveals that a future milestone needs adjustment, document that separately rather than implementing it opportunistically.

## Architectural expectations

SAR has strict crate and responsibility boundaries. Contributors should preserve those boundaries and avoid changes that blur ownership between wire-format code, archive/container logic, stream/session logic, transport code, feature crates, CLI behavior, and future bindings.

The authoritative source for crate ownership is:

* `docs/CRATE_RESPONSIBILITIES.md`

If a change intentionally modifies crate responsibility boundaries, update the authoritative document and explain the reason in the pull request.

## Wire-format compatibility

The SAR v1.0 wire format must not change accidentally.

Changes that affect encoded bytes, parser expectations, flags, field layout, algorithm identifiers, TLV layout, transform ordering, status/error mapping, or conformance-vector semantics require explicit review.

The authoritative source for wire-format behavior is:

* `specification.md`

If a pull request changes wire-format behavior, say so clearly in the PR description.

If the change is not intended to modify the wire format, include tests or reasoning showing compatibility is preserved.

## Security expectations

SAR is designed around bounded parsing, explicit validation, deterministic behavior, and fail-closed handling of malformed or unsupported input.

Do not weaken security-relevant behavior casually. This includes authentication handling, transform ordering, resource limits, malformed-input rejection, safe extraction policy, and crate-boundary separation.

The authoritative security posture is documented in:

* `docs/SECURITY.md`

Do not make production-readiness, certification, compliance, or independent-audit claims unless the project documentation explicitly supports them.

## Testing expectations

Pull requests should include tests appropriate to their risk.

Examples:

* parser changes need malformed/truncated/reserved-value tests
* transform changes need round-trip and negative tests
* crypto changes need authentication-failure tests
* archive-reader changes need indexed and `NO_INDEX` coverage where relevant
* stream/session changes need state-machine and invalid-sequence tests
* documentation/API changes should keep API inventory files accurate if public API changes
* conformance-vector changes should update manifests and manifest tests where needed

Do not rely only on "it compiles."

## Recommended validation

For most changes, run:

```bash
cargo fmt --all
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

For documentation, API inventory, or conformance-vector changes, also validate JSON files where practical:

```bash
python -m json.tool docs/MACHINE_READABLE_API.json > /dev/null
python -m json.tool test-vectors/manifest.schema.json > /dev/null
find test-vectors -name manifest.json -print0 | xargs -0 -n1 python -m json.tool > /dev/null
```

Optional checks, depending on local tooling:

```bash
cargo audit
cargo deny check
```

If you cannot run a validation step, say so in the pull request.

## Documentation expectations

Documentation changes should be accurate, conservative, and consistent with the authoritative project documents.

Avoid duplicating detailed rules from other files unless a short summary is needed for orientation. Prefer linking to the authoritative document.

When updating public API behavior, check whether these files need updates:

* `docs/API.md`
* `docs/MACHINE_READABLE_API.json`
* `README.md`

When changing conformance behavior, check:

* `docs/CONFORMANCE.md`
* `test-vectors/README.md`

When changing milestone status, check:

* `docs/MILESTONES.md`

When changing crate ownership or architecture, check:

* `docs/CRATE_RESPONSIBILITIES.md`
* `docs/LIBRARY_LAYOUT.md`

## Conformance vectors

Conformance vectors live under `test-vectors/`.

Vector changes should preserve manifest validity, clear expected status, and the distinction between valid, invalid, deferred, and profile-specific cases.

The authoritative conformance documentation is:

* `docs/CONFORMANCE.md`
* `test-vectors/README.md`
* `test-vectors/manifest.schema.json`

Binary fixture changes should be reviewed carefully. Avoid regenerating unrelated fixtures.

## Public API changes

Public Rust API changes are allowed while the implementation remains pre-stable, but they must be intentional.

If a pull request changes public API:

* describe the change
* explain why it is needed
* update API documentation and machine-readable inventory where applicable
* update README examples if affected
* update tests

The authoritative API inventory is:

* `docs/API.md`
* `docs/MACHINE_READABLE_API.json`

## AI-assisted contributions

AI-assisted contributions are welcome, but contributors remain responsible for the submitted change.

If AI tools materially contributed to a pull request, disclose that in the pull request description.

A useful disclosure includes:

* which tools or models were used, if known
* whether AI was used for implementation, tests, documentation, review, or refactoring
* whether the generated output was reviewed and modified by the contributor

Contributors should not submit unreviewed AI-generated code.

AI-assisted changes must meet the same standards as any other contribution.

See `AI_DISCLOSURE.md` for the project-level AI disclosure.

## Pull request checklist

Before opening a pull request, check:

* [ ] The change has a clear scope.
* [ ] The relevant milestone, issue, or cleanup category is identified.
* [ ] Wire-format changes are explicit, or compatibility is preserved.
* [ ] Crate responsibility boundaries are preserved or intentionally updated.
* [ ] Security-relevant behavior is preserved or intentionally updated.
* [ ] Tests were added or updated where appropriate.
* [ ] Documentation/API inventory was updated where appropriate.
* [ ] AI assistance was disclosed if materially used.
* [ ] Validation commands were run, or skipped steps were explained.

## Commit and PR style

Prefer focused pull requests.

Avoid mixing unrelated changes such as:

* behavior changes
* vector regeneration
* formatting churn
* public API redesign
* documentation rewrites
* milestone changes

in a single PR unless they are directly connected.

Use descriptive PR titles, for example:

```text
M12a-audit-cp: add archive audit primitives
docs: clarify archive vs stream responsibilities
sar-archive: reject malformed sparse metadata in audit mode
test-vectors: add invalid recovery TLV fixtures
```

## Licensing

By contributing, you agree that your contribution is provided under the applicable license for the files you modify.

This repository is multi-licensed:

* source code, tests, tools, conformance manifests, examples, and implementation documentation are licensed under Apache-2.0
* `specification.md` is licensed under CC-BY-4.0

See:

* `LICENSES/Apache-2.0.txt`
* `LICENSES/CC-BY-4.0.txt`

Do not copy code or documentation from sources with incompatible licenses.

## Reporting security issues

Do not open public issues for vulnerabilities or suspected vulnerabilities unless the repository's security policy explicitly instructs you to do so.

See `docs/SECURITY.md` for the current security posture and reporting guidance.

## Maintainer review

Maintainers may ask for:

* narrower scope
* additional tests
* documentation updates
* API inventory updates
* conformance-vector updates
* security clarification
* crate-boundary cleanup
* removal of unsupported claims

This is expected. SAR is intentionally strict about architecture, validation behavior, and public claims.

