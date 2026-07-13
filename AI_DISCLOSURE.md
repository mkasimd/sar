<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# AI Disclosure

This repository was developed with substantial AI assistance.

This document provides project-level transparency about how AI tools were used. It is not a certification, warranty, security audit, or line-by-line provenance record.

## Summary

SAR was developed through an AI-assisted engineering workflow.

AI agents were used to help with implementation drafts, refactoring suggestions, test generation, documentation updates, conformance-vector scaffolding, review prompts, and consistency checks.

The human maintainer retained responsibility for protocol design, architectural constraints, security invariants, milestone scope, review decisions, merge decisions, licensing decisions, and release decisions.

AI-generated or AI-assisted output is not treated as automatically correct. It must be reviewed, tested, and accepted like any other contribution.

## Why AI was used

AI assistance was used to accelerate development and review of a large, structured Rust codebase with many interacting concerns, including binary parsing, archive read/write behavior, transform orchestration, streaming/session semantics, conformance vectors, and documentation.

The project also served as an experiment in AI-assisted engineering: using AI agents for substantial implementation work while keeping human control over specification intent, architecture, security boundaries, and acceptance criteria.

## AI contribution

AI tools contributed to the project in broad areas including:

* Rust implementation drafts
* refactoring suggestions
* test and regression-test scaffolding
* conformance-vector scaffolding
* documentation drafts and rewrites
* API and milestone inventory updates
* review assistance and consistency checks
* pull request descriptions and review prompts

AI assistance was used as an engineering aid, not as final authority.

## Human contribution

The human maintainer provided the project's controlling direction and final accountability.

Human contributions included:

* SAR protocol goals and design constraints
* interpretation of specification intent
* crate responsibility boundaries
* security and fail-closed requirements
* milestone planning and sequencing
* decisions about what belongs in each crate
* decisions about what remains future work
* review and acceptance of AI-assisted changes
* licensing and public-release decisions

The human maintainer did not necessarily hand-write every line of code. The human role was primarily architectural, editorial, review-oriented, and acceptance-oriented.

## Models and tools used

The project used AI coding and reasoning tools including:

* ChatGPT, used for architectural review, prompt drafting, documentation drafting, Rust/code explanation, review planning, and public-release preparation.
* GitHub Copilot, used for implementation assistance, refactoring, tests, documentation edits, and milestone-specific code changes.

Exact model versions may vary over time depending on the services used.

## Disclosure limitations

This is a project-level disclosure. It does not provide perfect provenance for every line, commit, generated fragment, or review comment.

It does not imply that any AI model endorses, understands, verifies, or validates SAR.

It does not imply that the project is production-ready, secure, audited, certified, or standards-compliant.

The authoritative project status remains in:

* `README.md`
* `docs/MILESTONES.md`
* `docs/CONFORMANCE.md`
* `docs/SECURITY.md`
