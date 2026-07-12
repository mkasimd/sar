---
applyTo: "docs/**,README.md,CONTRIBUTING.md,AI_DISCLOSURE.md,test-vectors/README.md"
---

<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR documentation rules

* `specification.md` is authoritative for SAR protocol behavior.
* `docs/CRATE_RESPONSIBILITIES.md` tracks crate ownership.
* `docs/LIBRARY_LAYOUT.md` tracks future shared-library/profile layout.
* `docs/MILESTONES.md` tracks roadmap scope.
* `docs/MACHINE_READABLE_API.json` is the authoritative machine-readable public API inventory.
* `docs/MACHINE_READABLE_API.schema.json` defines the required API inventory structure.
* `docs/API.md` is generated from `docs/MACHINE_READABLE_API.json`; do not edit it by hand.

When public APIs change:

* update `docs/MACHINE_READABLE_API.json`
* keep it valid against `docs/MACHINE_READABLE_API.schema.json`
* run `python tools/check_api_schema.py`
* run `python tools/generate_api_md.py`
* include the regenerated `docs/API.md` in the pull request

Do not add arbitrary fields to `docs/MACHINE_READABLE_API.json`. Follow the schema.

Do not make false Standard Compliance claims.

When APIs move or are removed, update `docs/MACHINE_READABLE_API.json` to describe the current public API surface. Do not preserve stale entries in the API inventory unless they remain public compatibility shims.

Do not create new docs files unless explicitly requested or clearly required.
