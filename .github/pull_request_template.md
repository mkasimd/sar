<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Summary

Briefly describe what this PR changes.

## Scope

What milestone or issue does this PR belong to?

Examples:

```text
M12a-audit-cp
public-release-hygiene
docs-only cleanup
bug fix
```

## Type of change

* [ ] Code
* [ ] Tests
* [ ] Documentation
* [ ] Conformance vectors
* [ ] Build/CI/tooling
* [ ] Public API change
* [ ] Wire-format/specification change
* [ ] Security-relevant change

## Crate / area touched

* [ ] `sar-core`
* [ ] `sar-archive`
* [ ] `sar-stream`
* [ ] `sar-transport`
* [ ] `sar-cli`
* [ ] feature crates
* [ ] `docs/`
* [ ] `test-vectors/`
* [ ] other:

## Boundary and compatibility checklist

* [ ] Preserves SAR wire-format compatibility, or explicitly explains the change.
* [ ] Preserves crate responsibility boundaries.
* [ ] Does not add unintended dependencies between crates.
* [ ] Does not weaken fail-closed behavior.
* [ ] Does not weaken authentication, transform ordering, or resource-limit behavior.
* [ ] Does not make unsupported production, compliance, certification, or security-audit claims.
* [ ] If public APIs changed, `docs/MACHINE_READABLE_API.json` was updated, schema-validated, and `docs/API.md` was regenerated.

## Tests / validation

List the commands run.

```bash
cargo fmt --all
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Additional validation, if applicable:

```bash
python -m json.tool docs/MACHINE_READABLE_API.json > /dev/null
python -m json.tool docs/MACHINE_READABLE_API.schema.json > /dev/null
python tools/check_api_schema.py
python tools/generate_api_md.py --check
python -m json.tool test-vectors/manifest.schema.json > /dev/null
find test-vectors -name manifest.json -print0 | xargs -0 -n1 python -m json.tool > /dev/null
```

## AI assistance disclosure

* [ ] No meaningful AI assistance was used.
* [ ] AI assistance was used and is disclosed below.

Tools/models used, if known:

```text
```

How AI was used:

* [ ] implementation draft
* [ ] refactoring
* [ ] tests
* [ ] documentation
* [ ] review assistance
* [ ] prompt/planning assistance
* [ ] other:

Human review performed:

* [ ] I reviewed the generated output.
* [ ] I modified or corrected the generated output where needed.
* [ ] I verified the final behavior with tests or other validation.

## Notes for reviewers

Mention anything reviewers should pay special attention to.

