<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Spec Questions and Conservative Choices

This file tracks real open specification questions that may affect interoperability.
Resolved items are kept separately to avoid presenting closed work as still open.

## Open questions

### 1) Archive-level repair byte-to-block mapping
- **Area:** Recovery TLV orchestration / archive-level EC.
- **Question:** The spec does not fully define normative byte-offset to FEC block-index mapping for all erasure patterns.
- **Current implementation posture:** Fail-closed for unsupported/non-mappable cases.

### 2) Content hash algorithm signaling
- **Area:** Delta/content-hash verification.
- **Question:** 32-byte hash fields exist, but algorithm signaling is not fully portable in all paths.
- **Current implementation posture:** Parse/preserve metadata; avoid unverifiable cross-implementation claims.

### 3) CDC recipe interoperability details
- **Area:** CDC recipe mode and cross-writer equivalence.
- **Question:** Full normative profile for recipe hash algorithm and portable regeneration assumptions remains incomplete.
- **Current implementation posture:** Structural handling and bounded parsing only; conservative verification claims.

### 4) Extension policy strictness for future assigned IDs
- **Area:** Unknown-but-assigned extensions.
- **Question:** How strict conformance profiles should treat newly assigned IDs without profile updates.
- **Current implementation posture:** Fail-closed unless explicitly supported.

## Resolved (not open)

- **M11a:** LFH metadata API completeness delivered.
- **M11b:** Filesystem metadata encode/decode behavior delivered.
- **M11c/M11c-cp:** crate-boundary cleanup and corrective split delivered.
- **M11d:** high-level archive API ownership moved to `sar-archive`.
- **M11e:** CLI metadata flags/behavior and safe extraction policy gating delivered.
- **M12a:** conformance framework, corrective vector passes, serialized stream transcript vectors, archive audit primitives, and stream transcript validation/recording APIs delivered.

## Future milestone alignment note

* M12b: fuzzing and malicious corpus.
* M12c: documentation/API/security posture hardening.
* M13: security audit and remediation.
* M14: C ABI and Python module.
* M15: packaging and release automation.
* M16: Swift/iOS and Kotlin/Java Android packages.

