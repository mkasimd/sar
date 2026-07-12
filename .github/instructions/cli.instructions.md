---
applyTo: "crates/sar-cli/**"
---

<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR CLI rules

* CLI behavior must use library APIs rather than duplicating protocol logic.
* Do not add or broaden filesystem metadata restoration without explicit policy gates.
* Metadata restoration must remain opt-in where applicable.
* Extraction must reject unsafe paths by default.
* Symlink extraction must be opt-in or policy-gated.
* UID/GID restoration and setuid/setgid/sticky restoration must be disabled by default.
* Directory permissions should be applied after children where applicable.
* CLI changes must not weaken side-effect-free library parsing.
