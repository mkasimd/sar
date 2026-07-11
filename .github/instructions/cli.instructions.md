---
applyTo: "crates/sar-cli/**"
---

# SAR CLI rules

* CLI behavior must use library APIs rather than duplicating protocol logic.
* Do not add filesystem metadata restoration unless the task explicitly targets that milestone.
* Extraction must reject unsafe paths by default.
* Symlink extraction must be opt-in or policy-gated.
* UID/GID restoration and setuid/setgid/sticky restoration must be disabled by default.
* Directory permissions should be applied after children where applicable.
* CLI changes must not weaken side-effect-free library parsing.
