---
applyTo: "crates/sar-transport/**"
---

<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR transport rules

* Preserve M10 TCP/QUIC behavior unless explicitly asked to change it.
* Additional QUIC control streams are LFH-direct: no `SAR!`, no Global Header, no `CTL!`.
* `CTL!` must remain rejected.
* TLS_EXPORTER SAR-AEAD is selected by KMS Mode `0x04`, not by capability flags.
* SESSION_INIT is the mandatory plaintext bootstrap for TLS_EXPORTER mode.
* Post-binding entries must be encrypted/authenticated.
* AAD must include the associated Global Header bytes and physically present LFH bytes as required.
* Authentication failures must be generic and must not expose plaintext.
