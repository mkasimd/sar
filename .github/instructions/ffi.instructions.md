---
applyTo: "ffi/**,bindings/**"
---

# SAR FFI and binding rules

* Do not expose Rust `String`, `Vec`, `Option<T>`, references, slices, or lifetime-bearing structs directly across C ABI.
* Use opaque handles or C-compatible owned mirror structs.
* Provide explicit destructor/free functions for heap-owned results.
* Define ownership, lifetime, allocator, and thread-safety rules.
* No Rust panic may cross FFI boundaries.
* Do not expose raw keys, exporter-derived material, or AEAD internals.
* Python/PyO3 wrappers must release Rust-owned resources automatically when dropped.
* Long-lived readers/writers/streams should provide explicit close/release APIs or context-manager support.
