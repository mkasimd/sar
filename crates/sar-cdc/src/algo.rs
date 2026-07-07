//! CDC algorithm identifier constants (spec section 8.5, `SAR_L_CDC`).
//!
//! These are stored in the one-byte `CDC Algo ID` field of the Local File
//! Header when `CDC_SUPPORT` (Bit 5) is active globally.

/// LITERAL_MODE: deduplication disabled; payload is literal file data.
pub const CDC_ALGO_LITERAL: u8 = 0x00;

/// RABIN: Rabin Fingerprinting based CDC.  Not required; optional.
pub const CDC_ALGO_RABIN: u8 = 0x01;

/// FASTCDC: Gear-hash based high-speed CDC.  **Required** by the spec.
pub const CDC_ALGO_FASTCDC: u8 = 0x02;

/// BUZHASH: Buzhash based CDC.  Not required; optional.
pub const CDC_ALGO_BUZHASH: u8 = 0x03;

/// First byte in the CUSTOM range (0xF0–0xFF).
pub const CDC_ALGO_CUSTOM_MIN: u8 = 0xF0;

/// Last byte in the CUSTOM range (0xF0–0xFF).
pub const CDC_ALGO_CUSTOM_MAX: u8 = 0xFF;

/// Byte length of a single chunk-hash entry in a Recipe payload.
///
/// The spec states that hash length is "determined by the `DEDUPLICATION`
/// (Bit 29) setting" (section 20.2).  The `Content Hash` field is always
/// 32 bytes (section 6.1, row 18).  We therefore fix the recipe hash size
/// at 32 bytes and document the ambiguity in `docs/SPEC_QUESTIONS.md`.
pub const CDC_RECIPE_HASH_LEN: usize = 32;
