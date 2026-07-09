//! Patch algorithm identifier constants and registry validation
//! (spec section 8.4, `SAR_L_PATCH`).
//!
//! These constants are stored in the one-byte `Patch Algo ID` field of the
//! Local File Header when `HAS_DELTA` (Bit 9) is active globally.

/// STORE_PATCH: the decoded patch payload is the complete reconstructed target
/// logical byte sequence.
///
/// Assigned and **mandatory** per the spec.  Application is implemented:
/// [`apply_store_patch`] validates that the payload length equals the declared
/// `Uncompressed Size` and returns the payload as the reconstructed target.
/// No base read, no copy/insert instruction stream, no external dictionary.
pub const PATCH_ALGO_STORE_PATCH: u8 = 0x00;

/// VCDIFF: Standard Binary Diff (RFC 3284).
///
/// Assigned and **mandatory** per the spec. Application is implemented.
pub const PATCH_ALGO_VCDIFF: u8 = 0x01;

/// BSDIFF: high-efficiency binary patching.
///
/// Assigned, optional. Application is implemented as SAR BSDIFF v1 (`SARBSD01`).
pub const PATCH_ALGO_BSDIFF: u8 = 0x02;

/// ZSTD_PATCH: Zstd utilizing an external dictionary.
///
/// Assigned, **optional**.  Application is **not implemented** in this
/// milestone; the dictionary protocol is not defined by the spec.
pub const PATCH_ALGO_ZSTD_PATCH: u8 = 0x03;

/// First byte of the CUSTOM patch algorithm range (`0xF0–0xFF`).
pub const PATCH_ALGO_CUSTOM_MIN: u8 = 0xF0;

/// Last byte of the CUSTOM patch algorithm range (`0xF0–0xFF`).
pub const PATCH_ALGO_CUSTOM_MAX: u8 = 0xFF;

/// Type-safe representation of a `Patch Algo ID` registry value.
///
/// This enum covers all assigned IDs and both special ranges.  It is
/// constructed by [`validate_patch_algo_id`] after range checking.
///
/// # Application status
///
/// `STORE_PATCH`, `VCDIFF`, and `BSDIFF` are implemented for patch
/// application. `ZSTD_PATCH` remains unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchAlgoId {
    /// `0x00` — STORE_PATCH; assigned, mandatory; application implemented.
    StorePatch,
    /// `0x01` — VCDIFF (RFC 3284); assigned, mandatory; application implemented.
    Vcdiff,
    /// `0x02` — BSDIFF; assigned, optional; application implemented.
    Bsdiff,
    /// `0x03` — ZSTD_PATCH; assigned, optional; application not implemented.
    ZstdPatch,
    /// `0xF0–0xFF` — implementation-defined custom algorithm.
    Custom(u8),
}

impl PatchAlgoId {
    /// Returns the wire byte value for this algorithm ID.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::StorePatch => PATCH_ALGO_STORE_PATCH,
            Self::Vcdiff => PATCH_ALGO_VCDIFF,
            Self::Bsdiff => PATCH_ALGO_BSDIFF,
            Self::ZstdPatch => PATCH_ALGO_ZSTD_PATCH,
            Self::Custom(id) => id,
        }
    }

    /// Human-readable name for display purposes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StorePatch => "STORE_PATCH",
            Self::Vcdiff => "VCDIFF",
            Self::Bsdiff => "BSDIFF",
            Self::ZstdPatch => "ZSTD_PATCH",
            Self::Custom(_) => "CUSTOM",
        }
    }
}

/// Error type used by the patch algorithm registry and patch application.
///
/// Variant names mirror `sar_core::SarError` so that `sar-core` can map them
/// directly without taking a dependency on `sar-delta` for the error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// Valid patch algorithm or feature not implemented by this release.
    Unsupported(&'static str),
    /// Reserved or prohibited algorithm identifier.
    ReservedValue(&'static str),
    /// Patch application failed (e.g., payload length mismatch).
    PatchFailed(&'static str),
    /// Required base object missing or all-zero Delta Base Hash.
    BaseMissing(&'static str),
    /// A configured resource limit was exceeded.
    LimitExceeded(&'static str),
}

impl core::fmt::Display for PatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported(m) => write!(f, "patch unsupported: {m}"),
            Self::ReservedValue(m) => write!(f, "patch reserved value: {m}"),
            Self::PatchFailed(m) => write!(f, "patch failed: {m}"),
            Self::BaseMissing(m) => write!(f, "patch base missing: {m}"),
            Self::LimitExceeded(m) => write!(f, "patch limit exceeded: {m}"),
        }
    }
}

/// Validates a `Patch Algo ID` byte against the spec-defined algorithm
/// registry (spec section 8.4, `SAR_L_PATCH`).
///
/// This function enforces **registry membership** only.  It does **not**
/// indicate whether patch application is available for the returned ID.
///
/// # Registry behavior
///
/// | Range        | Result                                               |
/// |--------------|------------------------------------------------------|
/// | `0x00`       | `Ok(StorePatch)` — assigned, mandatory               |
/// | `0x01`       | `Ok(Vcdiff)` — assigned, mandatory                   |
/// | `0x02`       | `Ok(Bsdiff)` — assigned, optional                    |
/// | `0x03`       | `Ok(ZstdPatch)` — assigned, optional                 |
/// | `0x04–0xEF`  | `Err(ReservedValue)` — reserved by the spec          |
/// | `0xF0–0xFF`  | `Err(Unsupported)` — custom, not negotiated          |
///
/// # Errors
///
/// Returns [`PatchError::ReservedValue`] for reserved IDs (`0x04–0xEF`) and
/// [`PatchError::Unsupported`] for custom IDs (`0xF0–0xFF`).
pub fn validate_patch_algo_id(id: u8) -> Result<PatchAlgoId, PatchError> {
    match id {
        PATCH_ALGO_STORE_PATCH => Ok(PatchAlgoId::StorePatch),
        PATCH_ALGO_VCDIFF => Ok(PatchAlgoId::Vcdiff),
        PATCH_ALGO_BSDIFF => Ok(PatchAlgoId::Bsdiff),
        PATCH_ALGO_ZSTD_PATCH => Ok(PatchAlgoId::ZstdPatch),
        PATCH_ALGO_CUSTOM_MIN..=PATCH_ALGO_CUSTOM_MAX => Err(PatchError::Unsupported(
            "CUSTOM patch algorithm not supported",
        )),
        _ => Err(PatchError::ReservedValue("reserved patch algorithm ID")),
    }
}

/// Returns a short human-readable name for a `Patch Algo ID` byte.
///
/// This is a display-only helper; it does **not** validate the ID.  Unknown
/// or reserved IDs are reported as `"unknown"`.
#[must_use]
pub fn patch_algo_name(id: u8) -> &'static str {
    match id {
        PATCH_ALGO_STORE_PATCH => "STORE_PATCH",
        PATCH_ALGO_VCDIFF => "VCDIFF",
        PATCH_ALGO_BSDIFF => "BSDIFF",
        PATCH_ALGO_ZSTD_PATCH => "ZSTD_PATCH",
        PATCH_ALGO_CUSTOM_MIN..=PATCH_ALGO_CUSTOM_MAX => "custom",
        _ => "unknown",
    }
}

/// Applies `STORE_PATCH` (`0x00`) to `patch_payload`.
///
/// For `STORE_PATCH`, the decoded patch payload **is** the complete
/// reconstructed target logical byte sequence.  No base read is performed.
/// No copy/insert instruction stream exists.  No external dictionary is used.
///
/// # Arguments
///
/// * `patch_payload` — decoded bytes produced by the decompression (and
///   decryption) stage, representing the full target file content.
/// * `expected_len` — the LFH `Uncompressed Size` field.  The caller is
///   responsible for validating this value against any configured resource
///   limits **before** calling this function.
///
/// # Errors
///
/// Returns [`PatchError::PatchFailed`] when
/// `patch_payload.len() as u64 != expected_len`.
///
/// # Notes
///
/// All-zero `Delta Base Hash` is valid for `STORE_PATCH` and means "no base
/// required".  The caller must not pass `Delta Base Hash` to this function;
/// it is opaque metadata and plays no role in the application of this
/// algorithm.
pub fn apply_store_patch(patch_payload: &[u8], expected_len: u64) -> Result<Vec<u8>, PatchError> {
    let actual_len = patch_payload.len() as u64;
    if actual_len != expected_len {
        return Err(PatchError::PatchFailed(
            "STORE_PATCH: decoded payload length does not match LFH Uncompressed Size",
        ));
    }
    Ok(patch_payload.to_vec())
}
