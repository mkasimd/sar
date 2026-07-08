//! Patch algorithm identifier constants and registry validation
//! (spec section 8.4, `SAR_L_PATCH`).
//!
//! These constants are stored in the one-byte `Patch Algo ID` field of the
//! Local File Header when `HAS_DELTA` (Bit 9) is active globally.

/// STORE_PATCH: direct binary delta application.
///
/// Assigned and **mandatory** per the spec.  Application is **not implemented**
/// in this milestone; the wire format is underspecified.  Parsing and
/// preservation of the algorithm ID byte are fully supported.
pub const PATCH_ALGO_STORE_PATCH: u8 = 0x00;

/// VCDIFF: Standard Binary Diff (RFC 3284).
///
/// Assigned and **mandatory** per the spec.  Application is **not implemented**
/// in this milestone.  Parsing and preservation of the algorithm ID byte are
/// fully supported.
pub const PATCH_ALGO_VCDIFF: u8 = 0x01;

/// BSDIFF: high-efficiency binary patching.
///
/// Assigned, **optional**.  Application is **not implemented** in this
/// milestone; the specific wire format version is not cited by the spec.
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
/// None of the assigned algorithms are implemented for patch *application* in
/// this milestone.  The enum exists for registry validation and metadata
/// exposure only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchAlgoId {
    /// `0x00` — STORE_PATCH; assigned, mandatory; application not implemented.
    StorePatch,
    /// `0x01` — VCDIFF (RFC 3284); assigned, mandatory; application not implemented.
    Vcdiff,
    /// `0x02` — BSDIFF; assigned, optional; application not implemented.
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

/// Error type used by the patch algorithm registry.
///
/// Variant names mirror `sar_core::SarError` so that `sar-core` can map them
/// directly without taking a dependency on `sar-delta` for the error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// Valid patch algorithm or feature not implemented by this release.
    Unsupported(&'static str),
    /// Reserved or prohibited algorithm identifier.
    ReservedValue(&'static str),
}

impl core::fmt::Display for PatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported(m) => write!(f, "patch unsupported: {m}"),
            Self::ReservedValue(m) => write!(f, "patch reserved value: {m}"),
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
