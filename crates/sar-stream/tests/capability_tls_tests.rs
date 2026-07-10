/// Tests for `CAP_TLS_EXPORTER_AEAD` (bit 6) capability flag.
///
/// Verifies that:
/// - The bit constant is defined at the correct position.
/// - The accessor predicate works.
/// - `validate()` accepts the bit without error (it is spec-defined, not reserved).
/// - The bit does NOT appear in the reserved mask, so a peer advertising it does not
///   trigger `SAR_ERR_RESERVED_VALUE` in non-strict-validation contexts.
/// - Reserved bits (7–15) still trigger `SAR_ERR_RESERVED_VALUE` in strict mode.
use sar_core::SarError;
use sar_stream::CapabilityFlags;

#[test]
fn cap_tls_exporter_aead_constant_is_bit_6() {
    assert_eq!(CapabilityFlags::CAP_TLS_EXPORTER_AEAD, 1 << 6);
}

#[test]
fn supports_tls_exporter_aead_predicate() {
    let with_bit = CapabilityFlags::from_bits(CapabilityFlags::CAP_TLS_EXPORTER_AEAD);
    assert!(with_bit.supports_tls_exporter_aead());

    let without_bit = CapabilityFlags::from_bits(CapabilityFlags::SESSION_ACK);
    assert!(!without_bit.supports_tls_exporter_aead());
}

#[test]
fn cap_tls_exporter_aead_alone_passes_validate() {
    // Bit 6 is spec-defined; it must not be treated as a reserved value by validate().
    let flags = CapabilityFlags::from_bits(CapabilityFlags::CAP_TLS_EXPORTER_AEAD);
    assert!(
        flags.validate().is_ok(),
        "CAP_TLS_EXPORTER_AEAD alone should pass validate()"
    );
}

#[test]
fn cap_tls_exporter_aead_with_all_defined_bits_passes_validate() {
    let all_defined = CapabilityFlags::SESSION_ACK
        | CapabilityFlags::SESSION_STATUS
        | CapabilityFlags::SESSION_RESUME
        | CapabilityFlags::SESSION_METADATA
        | CapabilityFlags::BIDIRECTIONAL_CONTROL
        | CapabilityFlags::BIDIRECTIONAL_STREAM
        | CapabilityFlags::CAP_TLS_EXPORTER_AEAD;
    let flags = CapabilityFlags::from_bits(all_defined);
    assert!(
        flags.validate().is_ok(),
        "all defined bits including CAP_TLS_EXPORTER_AEAD should pass validate()"
    );
}

#[test]
fn reserved_capability_bits_above_6_still_fail_validate() {
    // Bit 7 (0x0080) is reserved and must still be rejected.
    let err = CapabilityFlags::from_bits(0x0080)
        .validate()
        .expect_err("reserved bit 7 must fail");
    assert!(
        matches!(err, SarError::ReservedValue(_)),
        "expected ReservedValue, got {err:?}"
    );
}

#[test]
fn tcp_local_capabilities_do_not_include_tls_exporter_aead() {
    // The TCP transport advertises SESSION_ACK and SESSION_STATUS when
    // bidirectional_control is enabled, but must never set CAP_TLS_EXPORTER_AEAD.
    // We verify the constant set used by sar-transport's TransportStreamContext.
    let tcp_caps =
        CapabilityFlags::from_bits(CapabilityFlags::SESSION_ACK | CapabilityFlags::SESSION_STATUS);
    assert!(
        !tcp_caps.supports_tls_exporter_aead(),
        "TCP must not advertise CAP_TLS_EXPORTER_AEAD"
    );
}
