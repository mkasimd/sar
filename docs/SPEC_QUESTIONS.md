# Spec Questions / Conservative Choices

1. **Global flags beyond first 32 bits**: currently parsed from the first 4 bytes (required minimum) with raw bytes retained.
2. **NO_INDEX footer-forbidden detection**: no heuristic scan is used; parser treats remaining bytes as data area in NO_INDEX mode.
3. **KMS custom mode handling**: custom range (`0xF0..=0xFF`) returns `SAR_ERR_UNSUPPORTED` unless future app policy enables it.
4. **Reserved CD bytes**: enforced as zero for fail-closed behavior.
5. **TLV processing scope**: milestone-limited parser supports structural parsing and strict reserved/unsupported mapping.
