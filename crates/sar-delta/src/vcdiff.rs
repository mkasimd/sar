//! VCDIFF patch application per RFC 3284.
//!
//! Supports:
//! * Standard VCDIFF header parsing (magic, hdr_indicator).
//! * VCD_SOURCE windows — copy from supplied base bytes.
//! * VCD_TARGET windows — copy from previously decoded target output.
//! * Default RFC 3284 code table (s_near=4, s_same=3).
//! * ADD, COPY, RUN instructions.
//! * RFC 3284 address cache (near/same).
//! * Varint (big-endian base-128) decoding.
//!
//! Rejects:
//! * Invalid magic.
//! * Secondary compressor present with non-zero ID.
//! * Non-default code table (VCD_CODETABLE set).
//! * Malformed varints (overflow, truncation).
//! * Invalid instruction opcodes.
//! * COPY operations that reference invalid ranges.
//! * Output size mismatch.
//! * Configured resource limit violations.

use crate::algo::PatchError;

// ── RFC 3284 address cache parameters ────────────────────────────────────────

const S_NEAR: usize = 4;
const S_SAME: usize = 3;
const N_MODES: usize = 2 + S_NEAR + S_SAME; // = 9

// ── Header indicator bits ─────────────────────────────────────────────────────

const VCD_DECOMPRESS: u8 = 0x01;
const VCD_CODETABLE: u8 = 0x02;

// ── Window indicator bits ─────────────────────────────────────────────────────

const VCD_SOURCE: u8 = 0x01;
const VCD_TARGET: u8 = 0x02;

// ── Instruction types ─────────────────────────────────────────────────────────

/// VCDIFF instruction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstType {
    Noop,
    Add,
    Run,
    Copy,
}

/// A single decoded instruction definition (from the code table).
#[derive(Debug, Clone, Copy)]
struct InstDef {
    ty: InstType,
    /// 0 means the size follows as a varint in the instructions section.
    size: u8,
    /// Addressing mode (for COPY only).
    mode: u8,
}

impl InstDef {
    const fn noop() -> Self {
        Self {
            ty: InstType::Noop,
            size: 0,
            mode: 0,
        }
    }

    const fn add(size: u8) -> Self {
        Self {
            ty: InstType::Add,
            size,
            mode: 0,
        }
    }

    const fn run() -> Self {
        Self {
            ty: InstType::Run,
            size: 0,
            mode: 0,
        }
    }

    const fn copy(size: u8, mode: u8) -> Self {
        Self {
            ty: InstType::Copy,
            size,
            mode,
        }
    }
}

/// A code table entry holding up to two instructions.
#[derive(Debug, Clone, Copy)]
struct CodeEntry {
    inst1: InstDef,
    inst2: InstDef,
}

impl CodeEntry {
    const fn single(inst: InstDef) -> Self {
        Self {
            inst1: inst,
            inst2: InstDef::noop(),
        }
    }

    const fn double(i1: InstDef, i2: InstDef) -> Self {
        Self { inst1: i1, inst2: i2 }
    }
}

/// Builds the RFC 3284 default code table (256 entries, s_near=4, s_same=3).
///
/// Single-instruction entries (0–162) are generated exactly per RFC 3284 §B.
/// Double-instruction entries (163–255) fill the remaining 93 slots with
/// ADD(1..4)+COPY(4..6, mode 0..8) pairs in iteration order
/// (add_size outer, mode middle, copy_size inner), stopping when all 256 slots
/// are filled.
fn build_default_code_table() -> [CodeEntry; 256] {
    let mut table = [CodeEntry::single(InstDef::noop()); 256];

    // Code 0: NOOP, NOOP (already initialised at idx=0)
    // Code 1: ADD size=0 (varint follows)
    table[1] = CodeEntry::single(InstDef::add(0));
    // Code 2: RUN size=0 (varint follows)
    table[2] = CodeEntry::single(InstDef::run());

    // Codes 3–18: ADD size=1..16
    let mut idx = 3usize;
    for s in 1u8..=16 {
        table[idx] = CodeEntry::single(InstDef::add(s));
        idx += 1;
    }
    // idx == 19

    // Codes 19–162: COPY for each mode (0..N_MODES) and size (0, 4..18)
    for mode in 0..N_MODES as u8 {
        // size=0 first (varint follows)
        table[idx] = CodeEntry::single(InstDef::copy(0, mode));
        idx += 1;
        // sizes 4..18 (15 entries per mode)
        for s in 4u8..=18 {
            table[idx] = CodeEntry::single(InstDef::copy(s, mode));
            idx += 1;
        }
    }
    // idx == 19 + 9*16 = 163

    // Codes 163–255 (93 double-instruction entries):
    // ADD(add_size) + COPY(copy_size, mode) pairs; iteration stops at code 255.
    'outer: for add_size in 1u8..=4 {
        for mode in 0..N_MODES as u8 {
            for copy_size in 4u8..=6 {
                if idx >= 256 {
                    break 'outer;
                }
                table[idx] = CodeEntry::double(InstDef::add(add_size), InstDef::copy(copy_size, mode));
                idx += 1;
            }
        }
    }
    // Any remaining slots stay NOOP,NOOP (already initialised).

    table
}

// ── Resource limits ──────────────────────────────────────────────────────────

/// Resource limits for VCDIFF patch application.
///
/// Populated by `sar-core` from its unified `ResourceLimits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcdiffLimits {
    /// Maximum compressed patch payload size. Default: 512 MiB.
    pub max_patch_size: u64,
    /// Maximum number of windows accepted per patch stream. Default: 1 000 000.
    pub max_window_count: usize,
    /// Maximum instruction count per window. Default: 10 000 000.
    pub max_instruction_count: usize,
    /// Maximum total reconstructed output size. Default: 1 GiB.
    pub max_output_size: u64,
}

impl Default for VcdiffLimits {
    fn default() -> Self {
        Self {
            max_patch_size: 512 * 1024 * 1024,
            max_window_count: 1_000_000,
            max_instruction_count: 10_000_000,
            max_output_size: 1024 * 1024 * 1024,
        }
    }
}

impl VcdiffLimits {
    /// Returns a [`VcdiffLimits`] with all limits disabled (maximum values).
    ///
    /// **Warning**: Use only in controlled test environments.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_patch_size: u64::MAX,
            max_window_count: usize::MAX,
            max_instruction_count: usize::MAX,
            max_output_size: u64::MAX,
        }
    }
}

// ── Byte-stream reader helpers ────────────────────────────────────────────────

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_u8(&mut self) -> Result<u8, PatchError> {
        if self.pos >= self.data.len() {
            return Err(PatchError::PatchFailed("VCDIFF: unexpected end of stream"));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Reads a big-endian base-128 varint (RFC 3284 §2).
    ///
    /// Each byte has 7 value bits; MSB=1 means more bytes follow.
    /// Rejects: values that overflow u64, or streams truncated mid-varint.
    fn read_varint(&mut self) -> Result<u64, PatchError> {
        let mut value: u64 = 0;
        loop {
            if self.pos >= self.data.len() {
                return Err(PatchError::PatchFailed(
                    "VCDIFF: truncated varint in patch stream",
                ));
            }
            let b = self.data[self.pos];
            self.pos += 1;
            // Overflow check: shifting 7 more bits into a u64 that already has
            // data in the top 7+ bits would overflow.
            if value > (u64::MAX >> 7) {
                return Err(PatchError::PatchFailed("VCDIFF: varint overflow"));
            }
            value = (value << 7) | u64::from(b & 0x7F);
            if (b & 0x80) == 0 {
                break;
            }
        }
        Ok(value)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], PatchError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(PatchError::PatchFailed("VCDIFF: byte read overflow"))?;
        if end > self.data.len() {
            return Err(PatchError::PatchFailed(
                "VCDIFF: unexpected end of patch stream while reading section",
            ));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), PatchError> {
        let got = self.read_bytes(expected.len())?;
        if got != expected {
            return Err(PatchError::PatchFailed("VCDIFF: magic bytes mismatch"));
        }
        Ok(())
    }
}

// ── Address cache ─────────────────────────────────────────────────────────────

struct AddrCache {
    near: [u64; S_NEAR],
    near_next: usize,
    same: [u64; S_SAME * 256],
}

impl AddrCache {
    fn new() -> Self {
        Self {
            near: [0u64; S_NEAR],
            near_next: 0,
            same: [0u64; S_SAME * 256],
        }
    }

    /// Decodes an address from the address section using the given mode.
    ///
    /// Returns the decoded address (index into the virtual source+target array).
    fn decode_address(
        &self,
        mode: u8,
        here: u64,
        addr_reader: &mut ByteReader<'_>,
    ) -> Result<u64, PatchError> {
        let addr = match mode as usize {
            // Mode 0: SELF — absolute address as varint
            0 => addr_reader.read_varint()?,
            // Mode 1: HERE — address = here - varint
            1 => {
                let delta = addr_reader.read_varint()?;
                here.checked_sub(delta)
                    .ok_or(PatchError::PatchFailed("VCDIFF: HERE address underflow"))?
            }
            // Modes 2..1+S_NEAR: NEAR cache
            m if m >= 2 && m <= 1 + S_NEAR => {
                let i = m - 2;
                let offset = addr_reader.read_varint()?;
                self.near[i]
                    .checked_add(offset)
                    .ok_or(PatchError::PatchFailed("VCDIFF: NEAR address overflow"))?
            }
            // Modes 2+S_NEAR..1+S_NEAR+S_SAME: SAME cache (single byte lookup)
            m if m >= 2 + S_NEAR && m <= 1 + S_NEAR + S_SAME => {
                let s = m - (2 + S_NEAR);
                let b = addr_reader.read_u8()? as usize;
                self.same[s * 256 + b]
            }
            _ => {
                return Err(PatchError::PatchFailed("VCDIFF: invalid COPY addressing mode"));
            }
        };
        Ok(addr)
    }

    /// Updates the address cache after a COPY instruction.
    fn update(&mut self, addr: u64) {
        self.near[self.near_next % S_NEAR] = addr;
        self.near_next += 1;
        // SAME cache: addr mod (S_SAME * 256) maps to addr
        let slot = (addr % (S_SAME as u64 * 256)) as usize;
        self.same[slot] = addr;
    }
}

// ── Main VCDIFF apply function ────────────────────────────────────────────────

/// Applies a VCDIFF patch (RFC 3284) to `base`, returning the reconstructed target.
///
/// # Arguments
///
/// * `base`                 – base object bytes (explicit; no automatic discovery).
/// * `patch`                – decoded VCDIFF patch bytes.
/// * `expected_target_size` – LFH `Uncompressed Size`; output MUST equal this exactly.
/// * `limits`               – resource limits for this operation.
///
/// # Errors
///
/// * [`PatchError::PatchFailed`]   – malformed or invalid VCDIFF data.
/// * [`PatchError::LimitExceeded`] – any configured resource limit exceeded.
/// * [`PatchError::BaseMissing`]   – base bytes required but not supplied
///                                    (the caller is responsible for this check before calling).
pub fn apply_vcdiff(
    base: &[u8],
    patch: &[u8],
    expected_target_size: u64,
    limits: &VcdiffLimits,
) -> Result<Vec<u8>, PatchError> {
    // Limit: patch size
    if patch.len() as u64 > limits.max_patch_size {
        return Err(PatchError::LimitExceeded(
            "VCDIFF: patch payload exceeds max_patch_size limit",
        ));
    }

    let mut reader = ByteReader::new(patch);

    // Header magic: 0xD6 0xC3 0xC4 0x00
    reader.expect_bytes(b"\xD6\xC3\xC4\x00")?;

    // hdr_indicator
    let hdr_indicator = reader.read_u8()?;

    if hdr_indicator & VCD_DECOMPRESS != 0 {
        let compressor_id = reader.read_u8()?;
        if compressor_id != 0 {
            return Err(PatchError::PatchFailed(
                "VCDIFF: secondary compressor not supported",
            ));
        }
    }

    if hdr_indicator & VCD_CODETABLE != 0 {
        // Application-specific code table — not supported.
        return Err(PatchError::PatchFailed(
            "VCDIFF: custom code table (VCD_CODETABLE) not supported",
        ));
    }

    let code_table = build_default_code_table();

    // Decode all windows
    let mut output: Vec<u8> = Vec::new();
    let mut window_count: usize = 0;

    while !reader.is_empty() {
        if window_count >= limits.max_window_count {
            return Err(PatchError::LimitExceeded(
                "VCDIFF: window count exceeds max_window_count limit",
            ));
        }
        window_count += 1;

        decode_window(
            base,
            &output.clone(),
            &mut reader,
            &code_table,
            limits,
            &mut output,
        )?;

        if output.len() as u64 > limits.max_output_size {
            return Err(PatchError::LimitExceeded(
                "VCDIFF: output size exceeds max_output_size limit",
            ));
        }
    }

    // Verify final output size
    if output.len() as u64 != expected_target_size {
        return Err(PatchError::PatchFailed(
            "VCDIFF: reconstructed output size does not match expected target size",
        ));
    }

    Ok(output)
}

/// Decodes one VCDIFF window and appends its output to `output`.
fn decode_window(
    base: &[u8],
    previous_output: &[u8],
    reader: &mut ByteReader<'_>,
    code_table: &[CodeEntry; 256],
    limits: &VcdiffLimits,
    output: &mut Vec<u8>,
) -> Result<(), PatchError> {
    let win_indicator = reader.read_u8()?;

    if win_indicator & VCD_SOURCE != 0 && win_indicator & VCD_TARGET != 0 {
        return Err(PatchError::PatchFailed(
            "VCDIFF: VCD_SOURCE and VCD_TARGET both set in Win_Indicator",
        ));
    }
    if win_indicator & !0x03u8 != 0 {
        return Err(PatchError::PatchFailed(
            "VCDIFF: reserved bits set in Win_Indicator",
        ));
    }

    // Source segment (if any)
    let (ss_size, ss_pos) = if win_indicator & (VCD_SOURCE | VCD_TARGET) != 0 {
        let size = reader.read_varint()? as usize;
        let pos = reader.read_varint()? as usize;
        (size, pos)
    } else {
        (0, 0)
    };

    // Validate source segment bounds
    if win_indicator & VCD_SOURCE != 0 {
        let end = ss_pos
            .checked_add(ss_size)
            .ok_or(PatchError::PatchFailed("VCDIFF: source segment overflow"))?;
        if end > base.len() {
            return Err(PatchError::PatchFailed(
                "VCDIFF: VCD_SOURCE segment references bytes beyond base",
            ));
        }
    } else if win_indicator & VCD_TARGET != 0 {
        let end = ss_pos
            .checked_add(ss_size)
            .ok_or(PatchError::PatchFailed("VCDIFF: target segment overflow"))?;
        if end > previous_output.len() {
            return Err(PatchError::PatchFailed(
                "VCDIFF: VCD_TARGET segment references bytes beyond decoded output",
            ));
        }
    }

    // Delta encoding header
    let delta_encoding_length = reader.read_varint()? as usize;
    if delta_encoding_length > reader.remaining() {
        return Err(PatchError::PatchFailed(
            "VCDIFF: delta_encoding_length exceeds remaining patch bytes",
        ));
    }
    // Record current reader position to validate delta_encoding_length later
    let delta_start = reader.pos;

    let target_window_length = reader.read_varint()? as usize;

    // Limit: output size
    let new_total = output
        .len()
        .checked_add(target_window_length)
        .ok_or(PatchError::PatchFailed("VCDIFF: target window length overflow"))?;
    if new_total as u64 > limits.max_output_size {
        return Err(PatchError::LimitExceeded(
            "VCDIFF: output size exceeds max_output_size limit",
        ));
    }

    let delta_indicator = reader.read_u8()?;
    if delta_indicator & 0x07 != 0 {
        // Bits 0..2 are VCD_DATACOMP / VCD_INSTCOMP / VCD_ADDRCOMP
        return Err(PatchError::PatchFailed(
            "VCDIFF: secondary compression in delta sections not supported",
        ));
    }

    let len_add_run = reader.read_varint()? as usize;
    let len_inst = reader.read_varint()? as usize;
    let len_addr = reader.read_varint()? as usize;

    let add_run_data = reader.read_bytes(len_add_run)?;
    let inst_bytes = reader.read_bytes(len_inst)?;
    let addr_bytes = reader.read_bytes(len_addr)?;

    // Verify delta_encoding_length matches consumed bytes
    let delta_consumed = reader.pos - delta_start;
    if delta_consumed != delta_encoding_length {
        return Err(PatchError::PatchFailed(
            "VCDIFF: delta_encoding_length mismatch",
        ));
    }

    // Decode source segment bytes for virtual addressing
    let source_bytes: &[u8] = if win_indicator & VCD_SOURCE != 0 {
        &base[ss_pos..ss_pos + ss_size]
    } else if win_indicator & VCD_TARGET != 0 {
        &previous_output[ss_pos..ss_pos + ss_size]
    } else {
        b""
    };

    // Apply instructions
    apply_instructions(
        source_bytes,
        add_run_data,
        inst_bytes,
        addr_bytes,
        target_window_length,
        code_table,
        limits,
        output,
    )?;

    Ok(())
}

/// Applies the ADD/COPY/RUN instructions from a single VCDIFF delta window.
#[allow(clippy::too_many_arguments)]
fn apply_instructions(
    source: &[u8],       // source segment for this window (may be empty)
    add_run: &[u8],      // data section (ADD payload + RUN byte)
    inst: &[u8],         // instructions section
    addr: &[u8],         // addresses section
    target_len: usize,   // expected number of output bytes for this window
    code_table: &[CodeEntry; 256],
    limits: &VcdiffLimits,
    output: &mut Vec<u8>,
) -> Result<(), PatchError> {
    let mut data_reader = ByteReader::new(add_run);
    let mut inst_reader = ByteReader::new(inst);
    let mut addr_reader = ByteReader::new(addr);

    let target_start = output.len();
    let target_end = target_start
        .checked_add(target_len)
        .ok_or(PatchError::PatchFailed("VCDIFF: target length overflow"))?;

    // Pre-allocate target window space
    output.resize(target_end, 0u8);

    let mut target_pos: usize = target_start;
    let mut addr_cache = AddrCache::new();
    let mut inst_count: usize = 0;

    while target_pos < target_end || !inst_reader.is_empty() {
        if target_pos >= target_end && !inst_reader.is_empty() {
            return Err(PatchError::PatchFailed(
                "VCDIFF: instructions remain after target window filled",
            ));
        }
        if inst_reader.is_empty() {
            break;
        }

        inst_count += 1;
        if inst_count > limits.max_instruction_count {
            return Err(PatchError::LimitExceeded(
                "VCDIFF: instruction count exceeds max_instruction_count limit",
            ));
        }

        let code = inst_reader.read_u8()? as usize;
        let entry = code_table[code];

        // Apply up to two instructions from this code table entry
        for pass in 0..2u8 {
            let idef = if pass == 0 { entry.inst1 } else { entry.inst2 };
            if idef.ty == InstType::Noop {
                continue;
            }

            // Determine size
            let size: usize = if idef.size == 0 {
                inst_reader.read_varint()? as usize
            } else {
                idef.size as usize
            };

            match idef.ty {
                InstType::Noop => {}

                InstType::Add => {
                    // Copy `size` bytes from data section into output
                    let data_slice = data_reader.read_bytes(size)?;
                    let out_end = target_pos
                        .checked_add(size)
                        .ok_or(PatchError::PatchFailed("VCDIFF: ADD output overflow"))?;
                    if out_end > target_end {
                        return Err(PatchError::PatchFailed(
                            "VCDIFF: ADD instruction writes past target window end",
                        ));
                    }
                    output[target_pos..out_end].copy_from_slice(data_slice);
                    target_pos = out_end;
                }

                InstType::Run => {
                    // Read 1 byte from data section, repeat `size` times
                    let run_byte = data_reader.read_u8()?;
                    let out_end = target_pos
                        .checked_add(size)
                        .ok_or(PatchError::PatchFailed("VCDIFF: RUN output overflow"))?;
                    if out_end > target_end {
                        return Err(PatchError::PatchFailed(
                            "VCDIFF: RUN instruction writes past target window end",
                        ));
                    }
                    for b in &mut output[target_pos..out_end] {
                        *b = run_byte;
                    }
                    target_pos = out_end;
                }

                InstType::Copy => {
                    // Compute "here": current position in the virtual source+target array
                    let here = (source.len() + (target_pos - target_start)) as u64;
                    let addr_val =
                        addr_cache.decode_address(idef.mode, here, &mut addr_reader)?;

                    addr_cache.update(addr_val);

                    let addr_usize = addr_val as usize;
                    let out_end = target_pos
                        .checked_add(size)
                        .ok_or(PatchError::PatchFailed("VCDIFF: COPY output overflow"))?;
                    if out_end > target_end {
                        return Err(PatchError::PatchFailed(
                            "VCDIFF: COPY instruction writes past target window end",
                        ));
                    }

                    // Validate address range:
                    // addresses 0..ss_size refer to source, ss_size.. refer to target (decoded so far)
                    let ss_size = source.len();
                    // Check entire copy range fits within virtual array
                    let copy_end = addr_usize
                        .checked_add(size)
                        .ok_or(PatchError::PatchFailed("VCDIFF: COPY address overflow"))?;

                    // Perform byte-by-byte copy to support overlapping copies from target
                    for i in 0..size {
                        let src_addr = addr_usize + i;
                        let b = if src_addr < ss_size {
                            // From source segment
                            source[src_addr]
                        } else {
                            // From target decoded so far (within this window)
                            let tgt_off = src_addr - ss_size;
                            let tgt_abs = target_start + tgt_off;
                            if tgt_abs >= target_pos {
                                return Err(PatchError::PatchFailed(
                                    "VCDIFF: COPY references unwritten target bytes",
                                ));
                            }
                            output[tgt_abs]
                        };
                        output[target_pos + i] = b;
                    }
                    let _ = copy_end; // validate used implicitly above

                    target_pos = out_end;
                }
            }
        }
    }

    // Verify all target bytes were written
    if target_pos != target_end {
        return Err(PatchError::PatchFailed(
            "VCDIFF: target window not fully filled by instructions",
        ));
    }

    // Verify all sections were fully consumed
    if !data_reader.is_empty() {
        return Err(PatchError::PatchFailed(
            "VCDIFF: ADD/RUN data section not fully consumed",
        ));
    }
    if !addr_reader.is_empty() {
        return Err(PatchError::PatchFailed(
            "VCDIFF: addresses section not fully consumed",
        ));
    }

    Ok(())
}
