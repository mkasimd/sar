// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use crate::archive::{
    ArchiveReaderOptions, EntryMetadata, EntryReader, apply_patch_stage, build_kms_context,
    compression_algorithm_name, require_literal_cdc,
};
use crate::transform::{DecodingPlanV2, EntryCryptoContext, decode_payload_v2};
use sar_compression::COMP_ALGO_STORE;
use sar_core::{
    error::SarError,
    flags::GlobalFlags,
    format::{
        GLOBAL_HEADER_FIXED_LEN, GlobalHeader, LocalFileHeader, decode_global_flags,
        lfh_bytes_for_aad, parse_global_header, parse_lfh, require_unpartitioned_processing,
        validate_global_header_prefix,
    },
};
use sar_crypto::{
    KeyProvider, MasterSecretScope, aad::build_aead_aad, derive_entry_key,
    validate_entry_encr_algo_id,
};

const SAR_MAGIC: [u8; 4] = [0x53, 0x41, 0x52, 0x21];

/// Explicit stream parser phases for forward-only byte-stream parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamParseState {
    /// Waiting for the next archive global header.
    NeedGlobalHeader,
    /// Waiting for the next Local File Header.
    NeedLocalFileHeader,
    /// Waiting for current entry payload bytes.
    NeedPayload,
    /// Current entry payload is complete and transform pipeline can run.
    TransformingEntry,
    /// One entry was fully transformed and is ready to consume.
    EntryReady,
    /// Indexed archive trailer state (not implemented for forward-only parser in M10a).
    NeedCentralDictionaryOrFooter,
    /// Current archive is structurally complete.
    ArchiveComplete,
    /// Parser entered a terminal error state.
    Error,
}

/// Deterministic incremental step result for stream parser execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamStep<T> {
    /// More bytes are required before the parser can advance.
    NeedMore {
        /// Exact required byte count when known for the current phase.
        needed: Option<usize>,
    },
    /// One parse event is ready.
    Ready(T),
    /// Parsing is complete and no further archives remain in the stream.
    Complete,
}

/// Events emitted by [`StreamArchiveParser`].
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Global header was parsed and current archive context is resolved.
    GlobalHeader(Box<GlobalHeader>),
    /// One decoded entry is ready.
    Entry(Box<EntryReader>),
    /// Current archive is complete.
    ArchiveComplete(StreamArchiveSummary),
}

/// Summary emitted when one archive completes in stream mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamArchiveSummary {
    /// Number of entries parsed in the archive.
    pub entry_count: u64,
    /// Archive global flags.
    pub flags: GlobalFlags,
    /// Whether archive is indexed.
    pub indexed: bool,
}

#[derive(Debug, Clone)]
struct PendingEntry {
    lfh: LocalFileHeader,
    lfh_bytes: Vec<u8>,
    payload_offset: u64,
    encoded_payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct ActiveArchive {
    header: GlobalHeader,
    /// Raw encoded Global Header bytes retained for AEAD AAD.
    global_header_bytes: Vec<u8>,
    entry_count: u64,
}

/// Forward-only SAR byte-stream parser with partial-input support.
pub struct StreamArchiveParser {
    options: ArchiveReaderOptions,
    key_provider: Option<Box<dyn KeyProvider>>,
    /// KMS Master Secret for the current archive stream; the KDF runs once.
    master_secret: MasterSecretScope,
    state: StreamParseState,
    buffer: Vec<u8>,
    consumed: usize,
    finalized: bool,
    absolute_offset: u64,
    archive: Option<ActiveArchive>,
    pending_entry: Option<PendingEntry>,
}

impl StreamArchiveParser {
    /// Creates a new forward-only parser using default reader options.
    #[must_use]
    pub fn new() -> Self {
        Self::with_options(ArchiveReaderOptions::default())
    }

    /// Creates a new forward-only parser using explicit options.
    #[must_use]
    pub fn with_options(options: ArchiveReaderOptions) -> Self {
        Self {
            options,
            key_provider: None,
            master_secret: MasterSecretScope::new(),
            state: StreamParseState::NeedGlobalHeader,
            buffer: Vec::new(),
            consumed: 0,
            finalized: false,
            absolute_offset: 0,
            archive: None,
            pending_entry: None,
        }
    }

    /// Attaches a key provider used for encrypted-entry decoding.
    #[must_use]
    pub fn with_key_provider(mut self, key_provider: Box<dyn KeyProvider>) -> Self {
        self.key_provider = Some(key_provider);
        self.master_secret.invalidate();
        self
    }

    /// Returns current parser state.
    #[must_use]
    pub const fn state(&self) -> StreamParseState {
        self.state
    }

    /// Appends a new chunk of bytes to the parser input buffer.
    pub fn push_bytes(&mut self, chunk: &[u8]) -> Result<(), SarError> {
        let add = u64::try_from(chunk.len()).map_err(|_| SarError::Overflow("stream chunk len"))?;
        let buffered = u64::try_from(self.available())
            .map_err(|_| SarError::Overflow("stream buffered len"))?;
        let total = self
            .absolute_offset
            .checked_add(buffered)
            .and_then(|v| v.checked_add(add))
            .ok_or(SarError::Overflow("stream byte count"))?;
        self.options.limits.check_archive_size(total)?;
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Returns the exact encoded Global Header bytes of the active archive,
    /// as received (the AEAD AAD prefix), once the header has been parsed.
    #[must_use]
    pub fn global_header_bytes(&self) -> Option<&[u8]> {
        self.archive
            .as_ref()
            .map(|archive| archive.global_header_bytes.as_slice())
    }

    /// Declares that no further bytes will be provided.
    pub fn finalize_input(&mut self) {
        self.finalized = true;
    }

    /// Executes one deterministic parser step.
    pub fn step(&mut self) -> Result<StreamStep<StreamEvent>, SarError> {
        loop {
            match self.state {
                StreamParseState::NeedGlobalHeader => {
                    if self.finalized && self.available() == 0 {
                        return Ok(StreamStep::Complete);
                    }
                    let Some(needed) = self.required_global_header_bytes()? else {
                        if self.finalized {
                            return self.set_error(SarError::Truncated(
                                "incomplete global header at end of stream",
                            ));
                        }
                        return Ok(StreamStep::NeedMore { needed: Some(8) });
                    };
                    if self.available() < needed {
                        if self.finalized {
                            return self.set_error(SarError::Truncated(
                                "incomplete global header at end of stream",
                            ));
                        }
                        return Ok(StreamStep::NeedMore {
                            needed: Some(needed),
                        });
                    }

                    let input = self.peek(needed).ok_or(SarError::Truncated(
                        "global header bytes missing from parser buffer",
                    ))?;
                    let (header, consumed) = parse_global_header(input, &self.options.limits)?;
                    if consumed != needed {
                        return self.set_error(SarError::InvalidLength(
                            "global header parser consumed unexpected length",
                        ));
                    }
                    if header.flags.contains(GlobalFlags::ENCRYPTED) {
                        let _ = build_kms_context(&header)?;
                    }
                    require_unpartitioned_processing(header.flags)?;

                    let raw_header_bytes = input
                        .get(..consumed)
                        .ok_or(SarError::Internal("global header length exceeds input"))?
                        .to_vec();
                    self.consume(consumed)?;
                    // A new Global Header starts a new KMS scope.
                    self.master_secret.invalidate();
                    self.archive = Some(ActiveArchive {
                        global_header_bytes: raw_header_bytes,
                        header: header.clone(),
                        entry_count: 0,
                    });

                    self.state = if header.flags.contains(GlobalFlags::NO_INDEX) {
                        StreamParseState::NeedLocalFileHeader
                    } else {
                        StreamParseState::NeedCentralDictionaryOrFooter
                    };
                    return Ok(StreamStep::Ready(StreamEvent::GlobalHeader(Box::new(
                        header,
                    ))));
                }
                StreamParseState::NeedCentralDictionaryOrFooter => {
                    return self.set_error(SarError::Unsupported(
                        "forward-only stream parser currently supports NO_INDEX archives only",
                    ));
                }
                StreamParseState::NeedLocalFileHeader => {
                    let archive = self
                        .archive
                        .as_ref()
                        .ok_or(SarError::Internal("stream parser missing active archive"))?;

                    if self.available() == 0 {
                        if self.finalized {
                            self.state = StreamParseState::ArchiveComplete;
                            continue;
                        }
                        return Ok(StreamStep::NeedMore { needed: Some(4) });
                    }

                    if self.available() >= 4 {
                        let prefix = self
                            .peek(4)
                            .ok_or(SarError::Truncated("LFH prefix unavailable"))?;
                        if prefix == SAR_MAGIC {
                            self.state = StreamParseState::ArchiveComplete;
                            continue;
                        }
                    } else if self.finalized {
                        return self.set_error(SarError::Truncated(
                            "incomplete LFH prefix at end of stream",
                        ));
                    } else {
                        return Ok(StreamStep::NeedMore { needed: Some(4) });
                    }

                    let header_size_bytes = self
                        .peek(4)
                        .ok_or(SarError::Truncated("LFH header size missing"))?;
                    let header_size = usize::try_from(u32::from_le_bytes([
                        header_size_bytes[0],
                        header_size_bytes[1],
                        header_size_bytes[2],
                        header_size_bytes[3],
                    ]))
                    .map_err(|_| SarError::Overflow("LFH header size"))?;
                    self.options.limits.check_lfh_header_bytes(header_size)?;
                    if header_size < 4 {
                        return self.set_error(SarError::InvalidLength(
                            "LFH Header Size smaller than fixed prefix",
                        ));
                    }
                    if self.available() < header_size {
                        if self.finalized {
                            return self
                                .set_error(SarError::Truncated("incomplete LFH at end of stream"));
                        }
                        return Ok(StreamStep::NeedMore {
                            needed: Some(header_size),
                        });
                    }

                    let lfh_bytes = self
                        .peek(header_size)
                        .ok_or(SarError::Truncated("LFH bytes missing"))?
                        .to_vec();
                    let (lfh, consumed) =
                        parse_lfh(&lfh_bytes, &archive.header.flags, &self.options.limits)?;
                    if consumed != header_size {
                        return self.set_error(SarError::InvalidLength(
                            "LFH parser consumed unexpected length",
                        ));
                    }
                    self.consume(consumed)?;

                    let payload_offset = self.absolute_offset;
                    let payload_len = self
                        .options
                        .limits
                        .allocation_len(lfh.payload_size, "payload length usize")?;

                    self.pending_entry = Some(PendingEntry {
                        lfh,
                        lfh_bytes,
                        payload_offset,
                        encoded_payload: None,
                    });
                    self.state = StreamParseState::NeedPayload;

                    if payload_len == 0 {
                        continue;
                    }
                }
                StreamParseState::NeedPayload => {
                    let payload_len = {
                        let pending = self
                            .pending_entry
                            .as_ref()
                            .ok_or(SarError::Internal("missing pending entry in NeedPayload"))?;
                        self.options
                            .limits
                            .allocation_len(pending.lfh.payload_size, "payload length usize")?
                    };

                    if self.available() < payload_len {
                        if self.finalized {
                            return self.set_error(SarError::Truncated(
                                "incomplete payload at end of stream",
                            ));
                        }
                        return Ok(StreamStep::NeedMore {
                            needed: Some(payload_len),
                        });
                    }

                    let payload = self
                        .peek(payload_len)
                        .ok_or(SarError::Truncated("payload bytes missing"))?
                        .to_vec();
                    self.consume(payload_len)?;

                    let pending = self.pending_entry.as_mut().ok_or(SarError::Internal(
                        "missing pending entry after payload read",
                    ))?;
                    pending.encoded_payload = Some(payload);
                    self.state = StreamParseState::TransformingEntry;
                    continue;
                }
                StreamParseState::TransformingEntry => {
                    let entry = self.decode_pending_entry()?;
                    self.state = StreamParseState::EntryReady;
                    return Ok(StreamStep::Ready(StreamEvent::Entry(Box::new(entry))));
                }
                StreamParseState::EntryReady => {
                    self.state = StreamParseState::NeedLocalFileHeader;
                    continue;
                }
                StreamParseState::ArchiveComplete => {
                    let archive = self
                        .archive
                        .take()
                        .ok_or(SarError::Internal("stream parser missing archive summary"))?;
                    self.pending_entry = None;
                    self.state = StreamParseState::NeedGlobalHeader;
                    return Ok(StreamStep::Ready(StreamEvent::ArchiveComplete(
                        StreamArchiveSummary {
                            entry_count: archive.entry_count,
                            flags: archive.header.flags,
                            indexed: !archive.header.flags.contains(GlobalFlags::NO_INDEX),
                        },
                    )));
                }
                StreamParseState::Error => {
                    return Err(SarError::StreamState(
                        "stream parser is in terminal error state",
                    ));
                }
            }
        }
    }

    fn decode_pending_entry(&mut self) -> Result<EntryReader, SarError> {
        let archive = self.archive.as_mut().ok_or(SarError::Internal(
            "missing active archive while decoding entry",
        ))?;
        let pending = self.pending_entry.take().ok_or(SarError::Internal(
            "missing pending entry for transform phase",
        ))?;

        let lfh = pending.lfh;
        let lfh_bytes = pending.lfh_bytes;
        let encoded_payload = pending.encoded_payload.ok_or(SarError::Internal(
            "missing encoded payload in transform phase",
        ))?;

        crate::fragment_group::check_later_fragment_sparse_map(&lfh)?;
        let is_effectively_compressed = archive.header.flags.contains(GlobalFlags::COMPRESSED)
            && lfh.entry_mode.is_compressed();
        let is_encrypted =
            archive.header.flags.contains(GlobalFlags::ENCRYPTED) && lfh.entry_mode.is_encrypted();
        let is_sparse =
            archive.header.flags.contains(GlobalFlags::SPARSE_FILES) && !lfh.sparse_map.is_empty();
        let is_has_delta = archive.header.flags.contains(GlobalFlags::HAS_DELTA);
        let patch_raw_id = lfh.patch_algo_id.unwrap_or(0);

        let effective_comp_algo_id = if is_effectively_compressed {
            lfh.comp_algo_id.unwrap_or(COMP_ALGO_STORE)
        } else {
            COMP_ALGO_STORE
        };

        // LFH `Uncompressed Size` is the fragment-local transform-boundary
        // length (spec Sections 6.1.2 and 8.4), never the patch output length.
        let decode_expected = lfh.uncompressed_size;

        let crypto = if is_encrypted {
            let algo_id = lfh.encr_algo_id.ok_or(SarError::Malformed(
                "encrypted entry missing encryption algorithm ID",
            ))?;
            validate_entry_encr_algo_id(algo_id).map_err(SarError::from)?;
            let provider = self.key_provider.as_deref().ok_or(SarError::KeyMissing(
                "no key provider configured for encrypted archive",
            ))?;
            let context = build_kms_context(&archive.header)?;
            let iv_nonce = lfh.iv_nonce.ok_or(SarError::Malformed(
                "encrypted entry missing IV/nonce field",
            ))?;
            let master = self
                .master_secret
                .get_or_resolve(provider, &context, &self.options.limits.kdf_limits())
                .map_err(SarError::from)?;
            let key = derive_entry_key(master, algo_id, &iv_nonce).map_err(SarError::from)?;
            let fec_algo_id = lfh.fec_algo_id.unwrap_or(0);
            let aad_lfh_bytes = lfh_bytes_for_aad(
                archive.header.flags,
                &lfh_bytes,
                fec_algo_id,
                lfh.fec_value.len(),
            )?;
            let aad = build_aead_aad(&archive.global_header_bytes, &aad_lfh_bytes);
            Some(EntryCryptoContext {
                algo_id,
                iv_nonce,
                aad,
                key,
            })
        } else {
            None
        };

        let decoded = decode_payload_v2(
            &encoded_payload,
            DecodingPlanV2 {
                is_compressed: is_effectively_compressed,
                comp_algo_id: effective_comp_algo_id,
                expected_output_size: decode_expected,
                max_output_size: self.options.max_decoded_entry_size(),
                crypto,
            },
        )?;

        if u64::try_from(decoded.len()).map_err(|_| SarError::Overflow("decoded payload len"))?
            != lfh.uncompressed_size
        {
            return Err(SarError::InvalidLength(
                "decoded payload size does not match LFH Uncompressed Size",
            ));
        }
        if !is_effectively_compressed && !is_encrypted && lfh.payload_size != lfh.uncompressed_size
        {
            return Err(SarError::InvalidLength(
                "STORE mode requires Payload Size == Uncompressed Size",
            ));
        }

        // The patch is applied once to a complete patch representation.  This
        // parser emits physical Entries, so an unfragmented Entry is patched
        // here, while a fragment is returned as its decoded contribution for
        // group-wide reassembly and patching.
        let decoded = if is_has_delta && !lfh.entry_mode.is_fragment() {
            apply_patch_stage(
                &self.options,
                patch_raw_id,
                lfh.delta_base_hash.unwrap_or([0u8; 32]),
                decoded,
            )?
        } else {
            decoded
        };

        let fec = if archive.header.flags.contains(GlobalFlags::SELECTIVE_FEC) {
            let algo_id = lfh.fec_algo_id.unwrap_or(0);
            sar_core::fec::parse_lfh_fec_value(algo_id, &lfh.fec_value, &self.options.limits)?
        } else {
            None
        };

        let sparse_map: Option<sar_core::sparse::SparseMap> = if is_sparse {
            let is_64bit = archive.header.flags.contains(GlobalFlags::SIZE_64BIT);
            let map = sar_core::sparse::parse_sparse_map(
                &lfh.sparse_map,
                is_64bit,
                &self.options.limits,
            )?;
            let extent_total = sar_sparse::validate_sparse_extents(
                &map.extents,
                map.logical_size,
                &self.options.limits.sparse_limits(),
            )?;
            // A fragment is only a contribution; its group is checked on assembly.
            if !lfh.entry_mode.is_fragment() {
                sar_sparse::check_gathered_length(
                    u64::try_from(decoded.len())
                        .map_err(|_| SarError::Overflow("gathered length"))?,
                    extent_total,
                )?;
            }
            Some(map)
        } else {
            None
        };
        let sparse_extents: Option<Vec<sar_core::sparse::SparseExtent>> =
            sparse_map.as_ref().map(|m| m.extents.clone());

        let cdc_algo_id_opt: Option<u8> = if archive.header.flags.contains(GlobalFlags::CDC_SUPPORT)
        {
            let algo_id = lfh.cdc_algo_id.unwrap_or(0);
            sar_core::cdc::validate_cdc_algo_id(algo_id)?;
            Some(algo_id)
        } else {
            None
        };
        // CDC recipe resolution follows patch application and is not
        // implemented; an unresolved Hash Recipe is never a logical Entry.
        if !lfh.entry_mode.is_fragment() {
            require_literal_cdc(cdc_algo_id_opt)?;
        }

        let name_str = String::from_utf8(lfh.name.clone())
            .map_err(|_| SarError::Malformed("LFH Name String is not valid UTF-8"))?;

        // Validate directory entry payload rule.
        if lfh.entry_mode.is_directory() && lfh.payload_size != 0 {
            return Err(SarError::Malformed(
                "IS_DIRECTORY entry must have zero Payload Size",
            ));
        }

        let entry_kind =
            sar_core::metadata::EntryKind::from_mode_and_name(lfh.entry_mode, name_str.is_empty());
        let symlink_target = if matches!(entry_kind, sar_core::metadata::EntryKind::Symlink) {
            Some(
                std::str::from_utf8(&decoded)
                    .map_err(|_| SarError::Malformed("Symlink target payload is not valid UTF-8"))?
                    .to_owned(),
            )
        } else {
            None
        };

        let compression_presence = if archive.header.flags.contains(GlobalFlags::COMPRESSED) {
            let raw_algo_id = lfh.comp_algo_id.unwrap_or(COMP_ALGO_STORE);
            let cm = sar_core::metadata::EntryCompressionMetadata {
                algo_id: raw_algo_id,
                algorithm_name: compression_algorithm_name(raw_algo_id),
            };
            if is_effectively_compressed {
                sar_core::metadata::FieldPresence::PresentActive(cm)
            } else {
                sar_core::metadata::FieldPresence::PresentInactive(cm)
            }
        } else {
            sar_core::metadata::FieldPresence::Absent
        };

        let encryption_presence = if archive.header.flags.contains(GlobalFlags::ENCRYPTED) {
            let algo_id = lfh.encr_algo_id.unwrap_or(0);
            let iv_nonce = lfh.iv_nonce.unwrap_or([0u8; 24]);
            let em = sar_core::metadata::EntryEncryptionMetadata { algo_id, iv_nonce };
            if is_encrypted {
                sar_core::metadata::FieldPresence::PresentActive(em)
            } else {
                sar_core::metadata::FieldPresence::PresentInactive(em)
            }
        } else {
            sar_core::metadata::FieldPresence::Absent
        };

        let fec_presence = if archive.header.flags.contains(GlobalFlags::SELECTIVE_FEC) {
            let algo_id = lfh.fec_algo_id.unwrap_or(0);
            let fm = sar_core::metadata::EntryFecMetadata {
                algo_id,
                summary: fec.clone(),
            };
            if algo_id != 0 {
                sar_core::metadata::FieldPresence::PresentActive(fm)
            } else {
                sar_core::metadata::FieldPresence::PresentInactive(fm)
            }
        } else {
            sar_core::metadata::FieldPresence::Absent
        };

        let fragment_presence = if archive
            .header
            .flags
            .contains(GlobalFlags::FILE_FRAGMENTATION)
        {
            let frag_id = lfh.fragment_id.unwrap_or(0);
            let frag_idx = lfh.fragment_index.unwrap_or(0);
            let fm = sar_core::metadata::EntryFragmentMetadata {
                fragment_id: frag_id,
                fragment_index: frag_idx,
                is_last: lfh.entry_mode.is_last_fragment(),
                is_loss_tolerant: lfh.entry_mode.is_loss_tolerant(),
            };
            if lfh.entry_mode.is_fragment() {
                sar_core::metadata::FieldPresence::PresentActive(fm)
            } else {
                sar_core::metadata::FieldPresence::PresentInactive(fm)
            }
        } else {
            sar_core::metadata::FieldPresence::Absent
        };

        let cdc: Option<sar_core::metadata::EntryCdcMetadata> =
            cdc_algo_id_opt.map(|algo_id| sar_core::metadata::EntryCdcMetadata { algo_id });

        let delta: Option<sar_core::metadata::EntryDeltaMetadata> = if is_has_delta {
            Some(sar_core::metadata::EntryDeltaMetadata {
                patch_algo_id: patch_raw_id,
                base_hash: lfh.delta_base_hash.unwrap_or([0u8; 32]),
            })
        } else {
            None
        };

        let sparse: Option<sar_core::metadata::EntrySparseMetadata> =
            sparse_map
                .as_ref()
                .map(|map| sar_core::metadata::EntrySparseMetadata {
                    logical_size: map.logical_size,
                    extents: map.extents.clone(),
                });

        let has_crc = archive.header.flags.contains(GlobalFlags::PER_FILE_CRC);
        let has_hash = archive.header.flags.contains(GlobalFlags::DEDUPLICATION);
        let hash: Option<sar_core::metadata::EntryHashMetadata> = if has_crc || has_hash {
            Some(sar_core::metadata::EntryHashMetadata {
                crc32: if has_crc { lfh.file_crc32 } else { None },
                hash_algo_id: if has_hash { lfh.hash_algo_id } else { None },
                content_hash: if has_hash { lfh.content_hash } else { None },
            })
        } else {
            None
        };

        let metadata = EntryMetadata {
            lfh_offset: pending
                .payload_offset
                .checked_sub(u64::from(lfh.header_size))
                .ok_or(SarError::Overflow("LFH offset underflow"))?,
            name: name_str,
            path: if lfh.path.is_empty() {
                None
            } else {
                let p = String::from_utf8(lfh.path.clone())
                    .map_err(|_| SarError::Malformed("LFH Path String is not valid UTF-8"))?;
                Some(p)
            },
            symlink_target,
            payload_size: lfh.payload_size,
            uncompressed_size: lfh.uncompressed_size,
            compression_algo_id: effective_comp_algo_id,
            compression_algorithm: compression_algorithm_name(effective_comp_algo_id),
            is_compressed: is_effectively_compressed,
            fec,
            fragment_id: lfh.fragment_id,
            fragment_index: lfh.fragment_index,
            is_fragment: lfh.entry_mode.is_fragment(),
            is_last_fragment: lfh.entry_mode.is_last_fragment(),
            is_loss_tolerant: lfh.entry_mode.is_loss_tolerant(),
            sparse_extents,
            file_crc32: lfh.file_crc32,
            hash_algo_id: lfh.hash_algo_id,
            content_hash: lfh.content_hash,
            cdc_algo_id: cdc_algo_id_opt,
            patch_algo_id: if is_has_delta {
                Some(patch_raw_id)
            } else {
                None
            },
            delta_base_hash: if is_has_delta {
                Some(lfh.delta_base_hash.unwrap_or([0u8; 32]))
            } else {
                None
            },
            entry_kind,
            entry_mode_raw: lfh.entry_mode.bits(),
            stream_id: lfh.stream_id,
            sequence_no: lfh.sequence_no,
            is_hidden: lfh.entry_mode.is_hidden_attr(),
            permissions: lfh
                .permissions
                .map(|mode| sar_core::metadata::EntryPermissionMetadata { mode }),
            owner: lfh
                .uid_gid
                .map(|uid_gid| sar_core::metadata::EntryOwnerMetadata { uid_gid }),
            timestamps: lfh
                .timestamps
                .map(|ts| sar_core::metadata::EntryTimestampMetadata {
                    mtime: ts[0],
                    atime: ts[1],
                    ctime: ts[2],
                }),
            // M11b filesystem metadata presence model.
            path_presence: if archive.header.flags.contains(GlobalFlags::HAS_PATH) {
                if lfh.path.is_empty() {
                    sar_core::metadata::FieldPresence::PresentInactive(String::new())
                } else {
                    let p = String::from_utf8(lfh.path.clone())
                        .map_err(|_| SarError::Malformed("LFH Path String is not valid UTF-8"))?;
                    sar_core::metadata::FieldPresence::PresentActive(p)
                }
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            permissions_presence: if archive.header.flags.contains(GlobalFlags::HAS_PERMS) {
                sar_core::metadata::FieldPresence::PresentActive(
                    sar_core::metadata::EntryPermissionMetadata {
                        mode: lfh.permissions.unwrap_or(0),
                    },
                )
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            owner_presence: if archive.header.flags.contains(GlobalFlags::EXT_UID_GID) {
                sar_core::metadata::FieldPresence::PresentActive(
                    sar_core::metadata::EntryOwnerMetadata {
                        uid_gid: lfh.uid_gid.unwrap_or(0),
                    },
                )
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            timestamps_presence: if archive.header.flags.contains(GlobalFlags::EXT_TIME) {
                let ts = lfh.timestamps.unwrap_or([0u64; 3]);
                sar_core::metadata::FieldPresence::PresentActive(
                    sar_core::metadata::EntryTimestampMetadata {
                        mtime: ts[0],
                        atime: ts[1],
                        ctime: ts[2],
                    },
                )
            } else {
                sar_core::metadata::FieldPresence::Absent
            },
            compression_presence,
            encryption_presence,
            fec_presence,
            fragment_presence,
            cdc,
            delta,
            sparse,
            hash,
        };

        archive.entry_count = archive
            .entry_count
            .checked_add(1)
            .ok_or(SarError::Overflow("entry count"))?;

        Ok(EntryReader {
            header: lfh,
            payload: decoded,
            metadata,
        })
    }

    fn required_global_header_bytes(&self) -> Result<Option<usize>, SarError> {
        let Some(prefix) = self.peek(8) else {
            return Ok(None);
        };
        validate_global_header_prefix(prefix)?;

        let Some(fixed) = self.peek(GLOBAL_HEADER_FIXED_LEN) else {
            return Ok(Some(GLOBAL_HEADER_FIXED_LEN));
        };
        let mut flags_bytes = [0u8; 4];
        flags_bytes.copy_from_slice(&fixed[8..GLOBAL_HEADER_FIXED_LEN]);
        let flags = decode_global_flags(flags_bytes)?;
        if !flags.contains(GlobalFlags::ENCRYPTED) {
            return Ok(Some(GLOBAL_HEADER_FIXED_LEN));
        }

        let kms_prefix_end = GLOBAL_HEADER_FIXED_LEN
            .checked_add(5)
            .ok_or(SarError::Overflow("KMS prefix offset"))?;
        let Some(prefix) = self.peek(kms_prefix_end) else {
            return Ok(Some(kms_prefix_end));
        };
        let payload_len = usize::try_from(u32::from_le_bytes([
            prefix[GLOBAL_HEADER_FIXED_LEN + 1],
            prefix[GLOBAL_HEADER_FIXED_LEN + 2],
            prefix[GLOBAL_HEADER_FIXED_LEN + 3],
            prefix[GLOBAL_HEADER_FIXED_LEN + 4],
        ]))
        .map_err(|_| SarError::Overflow("KMS payload length"))?;
        self.options.limits.check_kms_payload_bytes(payload_len)?;
        kms_prefix_end
            .checked_add(payload_len)
            .map(Some)
            .ok_or(SarError::Overflow("KMS extension size"))
    }

    fn peek(&self, len: usize) -> Option<&[u8]> {
        if self.available() < len {
            return None;
        }
        let start = self.consumed;
        self.buffer.get(start..start + len)
    }

    fn available(&self) -> usize {
        self.buffer.len().saturating_sub(self.consumed)
    }

    fn consume(&mut self, len: usize) -> Result<(), SarError> {
        if len > self.available() {
            return Err(SarError::Truncated("stream consume beyond available bytes"));
        }
        self.consumed = self
            .consumed
            .checked_add(len)
            .ok_or(SarError::Overflow("stream cursor"))?;
        self.absolute_offset = self
            .absolute_offset
            .checked_add(u64::try_from(len).map_err(|_| SarError::Overflow("stream offset"))?)
            .ok_or(SarError::Overflow("stream absolute offset"))?;
        if self.consumed > 0 && (self.consumed >= 4096 || self.consumed == self.buffer.len()) {
            self.buffer.drain(..self.consumed);
            self.consumed = 0;
        }
        Ok(())
    }

    fn set_error<T>(&mut self, err: SarError) -> Result<T, SarError> {
        self.state = StreamParseState::Error;
        Err(err)
    }
}

impl Default for StreamArchiveParser {
    fn default() -> Self {
        Self::new()
    }
}
