// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use sar_core::{
    GlobalFlags, GlobalHeader, LocalFileHeader, ResourceLimits, SarError, SarStatus,
    validate_entry_mode_against_global, validate_global_flags,
};

use crate::protocol::{
    AckFlags, CapabilityFlags, FilesystemOpCode, SessionAckFrame, SessionCapabilitiesFrame,
    SessionFlags, SessionInitFrame, SessionMetadataFrame, SessionOpCode, SessionResumeFrame,
    SessionStatusFrame,
};

const ACTIVE_SESSION_BASE_MEMORY_BYTES: u64 = 16 + 2 + 2 + 8;

/// Configuration for the in-memory stateful session manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionManagerConfig {
    /// Unified resource limits.
    pub limits: ResourceLimits,
    /// Local capabilities used when emitting in-memory reverse-control actions.
    pub local_capabilities: CapabilityFlags,
    /// Whether `SESSION_RESUME` is supported by this receiver model.
    pub support_resume: bool,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            limits: ResourceLimits::default(),
            local_capabilities: CapabilityFlags::from_bits(
                CapabilityFlags::SESSION_ACK
                    | CapabilityFlags::SESSION_STATUS
                    | CapabilityFlags::SESSION_METADATA,
            ),
            support_resume: false,
        }
    }
}

/// Stored application metadata associated with an active stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadataState {
    /// Content type carried by the latest `SESSION_METADATA` frame.
    pub content_type: String,
    /// Opaque metadata bytes.
    pub metadata: Vec<u8>,
}

/// Active in-memory session binding for one Stream ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSession {
    /// Bound Stream ID.
    pub stream_id: u16,
    /// Bound Session UUID.
    pub session_uuid: [u8; 16],
    /// Negotiated/requested session flags from `SESSION_INIT`.
    pub session_flags: SessionFlags,
    /// Most recently observed sequence number in this session.
    pub last_sequence_no: u16,
    /// Current archive/global flags associated with the active stream.
    pub global_flags: GlobalFlags,
    /// Last advertised peer capabilities.
    pub peer_capabilities: CapabilityFlags,
    /// Latest application metadata.
    pub metadata: Option<SessionMetadataState>,
    /// Logical activity tick updated on every accepted LFH.
    pub last_activity_tick: u64,
}

impl ActiveSession {
    fn memory_usage(&self) -> u64 {
        let metadata = self
            .metadata
            .as_ref()
            .map(|value| value.content_type.len() + value.metadata.len())
            .unwrap_or(0);
        ACTIVE_SESSION_BASE_MEMORY_BYTES + u64::try_from(metadata).unwrap_or(u64::MAX)
    }
}

/// Input entry for stateful session processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEntry {
    /// Parsed LFH.
    pub header: LocalFileHeader,
    /// Decoded payload bytes.
    pub payload: Vec<u8>,
    /// True when upstream loss-tolerant reconstruction produced degraded output.
    pub degraded: bool,
}

impl SessionEntry {
    /// Creates a session entry directly from decoded fields.
    #[must_use]
    pub fn new(header: LocalFileHeader, payload: Vec<u8>, degraded: bool) -> Self {
        Self {
            header,
            payload,
            degraded,
        }
    }
}

/// Filesystem action details for data-bearing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemEntryAction {
    /// Active Stream ID.
    pub stream_id: u16,
    /// Entry sequence number.
    pub sequence_no: u16,
    /// Raw LFH name bytes.
    pub name: Vec<u8>,
    /// Raw LFH path bytes.
    pub path: Vec<u8>,
    /// Decoded payload bytes.
    pub payload: Vec<u8>,
    /// True when `ATOMIC_WRITE` is set.
    pub atomic_write: bool,
    /// True when `FORCE_SYNC` is set.
    pub force_sync: bool,
    /// True when the entry is marked `LOSS_TOLERANT`.
    pub loss_tolerant: bool,
}

/// Filesystem action details for deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemDeleteAction {
    /// Active Stream ID.
    pub stream_id: u16,
    /// Entry sequence number.
    pub sequence_no: u16,
    /// Raw LFH name bytes.
    pub name: Vec<u8>,
    /// Raw LFH path bytes.
    pub path: Vec<u8>,
    /// True when `ATOMIC_WRITE` is set.
    pub atomic_write: bool,
    /// True when `FORCE_SYNC` is set.
    pub force_sync: bool,
}

/// Filesystem action details for rename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemRenameAction {
    /// Active Stream ID.
    pub stream_id: u16,
    /// Entry sequence number.
    pub sequence_no: u16,
    /// Raw LFH name bytes (old name/path source).
    pub old_name: Vec<u8>,
    /// Raw LFH path bytes (old path prefix).
    pub old_path: Vec<u8>,
    /// New path bytes carried in the payload.
    pub new_path: Vec<u8>,
    /// True when `ATOMIC_WRITE` is set.
    pub atomic_write: bool,
    /// True when `FORCE_SYNC` is set.
    pub force_sync: bool,
}

/// Filesystem action details for sync barriers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemSyncBarrierAction {
    /// Active Stream ID.
    pub stream_id: u16,
    /// Entry sequence number.
    pub sequence_no: u16,
    /// True when `ATOMIC_WRITE` is set.
    pub atomic_write: bool,
    /// True when `FORCE_SYNC` is set.
    pub force_sync: bool,
}

/// In-memory filesystem actions emitted by the session layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemAction {
    /// `DATA_WRITE`
    DataWrite(FilesystemEntryAction),
    /// `DELETE`
    Delete(FilesystemDeleteAction),
    /// `RENAME`
    Rename(FilesystemRenameAction),
    /// `META_PROBE`
    MetaProbe(FilesystemEntryAction),
    /// `SYNC_BARRIER`
    SyncBarrier(FilesystemSyncBarrierAction),
}

/// Reverse-direction actions the receiver would emit if transport existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    /// Emit a `SESSION_ACK` payload for the given Stream ID.
    EmitAck {
        /// Referenced active Stream ID.
        stream_id: u16,
        /// Payload frame to send.
        frame: SessionAckFrame,
    },
}

/// Observable state-machine events emitted by the session manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// `SESSION_INIT` successfully activated a new session binding.
    SessionActivated {
        /// Bound Stream ID.
        stream_id: u16,
        /// Bound Session UUID.
        session_uuid: [u8; 16],
        /// Session flags.
        flags: SessionFlags,
    },
    /// Stateful semantics were inactive for the current entry.
    StatefulInactive {
        /// Stream ID from the LFH.
        stream_id: u16,
        /// Raw OP_CODE bits.
        op_code: u8,
        /// True when the entry was in the session-control namespace.
        session_control: bool,
    },
    /// Active session was closed.
    SessionClosed {
        /// Closed Stream ID.
        stream_id: u16,
        /// Closed Session UUID.
        session_uuid: [u8; 16],
    },
    /// Active session successfully resumed.
    SessionResumed {
        /// Resumed Stream ID.
        stream_id: u16,
        /// Resumed Session UUID.
        session_uuid: [u8; 16],
    },
    /// Heartbeat accepted for an active session.
    Heartbeat {
        /// Stream ID.
        stream_id: u16,
        /// Sequence number.
        sequence_no: u16,
    },
    /// Status frame received.
    Status {
        /// Stream ID.
        stream_id: u16,
        /// Parsed status frame.
        frame: SessionStatusFrame,
    },
    /// ACK frame received.
    Ack {
        /// Stream ID.
        stream_id: u16,
        /// Parsed ACK frame.
        frame: SessionAckFrame,
    },
    /// Application metadata updated.
    MetadataUpdated {
        /// Stream ID.
        stream_id: u16,
        /// Parsed metadata frame.
        frame: SessionMetadataFrame,
    },
    /// Capabilities updated.
    CapabilitiesUpdated {
        /// Stream ID.
        stream_id: u16,
        /// Parsed capability frame.
        frame: SessionCapabilitiesFrame,
    },
    /// Filesystem operation is ready for a higher layer to execute.
    FilesystemAction(FilesystemAction),
    /// Non-fatal warning for degraded but authenticated output.
    Warning {
        /// Stream ID.
        stream_id: u16,
        /// Warning status code.
        status: SarStatus,
        /// Human-readable message.
        message: String,
    },
}

/// Result of processing one global header or entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessResult {
    /// Observable events emitted by the manager.
    pub events: Vec<SessionEvent>,
    /// Reverse-direction actions that would be emitted if transport existed.
    pub actions: Vec<SessionAction>,
}

/// Stateful Streaming Mode session manager.
#[derive(Debug, Clone)]
pub struct SessionManager {
    config: SessionManagerConfig,
    current_global_flags: Option<GlobalFlags>,
    activity_tick: u64,
    active_sessions: BTreeMap<u16, ActiveSession>,
}

impl SessionManager {
    /// Creates a new session manager.
    #[must_use]
    pub fn new(config: SessionManagerConfig) -> Self {
        Self {
            config,
            current_global_flags: None,
            activity_tick: 0,
            active_sessions: BTreeMap::new(),
        }
    }

    /// Observes a new archive global header.
    pub fn observe_global_header(&mut self, header: &GlobalHeader) -> Result<(), SarError> {
        validate_global_flags(header.flags)?;
        self.current_global_flags = Some(header.flags);
        Ok(())
    }

    /// Clears the current archive-context binding after archive completion.
    pub fn archive_complete(&mut self) {
        self.current_global_flags = None;
    }

    /// Returns the active session bound to `stream_id`, if any.
    #[must_use]
    pub fn active_session(&self, stream_id: u16) -> Option<&ActiveSession> {
        self.active_sessions.get(&stream_id)
    }

    /// Returns the current active session count.
    #[must_use]
    pub fn active_stream_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Processes a decoded entry.
    pub fn process_entry(&mut self, entry: &SessionEntry) -> Result<ProcessResult, SarError> {
        let global_flags = self.current_global_flags.ok_or(SarError::StreamState(
            "session manager missing current global header",
        ))?;
        validate_entry_mode_against_global(global_flags, entry.header.entry_mode)?;

        if entry.degraded && !entry.header.entry_mode.is_loss_tolerant() {
            return Err(SarError::FragmentGap(
                "degraded output without LOSS_TOLERANT is not allowed",
            ));
        }
        if entry.header.entry_mode.is_fragment() {
            self.config
                .limits
                .check_session_fragment_buffer_bytes(entry.header.uncompressed_size)?;
            let payload_len = u64::try_from(entry.payload.len())
                .map_err(|_| SarError::Overflow("payload len"))?;
            self.config
                .limits
                .check_session_fragment_buffer_bytes(payload_len)?;
        }

        if entry.header.entry_mode.is_session_control() {
            self.handle_session_control(global_flags, entry)
        } else {
            self.handle_filesystem(global_flags, entry)
        }
    }

    /// Processes an upstream parse/decode result while preserving hard errors.
    pub fn process_entry_result(
        &mut self,
        entry: Result<SessionEntry, SarError>,
    ) -> Result<ProcessResult, SarError> {
        self.process_entry(&entry?)
    }

    fn handle_session_control(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let op_code = entry.header.entry_mode.op_code();
        let op = SessionOpCode::try_from(op_code)?;
        match op {
            SessionOpCode::Init => self.handle_init(global_flags, entry),
            SessionOpCode::Close => self.handle_close(global_flags, entry),
            SessionOpCode::Resume => self.handle_resume(global_flags, entry),
            SessionOpCode::Heartbeat => self.handle_heartbeat(global_flags, entry),
            SessionOpCode::Status => self.handle_status(global_flags, entry),
            SessionOpCode::Ack => self.handle_ack(global_flags, entry),
            SessionOpCode::Metadata => self.handle_metadata(global_flags, entry),
            SessionOpCode::Capabilities => self.handle_capabilities(global_flags, entry),
        }
    }

    fn handle_init(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let frame = SessionInitFrame::parse(&entry.payload)?;
        if !global_flags.contains(GlobalFlags::NO_INDEX) || entry.header.stream_id == 0 {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        if self.active_sessions.contains_key(&entry.header.stream_id) {
            return Err(SarError::StreamState(
                "SESSION_INIT cannot reuse an already active Stream ID",
            ));
        }

        self.config
            .limits
            .check_active_streams(self.active_sessions.len().saturating_add(1))?;
        let projected_memory = self
            .total_session_memory()
            .checked_add(ACTIVE_SESSION_BASE_MEMORY_BYTES)
            .ok_or(SarError::Overflow("session memory"))?;
        self.config
            .limits
            .check_session_memory_bytes(projected_memory)?;

        let last_activity_tick = self.bump_activity_tick()?;
        self.active_sessions.insert(
            entry.header.stream_id,
            ActiveSession {
                stream_id: entry.header.stream_id,
                session_uuid: frame.session_uuid,
                session_flags: frame.flags,
                last_sequence_no: entry.header.sequence_no,
                global_flags,
                peer_capabilities: CapabilityFlags::NONE,
                metadata: None,
                last_activity_tick,
            },
        );

        Ok(ProcessResult {
            events: vec![SessionEvent::SessionActivated {
                stream_id: entry.header.stream_id,
                session_uuid: frame.session_uuid,
                flags: frame.flags,
            }],
            actions: Vec::new(),
        })
    }

    fn handle_close(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        if !entry.payload.is_empty() {
            return Err(SarError::InvalidLength(
                "SESSION_CLOSE payload must be empty",
            ));
        }

        let session_uuid = {
            let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
                Some(session) => session,
                None => {
                    return Ok(self.inactive_result(
                        entry.header.stream_id,
                        true,
                        entry.header.entry_mode.op_code(),
                    ));
                }
            };
            validate_and_advance_sequence(session, entry.header.sequence_no)?;
            session.session_uuid
        };
        self.active_sessions.remove(&entry.header.stream_id);

        let mut result = ProcessResult {
            events: vec![SessionEvent::SessionClosed {
                stream_id: entry.header.stream_id,
                session_uuid,
            }],
            actions: Vec::new(),
        };
        if self.config.local_capabilities.supports_session_ack() {
            result.actions.push(SessionAction::EmitAck {
                stream_id: entry.header.stream_id,
                frame: SessionAckFrame {
                    ref_sequence: entry.header.sequence_no,
                    flags: AckFlags::from_bits(AckFlags::ACK | AckFlags::OK | AckFlags::SUCCESS),
                },
            });
        }
        Ok(result)
    }

    fn handle_resume(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let frame = SessionResumeFrame::parse(&entry.payload)?;
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
            Some(session) => session,
            None => {
                return Ok(self.inactive_result(
                    entry.header.stream_id,
                    true,
                    entry.header.entry_mode.op_code(),
                ));
            }
        };
        validate_and_advance_sequence(session, entry.header.sequence_no)?;
        if session.session_uuid != frame.session_uuid {
            return Err(SarError::StreamState(
                "SESSION_RESUME UUID does not match active session",
            ));
        }
        if !self.config.support_resume {
            return Err(SarError::Unsupported("SESSION_RESUME is not supported"));
        }
        Ok(ProcessResult {
            events: vec![SessionEvent::SessionResumed {
                stream_id: entry.header.stream_id,
                session_uuid: frame.session_uuid,
            }],
            actions: Vec::new(),
        })
    }

    fn handle_heartbeat(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        if !entry.payload.is_empty() {
            return Err(SarError::InvalidLength(
                "SESSION_HEARTBEAT payload must be empty",
            ));
        }
        let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
            Some(session) => session,
            None => {
                return Ok(self.inactive_result(
                    entry.header.stream_id,
                    true,
                    entry.header.entry_mode.op_code(),
                ));
            }
        };
        validate_and_advance_sequence(session, entry.header.sequence_no)?;
        Ok(ProcessResult {
            events: vec![SessionEvent::Heartbeat {
                stream_id: entry.header.stream_id,
                sequence_no: entry.header.sequence_no,
            }],
            actions: Vec::new(),
        })
    }

    fn handle_status(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let frame = SessionStatusFrame::parse(&entry.payload, &self.config.limits)?;
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
            Some(session) => session,
            None => {
                return Ok(self.inactive_result(
                    entry.header.stream_id,
                    true,
                    entry.header.entry_mode.op_code(),
                ));
            }
        };
        validate_and_advance_sequence(session, entry.header.sequence_no)?;
        Ok(ProcessResult {
            events: vec![SessionEvent::Status {
                stream_id: entry.header.stream_id,
                frame,
            }],
            actions: Vec::new(),
        })
    }

    fn handle_ack(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let frame = SessionAckFrame::parse(&entry.payload)?;
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
            Some(session) => session,
            None => {
                return Ok(self.inactive_result(
                    entry.header.stream_id,
                    true,
                    entry.header.entry_mode.op_code(),
                ));
            }
        };
        validate_and_advance_sequence(session, entry.header.sequence_no)?;
        Ok(ProcessResult {
            events: vec![SessionEvent::Ack {
                stream_id: entry.header.stream_id,
                frame,
            }],
            actions: Vec::new(),
        })
    }

    fn handle_metadata(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let frame = SessionMetadataFrame::parse(&entry.payload, &self.config.limits)?;
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        let new_state = SessionMetadataState {
            content_type: frame.content_type.clone(),
            metadata: frame.metadata.clone(),
        };
        let current_total = self.total_session_memory();
        let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
            Some(session) => session,
            None => {
                return Ok(self.inactive_result(
                    entry.header.stream_id,
                    true,
                    entry.header.entry_mode.op_code(),
                ));
            }
        };
        validate_and_advance_sequence(session, entry.header.sequence_no)?;
        let old_usage = session.memory_usage();
        let mut updated = session.clone();
        updated.metadata = Some(new_state);
        let new_usage = updated.memory_usage();
        let projected_total = current_total
            .checked_sub(old_usage)
            .and_then(|value| value.checked_add(new_usage))
            .ok_or(SarError::Overflow("session memory"))?;
        self.config
            .limits
            .check_session_memory_bytes(projected_total)?;
        session.metadata = updated.metadata;
        Ok(ProcessResult {
            events: vec![SessionEvent::MetadataUpdated {
                stream_id: entry.header.stream_id,
                frame,
            }],
            actions: Vec::new(),
        })
    }

    fn handle_capabilities(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let frame = SessionCapabilitiesFrame::parse(&entry.payload)?;
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(
                entry.header.stream_id,
                true,
                entry.header.entry_mode.op_code(),
            ));
        }
        let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
            Some(session) => session,
            None => {
                return Ok(self.inactive_result(
                    entry.header.stream_id,
                    true,
                    entry.header.entry_mode.op_code(),
                ));
            }
        };
        validate_and_advance_sequence(session, entry.header.sequence_no)?;
        session.peer_capabilities = frame.flags;
        Ok(ProcessResult {
            events: vec![SessionEvent::CapabilitiesUpdated {
                stream_id: entry.header.stream_id,
                frame,
            }],
            actions: Vec::new(),
        })
    }

    fn handle_filesystem(
        &mut self,
        global_flags: GlobalFlags,
        entry: &SessionEntry,
    ) -> Result<ProcessResult, SarError> {
        let op_code = entry.header.entry_mode.op_code();
        let op = FilesystemOpCode::try_from(op_code)?;
        match op {
            FilesystemOpCode::Delete if !entry.payload.is_empty() => {
                return Err(SarError::InvalidLength("DELETE payload must be empty"));
            }
            _ => {}
        }
        if !self.should_apply_stateful(global_flags, entry.header.stream_id) {
            return Ok(self.inactive_result(entry.header.stream_id, false, op_code));
        }
        let session = match self.active_sessions.get_mut(&entry.header.stream_id) {
            Some(session) => session,
            None => {
                return Ok(self.inactive_result(entry.header.stream_id, false, op_code));
            }
        };
        validate_and_advance_sequence(session, entry.header.sequence_no)?;

        let common = FilesystemEntryAction {
            stream_id: entry.header.stream_id,
            sequence_no: entry.header.sequence_no,
            name: entry.header.name.clone(),
            path: entry.header.path.clone(),
            payload: entry.payload.clone(),
            atomic_write: entry.header.entry_mode.is_atomic_write(),
            force_sync: entry.header.entry_mode.is_force_sync(),
            loss_tolerant: entry.header.entry_mode.is_loss_tolerant(),
        };

        let action = match op {
            FilesystemOpCode::DataWrite => FilesystemAction::DataWrite(common),
            FilesystemOpCode::Delete => FilesystemAction::Delete(FilesystemDeleteAction {
                stream_id: entry.header.stream_id,
                sequence_no: entry.header.sequence_no,
                name: entry.header.name.clone(),
                path: entry.header.path.clone(),
                atomic_write: entry.header.entry_mode.is_atomic_write(),
                force_sync: entry.header.entry_mode.is_force_sync(),
            }),
            FilesystemOpCode::Rename => FilesystemAction::Rename(FilesystemRenameAction {
                stream_id: entry.header.stream_id,
                sequence_no: entry.header.sequence_no,
                old_name: entry.header.name.clone(),
                old_path: entry.header.path.clone(),
                new_path: entry.payload.clone(),
                atomic_write: entry.header.entry_mode.is_atomic_write(),
                force_sync: entry.header.entry_mode.is_force_sync(),
            }),
            FilesystemOpCode::MetaProbe => FilesystemAction::MetaProbe(common),
            FilesystemOpCode::SyncBarrier => {
                FilesystemAction::SyncBarrier(FilesystemSyncBarrierAction {
                    stream_id: entry.header.stream_id,
                    sequence_no: entry.header.sequence_no,
                    atomic_write: entry.header.entry_mode.is_atomic_write(),
                    force_sync: entry.header.entry_mode.is_force_sync(),
                })
            }
        };

        let mut events = vec![SessionEvent::FilesystemAction(action)];
        if entry.degraded {
            events.push(SessionEvent::Warning {
                stream_id: entry.header.stream_id,
                status: SarStatus::WarnIncomplete,
                message: "loss-tolerant degraded output accepted".to_string(),
            });
        }
        Ok(ProcessResult {
            events,
            actions: Vec::new(),
        })
    }

    fn inactive_result(&self, stream_id: u16, session_control: bool, op_code: u8) -> ProcessResult {
        ProcessResult {
            events: vec![SessionEvent::StatefulInactive {
                stream_id,
                op_code,
                session_control,
            }],
            actions: Vec::new(),
        }
    }

    fn should_apply_stateful(&self, global_flags: GlobalFlags, stream_id: u16) -> bool {
        global_flags.contains(GlobalFlags::NO_INDEX) && stream_id != 0
    }

    fn total_session_memory(&self) -> u64 {
        self.active_sessions.values().fold(0u64, |acc, session| {
            acc.saturating_add(session.memory_usage())
        })
    }

    fn bump_activity_tick(&mut self) -> Result<u64, SarError> {
        self.activity_tick = self
            .activity_tick
            .checked_add(1)
            .ok_or(SarError::Overflow("activity tick"))?;
        Ok(self.activity_tick)
    }
}

fn validate_and_advance_sequence(
    session: &mut ActiveSession,
    sequence_no: u16,
) -> Result<(), SarError> {
    let expected = session.last_sequence_no.wrapping_add(1);
    if sequence_no != expected {
        return Err(SarError::StreamState("sequence discontinuity detected"));
    }
    session.last_sequence_no = sequence_no;
    session.last_activity_tick = session
        .last_activity_tick
        .checked_add(1)
        .ok_or(SarError::Overflow("activity tick"))?;
    Ok(())
}
