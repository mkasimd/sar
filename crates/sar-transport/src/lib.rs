#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Transport abstraction and deterministic in-memory transport harness for SAR Stateful Streaming.
//!
//! Milestone coverage:
//! - M10c: in-memory harness, TCP/QUIC policy models, transport actions
//! - M10d: SAR-over-TCP binding ([`tcp`] module)
//! - M10e: SAR-over-QUIC binding ([`quic`] module, feature `quic`)

#[cfg(feature = "quic")]
pub mod quic;
pub mod tcp;

use std::collections::{BTreeMap, BTreeSet};

use sar_core::{
    ArchiveReaderOptions, EntryMode, GlobalHeader, ResourceLimits, SarError, SarStatus,
    StreamArchiveParser, StreamEvent, StreamStep, parse_lfh,
};
use sar_crypto::KMS_TLS_EXPORTER;
use sar_stream::{
    CapabilityFlags, ProcessResult, SessionAckFrame, SessionAction, SessionEntry, SessionEvent,
    SessionManager, SessionManagerConfig, SessionOpCode, SessionStatusFrame,
};

/// Transport binding family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportBindingKind {
    /// TCP-like policy model (no byte-interleaving of SAR streams).
    Tcp,
    /// QUIC-like policy model (independent concurrent transport streams).
    Quic,
    /// Deterministic in-memory harness binding.
    InMemory,
}

/// Transport stream identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportStreamId(pub u64);

/// Transport-level runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    /// Maximum concurrently open transport streams on one connection.
    pub max_active_transport_streams: usize,
    /// Maximum concurrently active SAR Stream IDs on one connection.
    pub max_active_sar_streams: usize,
    /// Maximum bytes accepted in a single `feed_bytes` call.
    pub max_buffered_bytes_per_transport_stream: usize,
    /// Maximum actions emitted by one operation.
    pub max_pending_actions: usize,
    /// Maximum emitted ACK/STATUS actions per operation.
    pub max_status_ack_actions: usize,
    /// Maximum remembered rejected SAR stream IDs.
    pub max_rejected_stream_ids: usize,
    /// Maximum additional control-stream attachments per SAR session (QUIC only).
    pub max_control_streams_per_sar_session: usize,
    /// Sender/receiver negotiated reverse control support.
    pub bidirectional_control: bool,
    /// Sender/receiver negotiated reverse data-stream support.
    pub bidirectional_stream: bool,
    /// Enables strict fail-closed transport policy checks.
    pub strict_validation: bool,
    /// Minimum spacing between emitted heartbeat hooks.
    pub heartbeat_min_interval_ms: u64,
    /// Heartbeat required interval.
    pub heartbeat_required_interval_ms: u64,
    /// Inactivity timeout for watchdog policy.
    pub inactivity_timeout_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_active_transport_streams: 256,
            max_active_sar_streams: ResourceLimits::default().max_active_streams,
            max_buffered_bytes_per_transport_stream: 64 * 1024,
            max_pending_actions: 128,
            max_status_ack_actions: 32,
            max_rejected_stream_ids: 1024,
            max_control_streams_per_sar_session: 4,
            bidirectional_control: true,
            bidirectional_stream: false,
            strict_validation: true,
            heartbeat_min_interval_ms: 5_000,
            heartbeat_required_interval_ms: 60_000,
            inactivity_timeout_ms: 180_000,
        }
    }
}

/// Transport stream lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportStreamState {
    /// Stream object exists but no SAR bytes consumed yet.
    Idle,
    /// Awaiting a valid SAR global header.
    AwaitingGlobalHeader,
    /// Global header consumed; first entry must activate with `SESSION_INIT`.
    AwaitingSessionInit,
    /// Stream has an active SAR binding.
    Active,
    /// Stream is closing.
    Closing,
    /// Stream is closed.
    Closed,
    /// Stream was reset.
    Reset,
    /// Stream was rejected.
    Rejected,
}

/// Transport-facing action/event output.
#[derive(Debug)]
pub enum TransportAction {
    /// Accept/open a transport stream in the harness.
    AcceptTransportStream {
        /// Transport stream ID.
        transport_stream_id: TransportStreamId,
    },
    /// Bind SAR Stream ID to a transport stream.
    BindSarStream {
        /// Transport stream ID.
        transport_stream_id: TransportStreamId,
        /// Bound SAR Stream ID.
        sar_stream_id: u16,
        /// Session UUID bound by `SESSION_INIT`.
        session_uuid: [u8; 16],
    },
    /// Attach an additional control stream to an existing SAR session (QUIC only).
    ///
    /// Emitted when a QUIC transport stream begins directly with a canonical
    /// LFH-encoded `SESSION_CONTROL` entry for an already-active SAR Stream ID.
    AttachControlStream {
        /// Control transport stream ID.
        transport_stream_id: TransportStreamId,
        /// SAR Stream ID of the existing session being attached to.
        sar_stream_id: u16,
    },
    /// Reject SAR Stream ID activation and keep it unbound.
    RejectSarStream {
        /// Transport stream ID.
        transport_stream_id: TransportStreamId,
        /// Rejection reason.
        error: SarError,
    },
    /// Reset one transport stream (QUIC-like local failure behavior).
    ResetTransportStream {
        /// Transport stream ID.
        transport_stream_id: TransportStreamId,
        /// Reset reason.
        error: SarError,
    },
    /// Close transport connection (TCP-like fatal behavior).
    CloseConnection {
        /// Close reason.
        error: SarError,
    },
    /// Discard bytes for the affected transport stream.
    DiscardBytes {
        /// Transport stream ID.
        transport_stream_id: TransportStreamId,
    },
    /// Emit session status control frame.
    EmitSessionStatus {
        /// Referenced SAR Stream ID.
        sar_stream_id: u16,
        /// Status frame from `sar-stream` type model.
        frame: SessionStatusFrame,
    },
    /// Emit session ack control frame.
    EmitSessionAck {
        /// Referenced SAR Stream ID.
        sar_stream_id: u16,
        /// ACK frame from `sar-stream` type model.
        frame: SessionAckFrame,
    },
    /// Emit heartbeat control hook.
    EmitHeartbeat {
        /// Referenced SAR Stream ID.
        sar_stream_id: u16,
    },
    /// Stream is closed and optional SAR Stream ID was detached.
    StreamClosed {
        /// Transport stream ID.
        transport_stream_id: TransportStreamId,
        /// Detached SAR Stream ID, if any.
        sar_stream_id: Option<u16>,
    },
    /// Non-fatal warning.
    Warning {
        /// Warning status code.
        status: SarStatus,
    },
}

/// TCP policy marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpPolicy;

impl TcpPolicy {
    /// Returns the binding kind represented by this policy.
    #[must_use]
    pub const fn binding_kind(self) -> TransportBindingKind {
        TransportBindingKind::Tcp
    }
}

/// QUIC policy marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuicPolicy;

impl QuicPolicy {
    /// Returns the binding kind represented by this policy.
    #[must_use]
    pub const fn binding_kind(self) -> TransportBindingKind {
        TransportBindingKind::Quic
    }
}

/// Abstract SAR transport-binding behavior.
pub trait SarTransportBinding {
    /// Returns configured binding kind.
    fn binding_kind(&self) -> TransportBindingKind;

    /// Open a transport stream.
    fn open_transport_stream(
        &mut self,
        transport_stream_id: TransportStreamId,
    ) -> Result<Vec<TransportAction>, SarError>;

    /// Feed ordered bytes to one transport stream.
    fn feed_bytes(
        &mut self,
        transport_stream_id: TransportStreamId,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<Vec<TransportAction>, SarError>;

    /// Close a transport stream.
    fn close_transport_stream(
        &mut self,
        transport_stream_id: TransportStreamId,
    ) -> Result<Vec<TransportAction>, SarError>;

    /// Reset a transport stream.
    fn reset_transport_stream(
        &mut self,
        transport_stream_id: TransportStreamId,
        reason: SarError,
    ) -> Result<Vec<TransportAction>, SarError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMode {
    Tcp,
    Quic,
}

struct TransportStreamContext {
    parser: StreamArchiveParser,
    manager: SessionManager,
    limits: ResourceLimits,
    state: TransportStreamState,
    bound_sar_stream_id: Option<u16>,
    awaiting_session_init: bool,
    peer_capabilities: CapabilityFlags,
    last_valid_activity_ms: Option<u64>,
    last_heartbeat_emit_ms: Option<u64>,
    current_global_header: Option<GlobalHeader>,
    quic_pending_bytes: Vec<u8>,
}

impl TransportStreamContext {
    fn new(config: &TransportConfig) -> Self {
        let limits = ResourceLimits {
            max_active_streams: config.max_active_sar_streams,
            ..ResourceLimits::default()
        };
        let mut local_capabilities = CapabilityFlags::NONE;
        if config.bidirectional_control {
            local_capabilities = CapabilityFlags::from_bits(
                CapabilityFlags::SESSION_ACK | CapabilityFlags::SESSION_STATUS,
            );
        }
        let manager_config = SessionManagerConfig {
            limits,
            local_capabilities,
            support_resume: false,
        };
        let parser = StreamArchiveParser::with_options(ArchiveReaderOptions {
            limits,
            delta_base: None,
        });
        Self {
            parser,
            manager: SessionManager::new(manager_config),
            limits,
            state: TransportStreamState::Idle,
            bound_sar_stream_id: None,
            awaiting_session_init: false,
            peer_capabilities: CapabilityFlags::NONE,
            last_valid_activity_ms: None,
            last_heartbeat_emit_ms: None,
            current_global_header: None,
            quic_pending_bytes: Vec::new(),
        }
    }
}

/// Deterministic in-memory transport binding/harness.
pub struct InMemoryTransport {
    config: TransportConfig,
    policy: PolicyMode,
    streams: BTreeMap<TransportStreamId, TransportStreamContext>,
    active_sar_streams: BTreeMap<u16, TransportStreamId>,
    /// Session UUIDs for active SAR stream IDs.
    active_session_uuids: BTreeMap<u16, [u8; 16]>,
    /// Canonical global headers for active SAR stream IDs.
    active_global_headers: BTreeMap<u16, GlobalHeader>,
    /// Control stream attachments (QUIC only): transport stream ID → SAR stream ID.
    control_stream_attachments: BTreeMap<TransportStreamId, u16>,
    rejected_sar_stream_ids: BTreeSet<u16>,
    connection_last_activity_ms: Option<u64>,
    /// SAR Stream IDs for which TLS_EXPORTER SAR-AEAD binding is active.
    ///
    /// After `SESSION_INIT` completes for a `KMS_TLS_EXPORTER` session, every
    /// subsequent SAR entry on the primary stream and on attached additional
    /// QUIC control streams MUST have `EntryMode::ENCRYPTED` set.  Any
    /// unencrypted entry received after binding is active is rejected with
    /// [`SarError::AuthFailed`]; the transport never falls back to plaintext.
    tls_exporter_bound: BTreeSet<u16>,
}

impl InMemoryTransport {
    /// Create a TCP-like in-memory transport model.
    #[must_use]
    pub fn new_tcp(config: TransportConfig) -> Self {
        Self {
            config,
            policy: PolicyMode::Tcp,
            streams: BTreeMap::new(),
            active_sar_streams: BTreeMap::new(),
            active_session_uuids: BTreeMap::new(),
            active_global_headers: BTreeMap::new(),
            control_stream_attachments: BTreeMap::new(),
            rejected_sar_stream_ids: BTreeSet::new(),
            connection_last_activity_ms: None,
            tls_exporter_bound: BTreeSet::new(),
        }
    }

    /// Create a QUIC-like in-memory transport model.
    #[must_use]
    pub fn new_quic(config: TransportConfig) -> Self {
        Self {
            config,
            policy: PolicyMode::Quic,
            streams: BTreeMap::new(),
            active_sar_streams: BTreeMap::new(),
            active_session_uuids: BTreeMap::new(),
            active_global_headers: BTreeMap::new(),
            control_stream_attachments: BTreeMap::new(),
            rejected_sar_stream_ids: BTreeSet::new(),
            connection_last_activity_ms: None,
            tls_exporter_bound: BTreeSet::new(),
        }
    }

    /// Returns the effective policy mode.
    #[must_use]
    pub fn policy_kind(&self) -> TransportBindingKind {
        match self.policy {
            PolicyMode::Tcp => TransportBindingKind::Tcp,
            PolicyMode::Quic => TransportBindingKind::Quic,
        }
    }

    /// Returns active transport stream count.
    #[must_use]
    pub fn active_transport_stream_count(&self) -> usize {
        self.streams
            .values()
            .filter(|context| {
                !matches!(
                    context.state,
                    TransportStreamState::Closed
                        | TransportStreamState::Reset
                        | TransportStreamState::Rejected
                )
            })
            .count()
    }

    /// Returns active SAR stream count.
    #[must_use]
    pub fn active_sar_stream_count(&self) -> usize {
        self.active_sar_streams.len()
    }

    /// Returns true when SAR Stream ID is currently bound.
    #[must_use]
    pub fn is_sar_stream_bound(&self, sar_stream_id: u16) -> bool {
        self.active_sar_streams.contains_key(&sar_stream_id)
    }

    /// Returns `true` when TLS_EXPORTER SAR-AEAD binding is active for the
    /// given SAR Stream ID (i.e. `SESSION_INIT` was processed and all further
    /// entries must be encrypted).
    #[must_use]
    pub fn is_tls_exporter_bound(&self, sar_stream_id: u16) -> bool {
        self.tls_exporter_bound.contains(&sar_stream_id)
    }

    /// Returns the session UUID for an active SAR stream, if known.
    #[must_use]
    pub fn session_uuid_for(&self, sar_stream_id: u16) -> Option<[u8; 16]> {
        self.active_session_uuids.get(&sar_stream_id).copied()
    }

    /// Returns true if the transport stream is a control attachment (QUIC only).
    #[must_use]
    pub fn is_control_stream(&self, transport_stream_id: TransportStreamId) -> bool {
        self.control_stream_attachments
            .contains_key(&transport_stream_id)
    }

    /// Returns the SAR stream ID that the given transport stream is attached to
    /// as a control stream, if applicable.
    #[must_use]
    pub fn control_sar_stream_id(&self, transport_stream_id: TransportStreamId) -> Option<u16> {
        self.control_stream_attachments
            .get(&transport_stream_id)
            .copied()
    }

    /// Returns current state for a transport stream.
    #[must_use]
    pub fn transport_stream_state(
        &self,
        transport_stream_id: TransportStreamId,
    ) -> Option<TransportStreamState> {
        self.streams
            .get(&transport_stream_id)
            .map(|context| context.state)
    }

    /// Records valid LFH activity using explicit time input.
    pub fn record_valid_activity(
        &mut self,
        transport_stream_id: TransportStreamId,
        now_ms: u64,
    ) -> Result<(), SarError> {
        let context = self
            .streams
            .get_mut(&transport_stream_id)
            .ok_or(SarError::NotFound("unknown transport stream"))?;
        context.last_valid_activity_ms = Some(now_ms);
        self.connection_last_activity_ms = Some(now_ms);
        Ok(())
    }

    /// Checks inactivity watchdog using explicit time input.
    pub fn check_inactivity(&self, now_ms: u64) -> Result<Vec<TransportAction>, SarError> {
        if let Some(last) = self.connection_last_activity_ms
            && now_ms.saturating_sub(last) > self.config.inactivity_timeout_ms
        {
            return Err(SarError::Timeout("transport inactivity watchdog expired"));
        }
        Ok(Vec::new())
    }

    /// Returns heartbeat actions based on explicit-time policy.
    pub fn maybe_emit_heartbeat(
        &mut self,
        transport_stream_id: TransportStreamId,
        now_ms: u64,
    ) -> Result<Vec<TransportAction>, SarError> {
        let context = self
            .streams
            .get_mut(&transport_stream_id)
            .ok_or(SarError::NotFound("unknown transport stream"))?;
        let Some(sar_stream_id) = context.bound_sar_stream_id else {
            return Ok(Vec::new());
        };

        let last = context.last_heartbeat_emit_ms.unwrap_or(0);
        if now_ms.saturating_sub(last) < self.config.heartbeat_min_interval_ms {
            return Ok(Vec::new());
        }
        let Some(last_activity) = context.last_valid_activity_ms else {
            return Ok(Vec::new());
        };
        if now_ms.saturating_sub(last_activity) < self.config.heartbeat_required_interval_ms {
            return Ok(Vec::new());
        }
        context.last_heartbeat_emit_ms = Some(now_ms);
        Ok(vec![TransportAction::EmitHeartbeat { sar_stream_id }])
    }

    fn ensure_tcp_not_interleaved(&self) -> Result<(), SarError> {
        if self.policy != PolicyMode::Tcp {
            return Ok(());
        }
        if self.active_transport_stream_count() > 1 {
            return Err(SarError::StreamState(
                "TCP policy forbids concurrent transport streams",
            ));
        }
        Ok(())
    }

    fn push_action(
        config: &TransportConfig,
        actions: &mut Vec<TransportAction>,
        action: TransportAction,
    ) -> Result<(), SarError> {
        if actions.len() >= config.max_pending_actions {
            return Err(SarError::LimitExceeded(
                "transport pending action limit exceeded",
            ));
        }
        actions.push(action);
        Ok(())
    }

    fn count_status_ack_actions(actions: &[TransportAction]) -> usize {
        actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    TransportAction::EmitSessionStatus { .. }
                        | TransportAction::EmitSessionAck { .. }
                )
            })
            .count()
    }

    fn maybe_emit_status_action(
        config: &TransportConfig,
        actions: &mut Vec<TransportAction>,
        sar_stream_id: u16,
        status: SarStatus,
        ref_sequence: u16,
        message: &'static str,
    ) -> Result<(), SarError> {
        if !config.bidirectional_control {
            return Ok(());
        }
        if Self::count_status_ack_actions(actions) >= config.max_status_ack_actions {
            return Err(SarError::LimitExceeded(
                "transport status/ack action limit exceeded",
            ));
        }
        Self::push_action(
            config,
            actions,
            TransportAction::EmitSessionStatus {
                sar_stream_id,
                frame: SessionStatusFrame {
                    ref_sequence,
                    status,
                    message: message.as_bytes().to_vec(),
                },
            },
        )
    }

    fn error_from_status(status: SarStatus) -> SarError {
        match status {
            SarStatus::ErrTooManyStreams => SarError::TooManyStreams("transport policy rejection"),
            SarStatus::ErrFlagConflict => SarError::FlagConflict("transport policy rejection"),
            SarStatus::ErrTimeout => SarError::Timeout("transport policy rejection"),
            SarStatus::ErrLimitExceeded => SarError::LimitExceeded("transport policy rejection"),
            SarStatus::ErrStreamState => SarError::StreamState("transport policy rejection"),
            _ => SarError::StreamState("transport policy rejection"),
        }
    }

    fn reject_stream_with_policy(
        &mut self,
        transport_stream_id: TransportStreamId,
        sar_stream_id: Option<u16>,
        error: SarError,
        ref_sequence: u16,
        actions: &mut Vec<TransportAction>,
    ) -> Result<(), SarError> {
        if let Some(id) = sar_stream_id {
            if self.rejected_sar_stream_ids.len() >= self.config.max_rejected_stream_ids
                && !self.rejected_sar_stream_ids.contains(&id)
            {
                return Err(SarError::LimitExceeded(
                    "transport rejected stream tracking limit exceeded",
                ));
            }
            self.rejected_sar_stream_ids.insert(id);
        }

        Self::push_action(
            &self.config,
            actions,
            TransportAction::RejectSarStream {
                transport_stream_id,
                error,
            },
        )?;

        let status = actions
            .iter()
            .rev()
            .find_map(|action| match action {
                TransportAction::RejectSarStream { error, .. } => Some(error.status()),
                _ => None,
            })
            .unwrap_or(SarStatus::ErrStreamState);

        if let Some(id) = sar_stream_id {
            Self::maybe_emit_status_action(
                &self.config,
                actions,
                id,
                status,
                ref_sequence,
                "stream rejected by transport policy",
            )?;
        }

        match self.policy {
            PolicyMode::Tcp => {
                Self::push_action(
                    &self.config,
                    actions,
                    TransportAction::DiscardBytes {
                        transport_stream_id,
                    },
                )?;
                Self::push_action(
                    &self.config,
                    actions,
                    TransportAction::CloseConnection {
                        error: Self::error_from_status(status),
                    },
                )?;
                if let Some(context) = self.streams.get_mut(&transport_stream_id) {
                    context.state = TransportStreamState::Rejected;
                }
            }
            PolicyMode::Quic => {
                Self::push_action(
                    &self.config,
                    actions,
                    TransportAction::ResetTransportStream {
                        transport_stream_id,
                        error: Self::error_from_status(status),
                    },
                )?;
                if let Some(context) = self.streams.get_mut(&transport_stream_id) {
                    context.state = TransportStreamState::Reset;
                }
            }
        }
        Ok(())
    }

    fn additional_control_header_size(bytes: &[u8]) -> Option<usize> {
        (bytes.len() >= 4).then(|| {
            usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])).ok()
        })?
    }

    fn validate_additional_control_entry(
        bidirectional_control: bool,
        attached_sar_stream_id: u16,
        entry: &SessionEntry,
    ) -> Result<(), SarError> {
        if entry.header.stream_id != attached_sar_stream_id {
            return Err(SarError::StreamState(
                "additional control stream Stream ID does not match attached SAR session",
            ));
        }
        if !entry.header.entry_mode.is_session_control() {
            return Err(SarError::StreamState(
                "filesystem entries are not permitted on additional QUIC control streams",
            ));
        }
        let op = SessionOpCode::try_from(entry.header.entry_mode.op_code())?;
        match op {
            SessionOpCode::Init => Err(SarError::StreamState(
                "SESSION_INIT is not permitted on an additional QUIC control stream",
            )),
            SessionOpCode::Ack | SessionOpCode::Status | SessionOpCode::Capabilities => {
                if bidirectional_control {
                    Ok(())
                } else {
                    Err(SarError::StreamState(
                        "bidirectional control is unavailable for additional QUIC control streams",
                    ))
                }
            }
            _ => Err(SarError::StreamState(
                "session-control opcode is not permitted on an additional QUIC control stream",
            )),
        }
    }

    fn run_additional_control_stream_loop(
        &mut self,
        transport_stream_id: TransportStreamId,
        now_ms: Option<u64>,
        mut actions: Vec<TransportAction>,
    ) -> Result<Vec<TransportAction>, SarError> {
        loop {
            enum ControlLoopEvent {
                NeedMore,
                SessionResult {
                    sequence_no: u16,
                    result: Result<ProcessResult, SarError>,
                },
                ParserError(SarError),
            }

            let loop_event = {
                let Some(attached_sar_stream_id) = self
                    .control_stream_attachments
                    .get(&transport_stream_id)
                    .copied()
                else {
                    return Err(SarError::Internal(
                        "additional control stream loop missing attachment",
                    ));
                };
                let Some(active_header) = self.active_global_headers.get(&attached_sar_stream_id)
                else {
                    return Err(SarError::Internal(
                        "additional control stream missing active global header",
                    ));
                };
                let active_flags = active_header.flags;
                let bidirectional_control = self.config.bidirectional_control;
                let context = self
                    .streams
                    .get_mut(&transport_stream_id)
                    .ok_or(SarError::NotFound("unknown transport stream"))?;

                if context.quic_pending_bytes.len() < 4 {
                    ControlLoopEvent::NeedMore
                } else {
                    match Self::additional_control_header_size(&context.quic_pending_bytes) {
                        None => {
                            ControlLoopEvent::ParserError(SarError::Overflow("LFH header size"))
                        }
                        Some(header_size) => {
                            if let Err(err) = context.limits.check_lfh_header_bytes(header_size) {
                                ControlLoopEvent::ParserError(err)
                            } else if context.quic_pending_bytes.len() < header_size {
                                ControlLoopEvent::NeedMore
                            } else {
                                match parse_lfh(
                                    &context.quic_pending_bytes[..header_size],
                                    &active_flags,
                                    &context.limits,
                                ) {
                                    Ok((lfh, _)) => match usize::try_from(lfh.payload_size) {
                                        Err(_) => ControlLoopEvent::ParserError(
                                            SarError::Overflow("additional control payload size"),
                                        ),
                                        Ok(payload_size) => {
                                            match header_size.checked_add(payload_size) {
                                                None => ControlLoopEvent::ParserError(
                                                    SarError::Overflow(
                                                        "additional control entry size",
                                                    ),
                                                ),
                                                Some(total_size) => {
                                                    if context.quic_pending_bytes.len() < total_size
                                                    {
                                                        ControlLoopEvent::NeedMore
                                                    } else {
                                                        let entry = SessionEntry {
                                                            header: lfh,
                                                            payload: context.quic_pending_bytes
                                                                [header_size..total_size]
                                                                .to_vec(),
                                                            degraded: false,
                                                        };
                                                        let validation =
                                                            Self::validate_additional_control_entry(
                                                                bidirectional_control,
                                                                attached_sar_stream_id,
                                                                &entry,
                                                            );
                                                        if let Err(err) = validation {
                                                            ControlLoopEvent::ParserError(err)
                                                        } else if self
                                                            .tls_exporter_bound
                                                            .contains(&attached_sar_stream_id)
                                                            && !entry
                                                                .header
                                                                .entry_mode
                                                                .is_encrypted()
                                                        {
                                                            // TLS_EXPORTER binding is active for
                                                            // the attached session; plaintext
                                                            // entries on additional control streams
                                                            // are rejected as an authentication
                                                            // failure.
                                                            ControlLoopEvent::ParserError(
                                                                SarError::AuthFailed(
                                                                    "TLS_EXPORTER binding active: \
                                                                     unencrypted additional control \
                                                                     stream entry rejected",
                                                                ),
                                                            )
                                                        } else {
                                                            context
                                                                .quic_pending_bytes
                                                                .drain(..total_size);
                                                            if let Some(now) = now_ms {
                                                                context.last_valid_activity_ms =
                                                                    Some(now);
                                                                self.connection_last_activity_ms =
                                                                    Some(now);
                                                            }
                                                            let sequence_no =
                                                                entry.header.sequence_no;
                                                            let result = context
                                                                .manager
                                                                .process_entry(&entry);
                                                            ControlLoopEvent::SessionResult {
                                                                sequence_no,
                                                                result,
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    Err(err) => ControlLoopEvent::ParserError(err),
                                }
                            }
                        }
                    }
                }
            };

            match loop_event {
                ControlLoopEvent::NeedMore => break,
                ControlLoopEvent::SessionResult {
                    sequence_no,
                    result,
                } => match result {
                    Ok(result) => {
                        self.process_session_result(
                            transport_stream_id,
                            result,
                            sequence_no,
                            &mut actions,
                        )?;
                    }
                    Err(err) => {
                        self.policy_error_actions(transport_stream_id, err, &mut actions)?;
                        break;
                    }
                },
                ControlLoopEvent::ParserError(err) => {
                    self.policy_error_actions(transport_stream_id, err, &mut actions)?;
                    break;
                }
            }
        }

        Ok(actions)
    }

    fn process_session_result(
        &mut self,
        transport_stream_id: TransportStreamId,
        result: ProcessResult,
        header_sequence: u16,
        actions: &mut Vec<TransportAction>,
    ) -> Result<(), SarError> {
        let mut close_stream: Option<Option<u16>> = None;

        for action in result.actions {
            match action {
                SessionAction::EmitAck { stream_id, frame } => {
                    if !self.config.bidirectional_control {
                        continue;
                    }
                    let Some(context) = self.streams.get(&transport_stream_id) else {
                        continue;
                    };
                    if !context.peer_capabilities.supports_session_ack() {
                        continue;
                    }
                    if Self::count_status_ack_actions(actions) >= self.config.max_status_ack_actions
                    {
                        return Err(SarError::LimitExceeded(
                            "transport status/ack action limit exceeded",
                        ));
                    }
                    Self::push_action(
                        &self.config,
                        actions,
                        TransportAction::EmitSessionAck {
                            sar_stream_id: stream_id,
                            frame,
                        },
                    )?;
                }
            }
        }

        for event in result.events {
            match event {
                SessionEvent::SessionActivated {
                    stream_id,
                    session_uuid,
                    flags,
                } => {
                    if stream_id == 0 {
                        self.reject_stream_with_policy(
                            transport_stream_id,
                            Some(stream_id),
                            SarError::StreamState("stream id 0 cannot be bound"),
                            header_sequence,
                            actions,
                        )?;
                        continue;
                    }

                    if self.active_sar_streams.contains_key(&stream_id) {
                        self.reject_stream_with_policy(
                            transport_stream_id,
                            Some(stream_id),
                            SarError::StreamState("duplicate active SAR Stream ID"),
                            header_sequence,
                            actions,
                        )?;
                        continue;
                    }
                    if self.active_sar_streams.len() >= self.config.max_active_sar_streams {
                        self.reject_stream_with_policy(
                            transport_stream_id,
                            Some(stream_id),
                            SarError::TooManyStreams("too many active SAR streams"),
                            header_sequence,
                            actions,
                        )?;
                        continue;
                    }

                    if self.config.strict_validation {
                        if flags.bidirectional_stream_required()
                            && !self.config.bidirectional_stream
                        {
                            self.reject_stream_with_policy(
                                transport_stream_id,
                                Some(stream_id),
                                SarError::FlagConflict(
                                    "bidirectional stream required but unsupported",
                                ),
                                header_sequence,
                                actions,
                            )?;
                            continue;
                        }
                        if flags.bidirectional_control_required()
                            && !self.config.bidirectional_control
                        {
                            self.reject_stream_with_policy(
                                transport_stream_id,
                                Some(stream_id),
                                SarError::FlagConflict(
                                    "bidirectional control required but unsupported",
                                ),
                                header_sequence,
                                actions,
                            )?;
                            continue;
                        }
                    }

                    self.active_sar_streams
                        .insert(stream_id, transport_stream_id);
                    self.active_session_uuids.insert(stream_id, session_uuid);
                    if let Some(header) = self
                        .streams
                        .get(&transport_stream_id)
                        .and_then(|context| context.current_global_header.clone())
                    {
                        // Activate TLS_EXPORTER SAR-AEAD binding when the
                        // global header used KMS Mode 0x04.  From this point
                        // all entries on this SAR stream (including entries on
                        // attached additional QUIC control streams) MUST have
                        // EntryMode::ENCRYPTED set; unencrypted entries are
                        // rejected with SarError::AuthFailed.
                        if header
                            .kms
                            .as_ref()
                            .map(|k| k.mode_id == KMS_TLS_EXPORTER)
                            .unwrap_or(false)
                        {
                            self.tls_exporter_bound.insert(stream_id);
                        }
                        self.active_global_headers.insert(stream_id, header);
                    }
                    // Clear pending state regardless of whether TLS_EXPORTER
                    // was active (idempotent remove).
                    if let Some(context) = self.streams.get_mut(&transport_stream_id) {
                        context.state = TransportStreamState::Active;
                        context.bound_sar_stream_id = Some(stream_id);
                        context.awaiting_session_init = false;
                    }
                    Self::push_action(
                        &self.config,
                        actions,
                        TransportAction::BindSarStream {
                            transport_stream_id,
                            sar_stream_id: stream_id,
                            session_uuid,
                        },
                    )?;
                }
                SessionEvent::SessionClosed {
                    stream_id,
                    session_uuid: _,
                } => {
                    self.active_sar_streams.remove(&stream_id);
                    self.active_session_uuids.remove(&stream_id);
                    self.active_global_headers.remove(&stream_id);
                    self.tls_exporter_bound.remove(&stream_id);
                    // Detach any control streams for this session.
                    self.control_stream_attachments
                        .retain(|_, &mut sid| sid != stream_id);
                    if let Some(context) = self.streams.get_mut(&transport_stream_id) {
                        context.bound_sar_stream_id = None;
                        context.state = TransportStreamState::Closing;
                    }
                    close_stream = Some(Some(stream_id));
                }
                SessionEvent::CapabilitiesUpdated {
                    stream_id: _,
                    frame,
                } => {
                    if let Some(context) = self.streams.get_mut(&transport_stream_id) {
                        context.peer_capabilities = frame.flags;
                    }
                }
                SessionEvent::Warning {
                    stream_id: _,
                    status,
                    message: _,
                } => {
                    Self::push_action(&self.config, actions, TransportAction::Warning { status })?;
                }
                SessionEvent::StatefulInactive {
                    stream_id,
                    op_code: _,
                    session_control: _,
                } => {
                    if let Some(context) = self.streams.get(&transport_stream_id)
                        && context.awaiting_session_init
                    {
                        self.reject_stream_with_policy(
                            transport_stream_id,
                            Some(stream_id),
                            SarError::StreamState(
                                "global header not followed by valid SESSION_INIT",
                            ),
                            header_sequence,
                            actions,
                        )?;
                    }
                }
                SessionEvent::Status { .. }
                | SessionEvent::Ack { .. }
                | SessionEvent::MetadataUpdated { .. }
                | SessionEvent::SessionResumed { .. }
                | SessionEvent::Heartbeat { .. }
                | SessionEvent::FilesystemAction(_) => {}
            }
        }

        if let Some(sar_stream_id) = close_stream {
            Self::push_action(
                &self.config,
                actions,
                TransportAction::StreamClosed {
                    transport_stream_id,
                    sar_stream_id,
                },
            )?;
            if let Some(context) = self.streams.get_mut(&transport_stream_id) {
                context.state = TransportStreamState::AwaitingGlobalHeader;
            }
        }

        Ok(())
    }

    fn policy_error_actions(
        &mut self,
        transport_stream_id: TransportStreamId,
        error: SarError,
        actions: &mut Vec<TransportAction>,
    ) -> Result<(), SarError> {
        let current_sar = self
            .streams
            .get(&transport_stream_id)
            .and_then(|context| context.bound_sar_stream_id);
        self.reject_stream_with_policy(transport_stream_id, current_sar, error, 0, actions)
    }

    /// Inner loop that steps the SAR stream parser and processes session events.
    fn run_feed_loop(
        &mut self,
        transport_stream_id: TransportStreamId,
        now_ms: Option<u64>,
        mut actions: Vec<TransportAction>,
    ) -> Result<Vec<TransportAction>, SarError> {
        loop {
            enum LoopEvent {
                NeedMore,
                Complete,
                Continue,
                SessionResult {
                    sequence_no: u16,
                    result: Result<ProcessResult, SarError>,
                },
                ParserError(SarError),
            }

            let step_event = {
                let is_additional_control_stream = self
                    .control_stream_attachments
                    .contains_key(&transport_stream_id);
                let context = self
                    .streams
                    .get_mut(&transport_stream_id)
                    .ok_or(SarError::NotFound("unknown transport stream"))?;
                match context.parser.step() {
                    Ok(StreamStep::NeedMore { .. }) => LoopEvent::NeedMore,
                    Ok(StreamStep::Complete) => LoopEvent::Complete,
                    Ok(StreamStep::Ready(StreamEvent::GlobalHeader(header))) => {
                        context.current_global_header = Some((*header).clone());
                        // TCP does not support TLS_EXPORTER KMS mode.  Reject
                        // immediately on global header to prevent partial
                        // session setup before the failure would otherwise
                        // surface during CEK derivation.
                        if self.policy == PolicyMode::Tcp {
                            if let Some(kms) = &header.kms {
                                if kms.mode_id == KMS_TLS_EXPORTER {
                                    LoopEvent::ParserError(SarError::Unsupported(
                                        "KMS_TLS_EXPORTER is not supported over plaintext TCP",
                                    ))
                                } else if let Err(err) =
                                    context.manager.observe_global_header(&header)
                                {
                                    LoopEvent::ParserError(err)
                                } else {
                                    context.state = TransportStreamState::AwaitingSessionInit;
                                    context.awaiting_session_init = true;
                                    LoopEvent::Continue
                                }
                            } else if let Err(err) = context.manager.observe_global_header(&header)
                            {
                                LoopEvent::ParserError(err)
                            } else {
                                context.state = TransportStreamState::AwaitingSessionInit;
                                context.awaiting_session_init = true;
                                LoopEvent::Continue
                            }
                        } else if let Err(err) = context.manager.observe_global_header(&header) {
                            LoopEvent::ParserError(err)
                        } else {
                            // For additional control streams the session is already
                            // active; `SESSION_INIT` is not expected.
                            context.state = TransportStreamState::AwaitingSessionInit;
                            context.awaiting_session_init = !is_additional_control_stream;
                            LoopEvent::Continue
                        }
                    }
                    Ok(StreamStep::Ready(StreamEvent::Entry(entry))) => {
                        if let Some(now) = now_ms {
                            context.last_valid_activity_ms = Some(now);
                            self.connection_last_activity_ms = Some(now);
                        }
                        let sequence_no = entry.header.sequence_no;
                        // TLS_EXPORTER post-binding enforcement: after SESSION_INIT
                        // binds the session, every subsequent entry MUST carry
                        // EntryMode::ENCRYPTED.  Plaintext entries received after
                        // binding is active are a hard authentication failure.
                        if let Some(sar_stream_id) = context.bound_sar_stream_id {
                            if self.tls_exporter_bound.contains(&sar_stream_id)
                                && !entry.header.entry_mode.is_encrypted()
                            {
                                LoopEvent::ParserError(SarError::AuthFailed(
                                    "TLS_EXPORTER binding active: \
                                     unencrypted SAR entry rejected post-binding",
                                ))
                            } else {
                                let result = context
                                    .manager
                                    .process_entry(&SessionEntry::from_entry_reader(*entry));
                                LoopEvent::SessionResult {
                                    sequence_no,
                                    result,
                                }
                            }
                        } else {
                            let result = context
                                .manager
                                .process_entry(&SessionEntry::from_entry_reader(*entry));
                            LoopEvent::SessionResult {
                                sequence_no,
                                result,
                            }
                        }
                    }
                    Ok(StreamStep::Ready(StreamEvent::ArchiveComplete(_))) => {
                        context.manager.archive_complete();
                        context.state = TransportStreamState::AwaitingGlobalHeader;
                        context.awaiting_session_init = false;
                        LoopEvent::Continue
                    }
                    Err(err) => LoopEvent::ParserError(err),
                }
            };

            match step_event {
                LoopEvent::NeedMore | LoopEvent::Complete => break,
                LoopEvent::Continue => continue,
                LoopEvent::SessionResult {
                    sequence_no,
                    result,
                } => match result {
                    Ok(result) => {
                        self.process_session_result(
                            transport_stream_id,
                            result,
                            sequence_no,
                            &mut actions,
                        )?;
                    }
                    Err(err) => {
                        self.policy_error_actions(transport_stream_id, err, &mut actions)?;
                        break;
                    }
                },
                LoopEvent::ParserError(err) => {
                    self.policy_error_actions(transport_stream_id, err, &mut actions)?;
                    break;
                }
            }
        }
        Ok(actions)
    }
}

impl SarTransportBinding for InMemoryTransport {
    fn binding_kind(&self) -> TransportBindingKind {
        TransportBindingKind::InMemory
    }

    fn open_transport_stream(
        &mut self,
        transport_stream_id: TransportStreamId,
    ) -> Result<Vec<TransportAction>, SarError> {
        if self.streams.contains_key(&transport_stream_id) {
            return Err(SarError::StreamState("transport stream id already exists"));
        }
        if self.active_transport_stream_count() >= self.config.max_active_transport_streams {
            return Err(SarError::TooManyStreams(
                "too many active transport streams for connection",
            ));
        }
        self.streams.insert(
            transport_stream_id,
            TransportStreamContext::new(&self.config),
        );
        if let Some(context) = self.streams.get_mut(&transport_stream_id) {
            context.state = TransportStreamState::AwaitingGlobalHeader;
        }

        let mut actions = Vec::new();
        Self::push_action(
            &self.config,
            &mut actions,
            TransportAction::AcceptTransportStream {
                transport_stream_id,
            },
        )?;

        self.ensure_tcp_not_interleaved().or_else(|err| {
            self.policy_error_actions(transport_stream_id, err, &mut actions)?;
            Ok::<(), SarError>(())
        })?;

        Ok(actions)
    }

    fn feed_bytes(
        &mut self,
        transport_stream_id: TransportStreamId,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<Vec<TransportAction>, SarError> {
        if bytes.len() > self.config.max_buffered_bytes_per_transport_stream {
            return Err(SarError::LimitExceeded(
                "feed bytes exceed configured per-stream buffer bound",
            ));
        }

        let mut actions = Vec::new();

        if self.policy == PolicyMode::Quic {
            let (current_state, is_attached) = {
                let context = self
                    .streams
                    .get(&transport_stream_id)
                    .ok_or(SarError::NotFound("unknown transport stream"))?;
                (
                    context.state,
                    self.control_stream_attachments
                        .contains_key(&transport_stream_id),
                )
            };

            if is_attached {
                let context = self
                    .streams
                    .get_mut(&transport_stream_id)
                    .ok_or(SarError::NotFound("unknown transport stream"))?;
                context.quic_pending_bytes.extend_from_slice(bytes);
                return self.run_additional_control_stream_loop(
                    transport_stream_id,
                    now_ms,
                    actions,
                );
            }

            if current_state == TransportStreamState::AwaitingGlobalHeader {
                let context = self
                    .streams
                    .get_mut(&transport_stream_id)
                    .ok_or(SarError::NotFound("unknown transport stream"))?;
                context.quic_pending_bytes.extend_from_slice(bytes);

                let pending = context.quic_pending_bytes.clone();
                if pending.len() < 4 {
                    return Ok(actions);
                }
                if pending.starts_with(b"SAR!") {
                    if let Err(err) = context.parser.push_bytes(&pending) {
                        self.policy_error_actions(transport_stream_id, err, &mut actions)?;
                        return Ok(actions);
                    }
                    context.quic_pending_bytes.clear();
                    return self.run_feed_loop(transport_stream_id, now_ms, actions);
                }
                if pending.starts_with(b"CTL!") {
                    self.policy_error_actions(
                        transport_stream_id,
                        SarError::InvalidMagic,
                        &mut actions,
                    )?;
                    return Ok(actions);
                }
                if pending.len() < 8 {
                    return Ok(actions);
                }

                let entry_mode = EntryMode::from_bits(u16::from_le_bytes([pending[4], pending[5]]));
                let sar_stream_id = u16::from_le_bytes([pending[6], pending[7]]);

                if !entry_mode.is_session_control() {
                    self.policy_error_actions(
                        transport_stream_id,
                        SarError::InvalidMagic,
                        &mut actions,
                    )?;
                    return Ok(actions);
                }
                if !self.active_sar_streams.contains_key(&sar_stream_id) {
                    self.policy_error_actions(
                        transport_stream_id,
                        SarError::StreamState(
                            "additional control stream references unknown SAR Stream ID",
                        ),
                        &mut actions,
                    )?;
                    return Ok(actions);
                }
                let control_count = self
                    .control_stream_attachments
                    .values()
                    .filter(|&&sid| sid == sar_stream_id)
                    .count();
                if control_count >= self.config.max_control_streams_per_sar_session {
                    self.policy_error_actions(
                        transport_stream_id,
                        SarError::LimitExceeded("too many control streams for SAR session"),
                        &mut actions,
                    )?;
                    return Ok(actions);
                }

                self.control_stream_attachments
                    .insert(transport_stream_id, sar_stream_id);
                context.state = TransportStreamState::Active;
                context.bound_sar_stream_id = Some(sar_stream_id);
                context.awaiting_session_init = false;
                context.manager.observe_global_header(
                    self.active_global_headers
                        .get(&sar_stream_id)
                        .ok_or(SarError::Internal("active global header missing"))?,
                )?;
                Self::push_action(
                    &self.config,
                    &mut actions,
                    TransportAction::AttachControlStream {
                        transport_stream_id,
                        sar_stream_id,
                    },
                )?;
                return self.run_additional_control_stream_loop(
                    transport_stream_id,
                    now_ms,
                    actions,
                );
            }
        }
        // ── Normal SAR stream path ────────────────────────────────────────────
        {
            let context = self
                .streams
                .get_mut(&transport_stream_id)
                .ok_or(SarError::NotFound("unknown transport stream"))?;
            if matches!(
                context.state,
                TransportStreamState::Closed
                    | TransportStreamState::Reset
                    | TransportStreamState::Rejected
            ) {
                return Err(SarError::StreamClosed(
                    "cannot feed bytes to closed/reset/rejected transport stream",
                ));
            }
            context.parser.push_bytes(bytes)?;
        }

        self.run_feed_loop(transport_stream_id, now_ms, actions)
    }

    fn close_transport_stream(
        &mut self,
        transport_stream_id: TransportStreamId,
    ) -> Result<Vec<TransportAction>, SarError> {
        let context = self
            .streams
            .get_mut(&transport_stream_id)
            .ok_or(SarError::NotFound("unknown transport stream"))?;

        let detached = context.bound_sar_stream_id;
        if let Some(sar_stream_id) = detached {
            // Only remove primary binding (not control attachments).
            if !self
                .control_stream_attachments
                .contains_key(&transport_stream_id)
            {
                self.active_sar_streams.remove(&sar_stream_id);
                self.active_session_uuids.remove(&sar_stream_id);
                self.tls_exporter_bound.remove(&sar_stream_id);
                // Detach any control streams for this session.
                self.control_stream_attachments
                    .retain(|_, &mut sid| sid != sar_stream_id);
            }
        }
        // Remove this stream from control attachments if it is one.
        self.control_stream_attachments.remove(&transport_stream_id);

        context.state = TransportStreamState::Closed;
        let mut actions = Vec::new();
        Self::push_action(
            &self.config,
            &mut actions,
            TransportAction::StreamClosed {
                transport_stream_id,
                sar_stream_id: detached,
            },
        )?;
        Ok(actions)
    }

    fn reset_transport_stream(
        &mut self,
        transport_stream_id: TransportStreamId,
        reason: SarError,
    ) -> Result<Vec<TransportAction>, SarError> {
        let context = self
            .streams
            .get_mut(&transport_stream_id)
            .ok_or(SarError::NotFound("unknown transport stream"))?;
        let detached = context.bound_sar_stream_id;
        if let Some(sar_stream_id) = detached
            && !self
                .control_stream_attachments
                .contains_key(&transport_stream_id)
        {
            self.active_sar_streams.remove(&sar_stream_id);
            self.active_session_uuids.remove(&sar_stream_id);
            self.tls_exporter_bound.remove(&sar_stream_id);
            self.control_stream_attachments
                .retain(|_, &mut sid| sid != sar_stream_id);
        }
        self.control_stream_attachments.remove(&transport_stream_id);
        context.state = TransportStreamState::Reset;

        let mut actions = Vec::new();
        Self::push_action(
            &self.config,
            &mut actions,
            TransportAction::ResetTransportStream {
                transport_stream_id,
                error: reason,
            },
        )?;
        Self::push_action(
            &self.config,
            &mut actions,
            TransportAction::StreamClosed {
                transport_stream_id,
                sar_stream_id: detached,
            },
        )?;
        Ok(actions)
    }
}

/// Convenience deterministic harness that accumulates transport actions.
pub struct TransportHarness {
    binding: InMemoryTransport,
    actions: Vec<TransportAction>,
}

impl TransportHarness {
    /// Creates a TCP-like harness.
    #[must_use]
    pub fn tcp(config: TransportConfig) -> Self {
        Self {
            binding: InMemoryTransport::new_tcp(config),
            actions: Vec::new(),
        }
    }

    /// Creates a QUIC-like harness.
    #[must_use]
    pub fn quic(config: TransportConfig) -> Self {
        Self {
            binding: InMemoryTransport::new_quic(config),
            actions: Vec::new(),
        }
    }

    /// Returns immutable binding view.
    #[must_use]
    pub const fn binding(&self) -> &InMemoryTransport {
        &self.binding
    }

    /// Returns mutable binding view.
    #[must_use]
    pub fn binding_mut(&mut self) -> &mut InMemoryTransport {
        &mut self.binding
    }

    /// Open stream and accumulate actions.
    pub fn open(&mut self, transport_stream_id: TransportStreamId) -> Result<(), SarError> {
        let actions = self.binding.open_transport_stream(transport_stream_id)?;
        self.actions.extend(actions);
        Ok(())
    }

    /// Feed one byte chunk and accumulate actions.
    pub fn feed(
        &mut self,
        transport_stream_id: TransportStreamId,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<(), SarError> {
        let actions = self
            .binding
            .feed_bytes(transport_stream_id, bytes, now_ms)?;
        self.actions.extend(actions);
        Ok(())
    }

    /// Feed many deterministic chunks in order.
    pub fn feed_chunks(
        &mut self,
        transport_stream_id: TransportStreamId,
        chunks: &[&[u8]],
        now_ms: Option<u64>,
    ) -> Result<(), SarError> {
        for chunk in chunks {
            self.feed(transport_stream_id, chunk, now_ms)?;
        }
        Ok(())
    }

    /// Close stream and accumulate actions.
    pub fn close(&mut self, transport_stream_id: TransportStreamId) -> Result<(), SarError> {
        let actions = self.binding.close_transport_stream(transport_stream_id)?;
        self.actions.extend(actions);
        Ok(())
    }

    /// Reset stream and accumulate actions.
    pub fn reset(
        &mut self,
        transport_stream_id: TransportStreamId,
        reason: SarError,
    ) -> Result<(), SarError> {
        let actions = self
            .binding
            .reset_transport_stream(transport_stream_id, reason)?;
        self.actions.extend(actions);
        Ok(())
    }

    /// Evaluate watchdog and collect action output.
    pub fn check_inactivity(&mut self, now_ms: u64) -> Result<(), SarError> {
        let actions = self.binding.check_inactivity(now_ms)?;
        self.actions.extend(actions);
        Ok(())
    }

    /// Trigger heartbeat hook and collect action output.
    pub fn heartbeat(
        &mut self,
        transport_stream_id: TransportStreamId,
        now_ms: u64,
    ) -> Result<(), SarError> {
        let actions = self
            .binding
            .maybe_emit_heartbeat(transport_stream_id, now_ms)?;
        self.actions.extend(actions);
        Ok(())
    }

    /// Drain all accumulated actions.
    pub fn drain_actions(&mut self) -> Vec<TransportAction> {
        let mut drained = Vec::new();
        std::mem::swap(&mut drained, &mut self.actions);
        drained
    }
}

pub use tcp::{TcpSarConnection, TcpTransportConfig};
