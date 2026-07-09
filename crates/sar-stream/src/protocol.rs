use sar_core::{ResourceLimits, SarError, SarStatus};

/// Filesystem-opcode namespace used when `SESSION_CONTROL` is not set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemOpCode {
    /// Standard creation/update payload.
    DataWrite = 0x0,
    /// Delete target path. Payload size must be zero.
    Delete = 0x1,
    /// Rename old path (LFH name/path) to new path (payload bytes).
    Rename = 0x2,
    /// Validate target/base metadata only.
    MetaProbe = 0x3,
    /// Synchronization barrier.
    SyncBarrier = 0x4,
}

impl TryFrom<u8> for FilesystemOpCode {
    type Error = SarError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(Self::DataWrite),
            0x1 => Ok(Self::Delete),
            0x2 => Ok(Self::Rename),
            0x3 => Ok(Self::MetaProbe),
            0x4 => Ok(Self::SyncBarrier),
            _ => Err(SarError::ReservedValue("reserved filesystem OP_CODE")),
        }
    }
}

/// Session-opcode namespace used when `SESSION_CONTROL` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOpCode {
    /// Establish or reinitialize a session binding.
    Init = 0x0,
    /// Gracefully terminate the bound session.
    Close = 0x1,
    /// Validate UUID for session resumption.
    Resume = 0x2,
    /// Heartbeat / keep-alive frame.
    Heartbeat = 0x3,
    /// Status frame.
    Status = 0x4,
    /// Acknowledgement frame.
    Ack = 0x5,
    /// Application metadata update frame.
    Metadata = 0x6,
    /// Capability advertisement frame.
    Capabilities = 0x7,
}

impl TryFrom<u8> for SessionOpCode {
    type Error = SarError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(Self::Init),
            0x1 => Ok(Self::Close),
            0x2 => Ok(Self::Resume),
            0x3 => Ok(Self::Heartbeat),
            0x4 => Ok(Self::Status),
            0x5 => Ok(Self::Ack),
            0x6 => Ok(Self::Metadata),
            0x7 => Ok(Self::Capabilities),
            _ => Err(SarError::ReservedValue("reserved session OP_CODE")),
        }
    }
}

/// Session flag bits carried by `SESSION_INIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionFlags {
    bits: u16,
}

impl SessionFlags {
    /// Sender can receive reverse-direction `SESSION_CONTROL` messages.
    pub const BIDIRECTIONAL_CONTROL_REQUESTED: u16 = 1 << 0;
    /// Sender requires reverse-direction `SESSION_CONTROL` support.
    pub const BIDIRECTIONAL_CONTROL_REQUIRED: u16 = 1 << 1;
    /// Sender can receive reverse-direction filesystem and session entries.
    pub const BIDIRECTIONAL_STREAM_REQUESTED: u16 = 1 << 2;
    /// Sender requires reverse-direction filesystem and session entries.
    pub const BIDIRECTIONAL_STREAM_REQUIRED: u16 = 1 << 3;

    const RESERVED_MASK: u16 = 0xfff0;

    /// Creates a flag set from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Returns the raw wire bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.bits
    }

    /// Returns true when bidirectional control is requested.
    #[must_use]
    pub const fn bidirectional_control_requested(self) -> bool {
        self.bits & Self::BIDIRECTIONAL_CONTROL_REQUESTED != 0
    }

    /// Returns true when bidirectional control is required.
    #[must_use]
    pub const fn bidirectional_control_required(self) -> bool {
        self.bits & Self::BIDIRECTIONAL_CONTROL_REQUIRED != 0
    }

    /// Returns true when bidirectional streaming is requested.
    #[must_use]
    pub const fn bidirectional_stream_requested(self) -> bool {
        self.bits & Self::BIDIRECTIONAL_STREAM_REQUESTED != 0
    }

    /// Returns true when bidirectional streaming is required.
    #[must_use]
    pub const fn bidirectional_stream_required(self) -> bool {
        self.bits & Self::BIDIRECTIONAL_STREAM_REQUIRED != 0
    }

    /// Validates reserved bits and required flag combinations.
    pub fn validate(self) -> Result<(), SarError> {
        if self.bits & Self::RESERVED_MASK != 0 {
            return Err(SarError::ReservedValue(
                "reserved SESSION_INIT flags must be zero",
            ));
        }

        let control_enabled =
            self.bidirectional_control_requested() || self.bidirectional_control_required();
        if (self.bidirectional_stream_requested() || self.bidirectional_stream_required())
            && !control_enabled
        {
            return Err(SarError::FlagConflict(
                "bidirectional stream requires bidirectional control",
            ));
        }

        if self.bidirectional_stream_required() && !self.bidirectional_control_required() {
            return Err(SarError::FlagConflict(
                "required bidirectional stream requires required bidirectional control",
            ));
        }

        Ok(())
    }
}

/// Capability flags carried by `SESSION_CAPABILITIES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityFlags {
    bits: u16,
}

impl CapabilityFlags {
    /// Endpoint can transmit and process `SESSION_ACK`.
    pub const SESSION_ACK: u16 = 1 << 0;
    /// Endpoint can transmit and process `SESSION_STATUS`.
    pub const SESSION_STATUS: u16 = 1 << 1;
    /// Endpoint can transmit and process `SESSION_RESUME`.
    pub const SESSION_RESUME: u16 = 1 << 2;
    /// Endpoint can transmit and process `SESSION_METADATA`.
    pub const SESSION_METADATA: u16 = 1 << 3;
    /// Endpoint supports reverse-direction session-control entries.
    pub const BIDIRECTIONAL_CONTROL: u16 = 1 << 4;
    /// Endpoint supports reverse-direction filesystem and session entries.
    pub const BIDIRECTIONAL_STREAM: u16 = 1 << 5;
    /// Endpoint supports SAR AEAD key derivation using KMS Mode `0x04 TLS_EXPORTER` over an
    /// authenticated TLS-based transport.  This bit is spec-defined but not advertised by
    /// plaintext TCP bindings; TCP must never set this bit in its local capability advertisement.
    pub const CAP_TLS_EXPORTER_AEAD: u16 = 1 << 6;

    const RESERVED_MASK: u16 = 0xff80;

    /// Empty capability set.
    pub const NONE: Self = Self { bits: 0 };

    /// Creates a capability set from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Returns raw capability bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.bits
    }

    /// Returns true when ACK capability is present.
    #[must_use]
    pub const fn supports_session_ack(self) -> bool {
        self.bits & Self::SESSION_ACK != 0
    }

    /// Returns true when STATUS capability is present.
    #[must_use]
    pub const fn supports_session_status(self) -> bool {
        self.bits & Self::SESSION_STATUS != 0
    }

    /// Returns true when RESUME capability is present.
    #[must_use]
    pub const fn supports_session_resume(self) -> bool {
        self.bits & Self::SESSION_RESUME != 0
    }

    /// Returns true when METADATA capability is present.
    #[must_use]
    pub const fn supports_session_metadata(self) -> bool {
        self.bits & Self::SESSION_METADATA != 0
    }

    /// Returns true when reverse-direction control is present.
    #[must_use]
    pub const fn supports_bidirectional_control(self) -> bool {
        self.bits & Self::BIDIRECTIONAL_CONTROL != 0
    }

    /// Returns true when reverse-direction streaming is present.
    #[must_use]
    pub const fn supports_bidirectional_stream(self) -> bool {
        self.bits & Self::BIDIRECTIONAL_STREAM != 0
    }

    /// Returns true when TLS-exporter AEAD capability is present.
    ///
    /// This capability is spec-defined (bit 6) but is **not** supported by plaintext TCP
    /// bindings.  Plaintext TCP must never advertise this bit.
    #[must_use]
    pub const fn supports_tls_exporter_aead(self) -> bool {
        self.bits & Self::CAP_TLS_EXPORTER_AEAD != 0
    }

    /// Validates reserved bits and required flag combinations.
    pub fn validate(self) -> Result<(), SarError> {
        if self.bits & Self::RESERVED_MASK != 0 {
            return Err(SarError::ReservedValue(
                "reserved SESSION_CAPABILITIES bits must be zero",
            ));
        }
        if self.supports_bidirectional_stream() && !self.supports_bidirectional_control() {
            return Err(SarError::FlagConflict(
                "bidirectional stream capability requires bidirectional control capability",
            ));
        }
        Ok(())
    }
}

/// ACK flag bits carried by `SESSION_ACK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckFlags {
    bits: u8,
}

impl AckFlags {
    /// Referenced entry was received and parsed.
    pub const ACK: u8 = 1 << 0;
    /// Referenced entry was accepted as valid/applicable.
    pub const OK: u8 = 1 << 1;
    /// Referenced operation completed successfully.
    pub const SUCCESS: u8 = 1 << 2;

    const RESERVED_MASK: u8 = 0xf8;

    /// Creates an ACK flag set from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    /// Returns the raw wire bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// Returns true when the ACK bit is set.
    #[must_use]
    pub const fn is_ack(self) -> bool {
        self.bits & Self::ACK != 0
    }

    /// Returns true when the OK bit is set.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        self.bits & Self::OK != 0
    }

    /// Returns true when the SUCCESS bit is set.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.bits & Self::SUCCESS != 0
    }

    /// Validates reserved bits and dependency ordering.
    pub fn validate(self) -> Result<(), SarError> {
        if self.bits & Self::RESERVED_MASK != 0 {
            return Err(SarError::ReservedValue(
                "reserved SESSION_ACK bits must be zero",
            ));
        }
        if self.is_ok() && !self.is_ack() {
            return Err(SarError::FlagConflict("SESSION_ACK OK requires ACK"));
        }
        if self.is_success() && !(self.is_ack() && self.is_ok()) {
            return Err(SarError::FlagConflict(
                "SESSION_ACK SUCCESS requires ACK and OK",
            ));
        }
        Ok(())
    }
}

/// Parsed `SESSION_INIT` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInitFrame {
    /// Session UUID.
    pub session_uuid: [u8; 16],
    /// Session flags.
    pub flags: SessionFlags,
}

impl SessionInitFrame {
    /// Parses and validates a `SESSION_INIT` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, SarError> {
        if payload.len() != 18 {
            return Err(SarError::InvalidLength(
                "SESSION_INIT payload must be 18 bytes",
            ));
        }
        let mut session_uuid = [0u8; 16];
        session_uuid.copy_from_slice(&payload[..16]);
        let flags = SessionFlags::from_bits(u16::from_le_bytes([payload[16], payload[17]]));
        flags.validate()?;
        Ok(Self {
            session_uuid,
            flags,
        })
    }

    /// Serializes a validated `SESSION_INIT` payload.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SarError> {
        self.flags.validate()?;
        let mut bytes = Vec::with_capacity(18);
        bytes.extend_from_slice(&self.session_uuid);
        bytes.extend_from_slice(&self.flags.bits().to_le_bytes());
        Ok(bytes)
    }
}

/// Parsed `SESSION_RESUME` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResumeFrame {
    /// Session UUID.
    pub session_uuid: [u8; 16],
}

impl SessionResumeFrame {
    /// Parses a `SESSION_RESUME` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, SarError> {
        if payload.len() != 16 {
            return Err(SarError::InvalidLength(
                "SESSION_RESUME payload must be 16 bytes",
            ));
        }
        let mut session_uuid = [0u8; 16];
        session_uuid.copy_from_slice(payload);
        Ok(Self { session_uuid })
    }

    /// Serializes a `SESSION_RESUME` payload.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.session_uuid.to_vec()
    }
}

/// Parsed `SESSION_STATUS` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatusFrame {
    /// Referenced sequence number.
    pub ref_sequence: u16,
    /// Registry status code.
    pub status: SarStatus,
    /// UTF-8/opaque diagnostic bytes.
    pub message: Vec<u8>,
}

impl SessionStatusFrame {
    /// Parses a `SESSION_STATUS` payload and enforces configured limits.
    pub fn parse(payload: &[u8], limits: &ResourceLimits) -> Result<Self, SarError> {
        if payload.len() < 5 {
            return Err(SarError::Truncated(
                "SESSION_STATUS payload shorter than fixed frame",
            ));
        }
        let ref_sequence = u16::from_le_bytes([payload[0], payload[1]]);
        let status = decode_status_code(u16::from_le_bytes([payload[2], payload[3]]))?;
        let message_len = usize::from(payload[4]);
        limits.check_session_status_message_bytes(message_len)?;
        if payload.len() != 5 + message_len {
            return Err(SarError::InvalidLength(
                "SESSION_STATUS payload length mismatch",
            ));
        }
        Ok(Self {
            ref_sequence,
            status,
            message: payload[5..].to_vec(),
        })
    }

    /// Serializes a `SESSION_STATUS` payload with configured size enforcement.
    pub fn to_bytes(&self, limits: &ResourceLimits) -> Result<Vec<u8>, SarError> {
        limits.check_session_status_message_bytes(self.message.len())?;
        let message_len = u8::try_from(self.message.len())
            .map_err(|_| SarError::Overflow("SESSION_STATUS message length"))?;
        let mut bytes = Vec::with_capacity(5 + self.message.len());
        bytes.extend_from_slice(&self.ref_sequence.to_le_bytes());
        bytes.extend_from_slice(&encode_status_code(self.status).to_le_bytes());
        bytes.push(message_len);
        bytes.extend_from_slice(&self.message);
        Ok(bytes)
    }
}

/// Parsed `SESSION_ACK` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAckFrame {
    /// Referenced sequence number.
    pub ref_sequence: u16,
    /// ACK flags.
    pub flags: AckFlags,
}

impl SessionAckFrame {
    /// Parses and validates a `SESSION_ACK` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, SarError> {
        if payload.len() != 3 {
            return Err(SarError::InvalidLength(
                "SESSION_ACK payload must be 3 bytes",
            ));
        }
        let flags = AckFlags::from_bits(payload[2]);
        flags.validate()?;
        Ok(Self {
            ref_sequence: u16::from_le_bytes([payload[0], payload[1]]),
            flags,
        })
    }

    /// Serializes a validated `SESSION_ACK` payload.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SarError> {
        self.flags.validate()?;
        let mut bytes = Vec::with_capacity(3);
        bytes.extend_from_slice(&self.ref_sequence.to_le_bytes());
        bytes.push(self.flags.bits());
        Ok(bytes)
    }
}

/// Parsed `SESSION_METADATA` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadataFrame {
    /// UTF-8 content type.
    pub content_type: String,
    /// Opaque metadata bytes.
    pub metadata: Vec<u8>,
}

impl SessionMetadataFrame {
    /// Parses and validates a `SESSION_METADATA` payload.
    pub fn parse(payload: &[u8], limits: &ResourceLimits) -> Result<Self, SarError> {
        if payload.len() < 5 {
            return Err(SarError::Truncated(
                "SESSION_METADATA payload shorter than fixed frame",
            ));
        }
        let content_type_len = usize::from(payload[0]);
        if content_type_len == 0 {
            return Err(SarError::InvalidLength(
                "SESSION_METADATA content type length must be non-zero",
            ));
        }
        let metadata_len_u32 = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let metadata_len =
            usize::try_from(metadata_len_u32).map_err(|_| SarError::Overflow("metadata length"))?;
        limits.check_session_metadata_bytes(metadata_len)?;
        let total = 5usize
            .checked_add(content_type_len)
            .and_then(|v| v.checked_add(metadata_len))
            .ok_or(SarError::Overflow("SESSION_METADATA frame length"))?;
        if payload.len() != total {
            return Err(SarError::InvalidLength(
                "SESSION_METADATA payload length mismatch",
            ));
        }
        let content_type = std::str::from_utf8(&payload[5..5 + content_type_len])
            .map_err(|_| SarError::Malformed("SESSION_METADATA content type is not valid UTF-8"))?
            .to_string();
        Ok(Self {
            content_type,
            metadata: payload[5 + content_type_len..].to_vec(),
        })
    }

    /// Serializes a validated `SESSION_METADATA` payload.
    pub fn to_bytes(&self, limits: &ResourceLimits) -> Result<Vec<u8>, SarError> {
        if self.content_type.is_empty() {
            return Err(SarError::InvalidLength(
                "SESSION_METADATA content type length must be non-zero",
            ));
        }
        let content_type_len = u8::try_from(self.content_type.len())
            .map_err(|_| SarError::Overflow("SESSION_METADATA content type length"))?;
        limits.check_session_metadata_bytes(self.metadata.len())?;
        let metadata_len = u32::try_from(self.metadata.len())
            .map_err(|_| SarError::Overflow("SESSION_METADATA metadata length"))?;
        let mut bytes = Vec::with_capacity(5 + self.content_type.len() + self.metadata.len());
        bytes.push(content_type_len);
        bytes.extend_from_slice(&metadata_len.to_le_bytes());
        bytes.extend_from_slice(self.content_type.as_bytes());
        bytes.extend_from_slice(&self.metadata);
        Ok(bytes)
    }
}

/// Parsed `SESSION_CAPABILITIES` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCapabilitiesFrame {
    /// Capability flag set.
    pub flags: CapabilityFlags,
}

impl SessionCapabilitiesFrame {
    /// Parses and validates a `SESSION_CAPABILITIES` payload.
    pub fn parse(payload: &[u8]) -> Result<Self, SarError> {
        if payload.len() != 2 {
            return Err(SarError::InvalidLength(
                "SESSION_CAPABILITIES payload must be 2 bytes",
            ));
        }
        let flags = CapabilityFlags::from_bits(u16::from_le_bytes([payload[0], payload[1]]));
        flags.validate()?;
        Ok(Self { flags })
    }

    /// Serializes a validated `SESSION_CAPABILITIES` payload.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SarError> {
        self.flags.validate()?;
        Ok(self.flags.bits().to_le_bytes().to_vec())
    }
}

fn decode_status_code(code: u16) -> Result<SarStatus, SarError> {
    let signed = if code == u16::MAX {
        -1
    } else {
        i32::from(code)
    };
    SarStatus::try_from(signed).map_err(|_| SarError::ReservedValue("unknown session status code"))
}

fn encode_status_code(status: SarStatus) -> u16 {
    if status.code() == -1 {
        u16::MAX
    } else {
        status.code() as u16
    }
}
