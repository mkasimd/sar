// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! SAR-over-QUIC transport binding (M10e).
//!
//! This module implements the SAR-over-QUIC transport binding as defined in
//! Section 18.5.2 of the SAR specification.  It is enabled by the `quic`
//! Cargo feature and depends on [`quinn`], [`rustls`], and [`tokio`].
//!
//! # Feature gate
//!
//! This module and all its types are available only when the `quic` feature
//! is enabled:
//!
//! ```toml
//! [dependencies]
//! sar-transport = { path = "…", features = ["quic"] }
//! ```
//!
//! # Security model
//!
//! * QUIC/TLS protects all transport bytes.
//! * SAR AEAD is an **additional** optional protection layer and is recommended
//!   for deployments that require SAR-layer authentication/confidentiality.
//! * TCP+TLS is **not** supported.  STARTTLS is **not** supported.
//! * TLS certificate verification is enforced by default.  Any test-only
//!   insecure mode is explicitly named
//!   [`InsecureSkipVerifyForTestsOnly`][`QuicClientTrust::InsecureSkipVerifyForTestsOnly`].
//!
//! # QUIC + TLS_EXPORTER SAR-AEAD mode
//!
//! When the selected QUIC/TLS stack exposes exporter keying material (quinn
//! 0.11 + rustls 0.23), KMS Mode `0x04 TLS_EXPORTER` is supported via
//! [`QuicSarConnection::export_keying_material`].  If the underlying TLS
//! connection does not expose exporter material, key derivation fails closed
//! with [`sar_core::SarError::Unsupported`].

pub mod config;
pub mod connection;
pub mod identity;

pub use config::{QuicClientConfig, QuicServerConfig, QuicTransportConfig, TlsPqPolicy};
pub use connection::{QuicSarConnection, QuicSarListener, QuicSarStream, connect_quic};
pub use identity::{QuicClientTrust, QuicServerIdentity};
