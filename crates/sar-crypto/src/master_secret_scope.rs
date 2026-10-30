// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Context-owned retention of one KMS Master Secret.
//!
//! A KMS Extension establishes a single 32-byte KMS Master Secret for the
//! physical archive or Stateful Streaming session that carries it.  Expensive
//! KDFs (PBKDF2, Argon2id) must therefore run once per such scope, not once per
//! encrypted Entry.  A [`MasterSecretScope`] is owned by exactly one scope
//! owner (an archive reader, a stream parser, or one session's control-stream
//! state).  It is deliberately not shared, not global and holds at most one
//! secret.

use core::fmt;

use crate::error::SarCryptoError;
use crate::kms::limits::KdfLimits;
use crate::kms::types::KmsContext;
use crate::provider::{KeyProvider, resolve_master_secret};
use crate::secret::SecretBytes;

/// Holds the KMS Master Secret resolved for one [`KmsContext`].
///
/// The retained secret is bound to the exact context it was resolved for.  A
/// request for a different context discards the old secret and resolves anew,
/// so a context change can never reuse a stale secret.  The secret lives in a
/// zeroizing container and is wiped on invalidation and on drop.
#[derive(Default)]
pub struct MasterSecretScope {
    retained: Option<(KmsContext, SecretBytes)>,
}

impl MasterSecretScope {
    /// Creates an empty scope.
    #[must_use]
    pub const fn new() -> Self {
        Self { retained: None }
    }

    /// Returns the KMS Master Secret for `context`, resolving it on first use.
    ///
    /// `limits` are enforced by [`resolve_master_secret`] before any expensive
    /// derivation.  Failed resolutions are never retained.
    ///
    /// # Errors
    ///
    /// Propagates every error of [`resolve_master_secret`] unchanged.
    pub fn get_or_resolve(
        &mut self,
        provider: &dyn KeyProvider,
        context: &KmsContext,
        limits: &KdfLimits,
    ) -> Result<&SecretBytes, SarCryptoError> {
        let reusable = matches!(&self.retained, Some((bound, _)) if bound == context);
        if !reusable {
            self.retained = None;
            let secret = resolve_master_secret(provider, context, limits)?;
            self.retained = Some((context.clone(), secret));
        }
        match &self.retained {
            Some((_, secret)) => Ok(secret),
            None => Err(SarCryptoError::Internal(
                "master secret scope lost its retained secret",
            )),
        }
    }

    /// Discards (and zeroizes) the retained secret.
    pub fn invalidate(&mut self) {
        self.retained = None;
    }

    /// Returns whether a secret is currently retained.
    #[must_use]
    pub const fn is_retained(&self) -> bool {
        self.retained.is_some()
    }
}

impl fmt::Debug for MasterSecretScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterSecretScope")
            .field("retained", &self.retained.is_some())
            .finish()
    }
}
