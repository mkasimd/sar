// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};

use sar_crypto::{
    KdfLimits, KeyProvider, KmsContext, KmsParams, MasterSecretScope, PBKDF2_PRF_HMAC_SHA256,
    Pbkdf2Params, SarCryptoError, SecretBytes, SecretString,
};

struct Counting(AtomicUsize);

impl KeyProvider for Counting {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Some(SecretString::new("pw".to_string())))
    }
    fn unwrap_key(
        &self,
        _ctx: &KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
    fn external_key(&self, _ctx: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
}

fn context(salt: u8) -> KmsContext {
    KmsContext {
        mode_id: sar_crypto::KMS_PBKDF2,
        params: KmsParams::Pbkdf2(Pbkdf2Params {
            prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
            salt: vec![salt; 16],
            iterations: 100_000,
            derived_key_length: 32,
        }),
    }
}

#[test]
fn same_context_reuses_secret_and_changed_context_rederives() {
    let provider = Counting(AtomicUsize::new(0));
    let limits = KdfLimits::default();
    let mut scope = MasterSecretScope::new();
    let first = scope
        .get_or_resolve(&provider, &context(1), &limits)
        .expect("first")
        .to_vec();
    let again = scope
        .get_or_resolve(&provider, &context(1), &limits)
        .expect("again")
        .to_vec();
    assert_eq!(first, again);
    assert_eq!(provider.0.load(Ordering::SeqCst), 1);

    let other = scope
        .get_or_resolve(&provider, &context(2), &limits)
        .expect("other")
        .to_vec();
    assert_ne!(
        first, other,
        "a different KMS context must not reuse a secret"
    );
    assert_eq!(provider.0.load(Ordering::SeqCst), 2);
}

#[test]
fn invalidate_discards_the_secret() {
    let provider = Counting(AtomicUsize::new(0));
    let limits = KdfLimits::default();
    let mut scope = MasterSecretScope::new();
    scope
        .get_or_resolve(&provider, &context(1), &limits)
        .expect("resolve");
    assert!(scope.is_retained());
    scope.invalidate();
    assert!(!scope.is_retained());
    scope
        .get_or_resolve(&provider, &context(1), &limits)
        .expect("resolve after invalidate");
    assert_eq!(provider.0.load(Ordering::SeqCst), 2);
}

#[test]
fn limits_are_enforced_before_derivation_and_failures_are_not_retained() {
    let provider = Counting(AtomicUsize::new(0));
    let tight = KdfLimits {
        max_pbkdf2_iterations: 10,
        ..KdfLimits::default()
    };
    let mut scope = MasterSecretScope::new();
    let err = scope
        .get_or_resolve(&provider, &context(1), &tight)
        .expect_err("limit");
    assert!(matches!(err, SarCryptoError::LimitExceeded(_)));
    assert!(!scope.is_retained());
    scope
        .get_or_resolve(&provider, &context(1), &KdfLimits::default())
        .expect("succeeds once limits allow it");
    assert!(scope.is_retained());
}

#[test]
fn debug_output_never_contains_secret_material() {
    let provider = Counting(AtomicUsize::new(0));
    let mut scope = MasterSecretScope::new();
    let secret = scope
        .get_or_resolve(&provider, &context(1), &KdfLimits::default())
        .expect("resolve")
        .to_vec();
    let rendered = format!("{scope:?}");
    assert_eq!(rendered, "MasterSecretScope { retained: true }");
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!rendered.contains(&hex));
}
