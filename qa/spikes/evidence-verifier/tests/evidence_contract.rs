//! Contract-first tests (FOSS-478): these MUST fail against the intentional
//! reject-all stub, then pass against a real pinned-key verifier.
//!
//! Signing seeds below are PUBLIC TEST FIXTURES, never production secrets.
use ed25519_dalek::{Signer, SigningKey};
use openscion_evidence_verifier_lab::*;
use std::collections::BTreeSet;

const NOW: u64 = 1_800_000_000;
const AUDIENCE: &str = "openscion.authority.local.v1";
const SUBJECT: &str = "agent01";
const ISSUER_ID: &str = "review-key-01";

struct Fixture {
    request: PromotionRequest,
    statement: AuthorizationStatement,
    signed: SignedAuthorization,
    policy: ChannelPolicy,
    issuers: Vec<TrustedIssuer>,
    revocation: RevocationState,
    nonces: BTreeSet<NonceKey>,
    now: Option<u64>,
    subject: String,
    audience: String,
    evidence_bytes: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let policy_digest = sha256(b"FOSS-478-test-policy");
        let evidence_bytes = b"FOSS-478-test-evidence-bundle".to_vec();
        let evidence_digest = sha256(&evidence_bytes);
        let candidate = format!("r1_{}", "a".repeat(64));
        let request = PromotionRequest {
            channel: "main".into(),
            expected_head: None,
            candidate: candidate.clone(),
            policy_id: "policy-foss478".into(),
            policy_digest,
            policy_epoch: 3,
            evidence_digest,
            idempotency_key: "stable-idempotency-key-01".into(),
        };
        let fingerprint = request.fingerprint(SUBJECT).expect("valid fixture");
        let statement = AuthorizationStatement {
            audience: AUDIENCE.into(),
            issuer_key_id: ISSUER_ID.into(),
            issuer_key_version: 2,
            algorithm: ALG_ED25519,
            request_fingerprint: fingerprint,
            channel: "main".into(),
            expected_head: None,
            candidate,
            policy_id: "policy-foss478".into(),
            policy_digest,
            policy_epoch: 3,
            evidence_digest,
            key_epoch: 7,
            revocation_epoch: 11,
            role: Role::Reviewer,
            decision: DECISION_ALLOW,
            nonce: [9u8; 32],
            issued_at: NOW - 30,
            expires_at: NOW + 300,
        };
        let signed = sign(&statement, &signer);
        let issuers = vec![TrustedIssuer {
            key_id: ISSUER_ID.into(),
            key_version: 2,
            principal_id: "reviewer-a".into(),
            public_key: signer.verifying_key().to_bytes(),
            role: Role::Reviewer,
            key_epoch: 7,
            active_from: NOW - 900,
            active_until: NOW + 900,
            revoked: false,
        }];
        let policy = ChannelPolicy {
            channel: "main".into(),
            policy_id: "policy-foss478".into(),
            policy_digest,
            policy_epoch: 3,
        };
        Self {
            request,
            statement,
            signed,
            policy,
            issuers,
            revocation: RevocationState {
                epoch: 11,
                fresh_until: NOW + 600,
            },
            nonces: BTreeSet::new(),
            now: Some(NOW),
            subject: SUBJECT.into(),
            audience: AUDIENCE.into(),
            evidence_bytes,
        }
    }
    fn resign(&mut self) {
        self.signed = sign(&self.statement, &SigningKey::from_bytes(&[7u8; 32]));
    }
    fn view(&self) -> TrustView<'_> {
        TrustView {
            authenticated_subject: &self.subject,
            audience: &self.audience,
            now: self.now,
            policy: &self.policy,
            issuers: &self.issuers,
            revocation: Some(&self.revocation),
            used_nonces: &self.nonces,
            evidence_bundle: &self.evidence_bytes,
        }
    }
    fn verify(&self) -> Result<VerifiedApproval, VerifyError> {
        verify_new_authorization(&self.request, &self.signed, &self.view())
    }
    fn reject(&self, reason: VerifyError) {
        assert_eq!(self.verify().unwrap_err(), reason);
    }
}
fn sign(statement: &AuthorizationStatement, signer: &SigningKey) -> SignedAuthorization {
    let bytes = statement.encode_canonical();
    SignedAuthorization {
        statement_bytes: bytes.clone(),
        signature: signer.sign(&bytes).to_bytes(),
    }
}

#[test]
fn valid_independent_signed_review_is_verified() {
    let f = Fixture::new();
    let result = f.verify().expect("signed independent reviewer accepted");
    assert_eq!(result.fingerprint(), f.statement.request_fingerprint);
    assert_eq!(result.issuer_key_id(), ISSUER_ID);
    assert_eq!(result.issuer_key_version(), 2);
    assert_eq!(result.issuer_principal(), "reviewer-a");
    assert_eq!(result.authenticated_subject(), SUBJECT);
    assert_eq!(result.audience(), AUDIENCE);
    assert_eq!(result.evidence_bundle_digest(), f.request.evidence_digest);
    assert_eq!(result.nonce(), [9u8; 32]);
    assert_eq!(result.policy_epoch(), 3);
    assert_eq!(result.key_epoch(), 7);
    assert_eq!(result.revocation_epoch(), 11);
}

#[test]
fn deterministic_domain_separated_request_fingerprint() {
    let f = Fixture::new();
    assert_eq!(
        f.request.fingerprint(SUBJECT).unwrap(),
        f.statement.request_fingerprint
    );
    assert_ne!(
        f.request.fingerprint("agent02").unwrap(),
        f.statement.request_fingerprint
    );
    let mut r = f.request.clone();
    r.idempotency_key.push('x');
    assert_ne!(
        r.fingerprint(SUBJECT).unwrap(),
        f.statement.request_fingerprint
    );
    let mut r = f.request.clone();
    r.expected_head = Some(format!("r1_{}", "b".repeat(64)));
    assert_ne!(
        r.fingerprint(SUBJECT).unwrap(),
        f.statement.request_fingerprint
    );
}

#[test]
fn rejects_modified_signature() {
    let mut f = Fixture::new();
    f.signed.signature[0] ^= 0x40;
    f.reject(VerifyError::InvalidSignature);
}

#[test]
fn rejects_forged_review_signed_by_untrusted_private_key() {
    let mut f = Fixture::new();
    f.signed = sign(&f.statement, &SigningKey::from_bytes(&[8u8; 32]));
    f.reject(VerifyError::InvalidSignature);
}

#[test]
fn rejects_unknown_issuer_key() {
    let mut f = Fixture::new();
    f.statement.issuer_key_id = "untrusted-issuer".into();
    f.resign();
    f.reject(VerifyError::UntrustedIssuer);
}

#[test]
fn rejects_wrong_key_version() {
    let mut f = Fixture::new();
    f.statement.issuer_key_version += 1;
    f.resign();
    f.reject(VerifyError::UntrustedIssuer);
}

#[test]
fn rejects_unsupported_algorithm_without_fallback() {
    let mut f = Fixture::new();
    f.statement.algorithm = 2;
    f.resign();
    f.reject(VerifyError::WrongAlgorithm);
}

#[test]
fn rejects_wrong_audience() {
    let mut f = Fixture::new();
    f.statement.audience = "other.authority".into();
    f.resign();
    f.reject(VerifyError::ScopeMismatch);
}

#[test]
fn rejects_changed_candidate_even_when_old_review_was_valid() {
    let mut f = Fixture::new();
    f.request.candidate = format!("r1_{}", "c".repeat(64));
    f.reject(VerifyError::ScopeMismatch);
}

#[test]
fn rejects_mismatched_head_and_channel() {
    let mut f = Fixture::new();
    f.request.expected_head = Some(format!("r1_{}", "d".repeat(64)));
    f.reject(VerifyError::ScopeMismatch);
    let mut f = Fixture::new();
    f.request.channel = "release".into();
    f.reject(VerifyError::ScopeMismatch);
}

#[test]
fn rejects_claimed_agent_as_authenticated_subject() {
    let mut f = Fixture::new();
    f.subject = "other-agent".into();
    f.reject(VerifyError::ScopeMismatch);
}

#[test]
fn rejects_wrong_evidence_bundle_digest() {
    let mut f = Fixture::new();
    f.statement.evidence_digest = sha256(b"wrong evidence");
    f.resign();
    f.reject(VerifyError::ScopeMismatch);
}

#[test]
fn rejects_policy_epoch_and_policy_digest_changes() {
    let mut f = Fixture::new();
    f.policy.policy_epoch += 1;
    f.reject(VerifyError::PolicyStale);
    let mut f = Fixture::new();
    f.policy.policy_digest = sha256(b"replaced policy");
    f.reject(VerifyError::PolicyStale);
}

#[test]
fn rejects_revoked_and_rotated_issuer() {
    let mut f = Fixture::new();
    f.issuers[0].revoked = true;
    f.reject(VerifyError::KeyRevoked);
    let mut f = Fixture::new();
    f.issuers[0].key_epoch += 1;
    f.reject(VerifyError::EpochStale);
}

#[test]
fn rejects_unknown_and_stale_revocation_state() {
    let f = Fixture::new();
    let mut context = f.view();
    context.revocation = None;
    assert_eq!(
        verify_new_authorization(&f.request, &f.signed, &context).unwrap_err(),
        VerifyError::RevocationUnknown
    );
    let mut f = Fixture::new();
    f.revocation.fresh_until = NOW - 1;
    f.reject(VerifyError::RevocationUnknown);
    let mut f = Fixture::new();
    f.revocation.epoch += 1;
    f.reject(VerifyError::EpochStale);
}

#[test]
fn rejects_missing_clock_or_signature_expiry() {
    let mut f = Fixture::new();
    f.now = None;
    f.reject(VerifyError::TimeUnavailable);
    let mut f = Fixture::new();
    // Keep independent key/revocation freshness valid, isolating SIGNATURE
    // expiry instead of expecting an expired revocation snapshot to pass.
    f.revocation.fresh_until = NOW + 1_200;
    f.issuers[0].active_until = NOW + 1_200;
    f.now = Some(NOW + 901);
    f.reject(VerifyError::Expired);
    let mut f = Fixture::new();
    f.issuers[0].active_from = NOW - 1_200;
    f.now = Some(NOW - 901);
    f.reject(VerifyError::NotYetValid);
}

#[test]
fn rejects_oversized_signature_validity_interval() {
    let mut f = Fixture::new();
    f.statement.expires_at = NOW + MAX_AUTH_TTL_SECONDS + 1;
    f.resign();
    f.reject(VerifyError::Expired);
}

#[test]
fn rejects_denied_decision_even_with_valid_signature() {
    let mut f = Fixture::new();
    f.statement.decision = 0;
    f.resign();
    f.reject(VerifyError::DecisionDenied);
}

#[test]
fn rejects_agent_role_approval() {
    let mut f = Fixture::new();
    f.statement.role = Role::Agent;
    f.resign();
    f.reject(VerifyError::RoleDenied);
    let mut f = Fixture::new();
    f.issuers[0].role = Role::Agent;
    f.reject(VerifyError::RoleDenied);
}

#[test]
fn rejects_self_approval_using_trusted_issuer_identity() {
    let mut f = Fixture::new();
    f.issuers[0].principal_id = SUBJECT.into();
    f.reject(VerifyError::SeparationOfDuties);
}

#[test]
fn rejects_nonce_replay_without_state_mutation() {
    let mut f = Fixture::new();
    let nonce = NonceKey {
        issuer_key_id: ISSUER_ID.into(),
        nonce: f.statement.nonce,
    };
    f.nonces.insert(nonce.clone());
    f.reject(VerifyError::NonceReplay);
    assert!(
        f.nonces.contains(&nonce),
        "verifier must not consume nonce on denial"
    );
}

#[test]
fn rejects_expired_issuer_key() {
    let mut f = Fixture::new();
    f.issuers[0].active_until = NOW - 1;
    f.reject(VerifyError::KeyRevoked);
}

#[test]
fn rejects_malformed_or_noncanonical_signed_bytes() {
    let mut f = Fixture::new();
    f.signed.statement_bytes.push(0);
    f.reject(VerifyError::NonCanonical);
    let mut f = Fixture::new();
    f.signed.statement_bytes[0] = b'x';
    f.reject(VerifyError::MalformedWire);
    let mut f = Fixture::new();
    f.signed.statement_bytes.truncate(23);
    f.reject(VerifyError::MalformedWire);
}

#[test]
fn rejects_invalid_revision_identifiers_and_idempotency_keys() {
    let mut f = Fixture::new();
    f.request.candidate = format!("r1_{}", "G".repeat(64));
    f.reject(VerifyError::InvalidRequest);
    let mut f = Fixture::new();
    f.request.idempotency_key = "x".into();
    f.reject(VerifyError::InvalidRequest);
}

#[test]
fn replay_after_revocation_is_not_a_new_promotion() {
    // PROM-019: an already committed receipt is handled by the *future*
    // authority's authenticated idempotency lookup before this verifier.
    // Calling this verifier for a NEW promotion must still reject.
    let mut f = Fixture::new();
    f.issuers[0].revoked = true;
    f.reject(VerifyError::KeyRevoked);
}

#[test]
fn rejects_missing_evidence_bundle_even_when_signed_hash_matches() {
    let mut f = Fixture::new();
    f.evidence_bytes.clear();
    f.reject(VerifyError::EvidenceMissing);
}

#[test]
fn rejects_modified_evidence_bundle_bytes_with_valid_signature() {
    let mut f = Fixture::new();
    f.evidence_bytes[0] ^= 1;
    f.reject(VerifyError::EvidenceHashMismatch);
}

#[test]
fn rejects_oversized_evidence_bundle_before_hashing_or_allocating_more() {
    let mut f = Fixture::new();
    f.evidence_bytes = vec![0xa5; MAX_EVIDENCE_BYTES + 1];
    f.reject(VerifyError::EvidenceMissing);
}

#[test]
fn rejects_ambiguous_channel_and_identity_tokens() {
    let mut f = Fixture::new();
    f.request.channel = "Main".into();
    f.reject(VerifyError::InvalidRequest);
    let mut f = Fixture::new();
    f.request.channel = "..".into();
    f.reject(VerifyError::InvalidRequest);
    let mut f = Fixture::new();
    f.request.policy_id = "policy.".into();
    f.reject(VerifyError::InvalidRequest);
}

#[test]
fn rejects_ambiguous_duplicate_issuer_id_and_version() {
    let mut f = Fixture::new();
    f.issuers.push(f.issuers[0].clone());
    f.reject(VerifyError::UntrustedIssuer);
}

#[test]
fn rejects_zero_nonce_even_if_issuer_signed_it() {
    let mut f = Fixture::new();
    f.statement.nonce = [0; 32];
    f.resign();
    f.reject(VerifyError::MalformedWire);
}

#[test]
fn distinct_version_during_key_rotation_does_not_override_pinned_key() {
    let mut f = Fixture::new();
    let mut old_key = f.issuers[0].clone();
    old_key.key_version = 1;
    old_key.public_key = [0u8; 32];
    f.issuers.push(old_key);
    assert!(f.verify().is_ok(), "the exact signed key version must be used");
}

#[test]
fn all_truncations_of_signed_canonical_wire_fail_without_panicking() {
    let f = Fixture::new();
    for len in 0..f.signed.statement_bytes.len() {
        let mut changed = f.signed.clone();
        changed.statement_bytes.truncate(len);
        assert!(
            verify_new_authorization(&f.request, &changed, &f.view()).is_err(),
            "truncated signed authorization of length {len} must not verify"
        );
    }
}

#[test]
fn each_single_byte_signed_wire_mutation_fails_without_panicking() {
    let f = Fixture::new();
    for offset in 0..f.signed.statement_bytes.len() {
        let mut changed = f.signed.clone();
        changed.statement_bytes[offset] ^= 1;
        assert!(
            verify_new_authorization(&f.request, &changed, &f.view()).is_err(),
            "tampering at offset {offset} must not verify"
        );
    }
}

#[test]
fn oversized_authorization_wire_is_rejected_before_parsing() {
    let mut f = Fixture::new();
    f.signed.statement_bytes = vec![0; MAX_AUTH_BYTES + 1];
    f.reject(VerifyError::MalformedWire);
}
