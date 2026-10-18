//! FOSS-478 isolated contract experiment.
//!
//! This crate is NOT linked into the OpenScion CLI or promotion service.
//! Only externally authenticated sessions, independently configured trust
//! anchors and trusted clock/revocation snapshots can authorize new changes.
//! Tests are deliberately authored before the verifier implementation.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const REQUEST_DOMAIN: &[u8] = b"openscion.promotion.request.v1\0";
pub const AUTH_DOMAIN: &[u8] = b"openscion.promotion.authorization.v1\0";
pub const MAX_AUTH_BYTES: usize = 4096;
pub const MAX_AUTH_TTL_SECONDS: u64 = 900;
pub const ALG_ED25519: u8 = 1;
pub const DECISION_ALLOW: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Agent,
    Reviewer,
}
impl Role {
    pub const fn value(self) -> u8 {
        match self {
            Self::Agent => 1,
            Self::Reviewer => 2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PromotionRequest {
    pub channel: String,
    pub expected_head: Option<String>,
    pub candidate: String,
    pub policy_id: String,
    pub policy_digest: [u8; 32],
    pub policy_epoch: u64,
    pub evidence_digest: [u8; 32],
    pub idempotency_key: String,
}

#[derive(Clone, Debug)]
pub struct AuthorizationStatement {
    pub audience: String,
    pub issuer_key_id: String,
    pub issuer_key_version: u64,
    pub algorithm: u8,
    pub request_fingerprint: [u8; 32],
    pub channel: String,
    pub expected_head: Option<String>,
    pub candidate: String,
    pub policy_id: String,
    pub policy_digest: [u8; 32],
    pub policy_epoch: u64,
    pub evidence_digest: [u8; 32],
    pub key_epoch: u64,
    pub revocation_epoch: u64,
    pub role: Role,
    pub decision: u8,
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct SignedAuthorization {
    pub statement_bytes: Vec<u8>,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug)]
pub struct ChannelPolicy {
    pub channel: String,
    pub policy_id: String,
    pub policy_digest: [u8; 32],
    pub policy_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct TrustedIssuer {
    pub key_id: String,
    pub key_version: u64,
    pub principal_id: String,
    pub public_key: [u8; 32],
    pub role: Role,
    pub key_epoch: u64,
    pub active_from: u64,
    pub active_until: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug)]
pub struct RevocationState {
    pub epoch: u64,
    pub fresh_until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonceKey {
    pub issuer_key_id: String,
    pub nonce: [u8; 32],
}

pub struct TrustView<'a> {
    /// Obtained from the authenticated IPC/session, never agent JSON.
    pub authenticated_subject: &'a str,
    pub audience: &'a str,
    /// Trusted authority time; None must fail closed.
    pub now: Option<u64>,
    pub policy: &'a ChannelPolicy,
    pub issuers: &'a [TrustedIssuer],
    pub revocation: Option<&'a RevocationState>,
    /// Read-only authoritative replay projection, checked again in DB txn.
    pub used_nonces: &'a BTreeSet<NonceKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    InvalidRequest,
    MalformedWire,
    NonCanonical,
    WrongAlgorithm,
    UntrustedIssuer,
    InvalidSignature,
    ScopeMismatch,
    PolicyStale,
    EpochStale,
    DecisionDenied,
    RoleDenied,
    SeparationOfDuties,
    RevocationUnknown,
    KeyRevoked,
    TimeUnavailable,
    NotYetValid,
    Expired,
    NonceReplay,
    NotImplemented,
}
impl VerifyError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "E_INVALID_REQUEST",
            Self::MalformedWire => "E_MALFORMED",
            Self::NonCanonical => "E_NONCANONICAL",
            Self::WrongAlgorithm => "E_ALGORITHM",
            Self::UntrustedIssuer => "E_UNTRUSTED_ISSUER",
            Self::InvalidSignature => "E_SIGNATURE",
            Self::ScopeMismatch => "E_SCOPE",
            Self::PolicyStale => "E_POLICY_STALE",
            Self::EpochStale => "E_EPOCH_STALE",
            Self::DecisionDenied => "E_DECISION_DENIED",
            Self::RoleDenied => "E_ROLE_DENIED",
            Self::SeparationOfDuties => "E_SEPARATION_OF_DUTIES",
            Self::RevocationUnknown => "E_REVOCATION_UNKNOWN",
            Self::KeyRevoked => "E_KEY_REVOKED",
            Self::TimeUnavailable => "E_TIME_UNAVAILABLE",
            Self::NotYetValid => "E_NOT_YET_VALID",
            Self::Expired => "E_EXPIRED",
            Self::NonceReplay => "E_NONCE_REPLAY",
            Self::NotImplemented => "E_NOT_IMPLEMENTED",
        }
    }
}

/// Proof object can only be created by this crate's verifier.
#[must_use]
#[derive(Clone, Debug)]
pub struct VerifiedApproval {
    fingerprint: [u8; 32],
    issuer_key_id: String,
    issuer_key_version: u64,
    nonce: [u8; 32],
    policy_epoch: u64,
    key_epoch: u64,
    revocation_epoch: u64,
}
impl VerifiedApproval {
    pub fn fingerprint(&self) -> [u8; 32] { self.fingerprint }
    pub fn issuer_key_id(&self) -> &str { &self.issuer_key_id }
    pub fn issuer_key_version(&self) -> u64 { self.issuer_key_version }
    pub fn nonce(&self) -> [u8; 32] { self.nonce }
    pub fn policy_epoch(&self) -> u64 { self.policy_epoch }
    pub fn key_epoch(&self) -> u64 { self.key_epoch }
    pub fn revocation_epoch(&self) -> u64 { self.revocation_epoch }
}

fn valid_token(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn valid_revision(id: &str) -> bool {
    id.len() == 67
        && id.starts_with("r1_")
        && id.as_bytes()[3..].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn framed(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 8 + payload.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn write_str(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}
fn write_opt_revision(out: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        out.push(1);
        write_str(out, value);
    } else {
        out.push(0);
    }
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

impl PromotionRequest {
    pub fn fingerprint(&self, authenticated_subject: &str) -> Result<[u8; 32], VerifyError> {
        if !valid_token(&self.channel, 1, 128)
            || !valid_token(&self.policy_id, 1, 128)
            || !valid_token(&self.idempotency_key, 16, 128)
            || !valid_token(authenticated_subject, 1, 128)
            || !valid_revision(&self.candidate)
            || self.expected_head.as_deref().is_some_and(|id| !valid_revision(id))
            || self.policy_epoch == 0
        {
            return Err(VerifyError::InvalidRequest);
        }
        let mut payload = Vec::new();
        write_str(&mut payload, authenticated_subject);
        write_str(&mut payload, &self.channel);
        write_opt_revision(&mut payload, self.expected_head.as_deref());
        write_str(&mut payload, &self.candidate);
        write_str(&mut payload, &self.policy_id);
        payload.extend_from_slice(&self.policy_digest);
        payload.extend_from_slice(&self.policy_epoch.to_be_bytes());
        payload.extend_from_slice(&self.evidence_digest);
        write_str(&mut payload, &self.idempotency_key);
        Ok(sha256(&framed(REQUEST_DOMAIN, &payload)))
    }
}

impl AuthorizationStatement {
    /// Canonical, fixed-order binary bytes. No JSON, optional extensions,
    /// variable signing algorithms or unknown-field tolerance.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut data = Vec::new();
        write_str(&mut data, &self.audience);
        write_str(&mut data, &self.issuer_key_id);
        data.extend_from_slice(&self.issuer_key_version.to_be_bytes());
        data.push(self.algorithm);
        data.extend_from_slice(&self.request_fingerprint);
        write_str(&mut data, &self.channel);
        write_opt_revision(&mut data, self.expected_head.as_deref());
        write_str(&mut data, &self.candidate);
        write_str(&mut data, &self.policy_id);
        data.extend_from_slice(&self.policy_digest);
        data.extend_from_slice(&self.policy_epoch.to_be_bytes());
        data.extend_from_slice(&self.evidence_digest);
        data.extend_from_slice(&self.key_epoch.to_be_bytes());
        data.extend_from_slice(&self.revocation_epoch.to_be_bytes());
        data.push(self.role.value());
        data.push(self.decision);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.issued_at.to_be_bytes());
        data.extend_from_slice(&self.expires_at.to_be_bytes());
        framed(AUTH_DOMAIN, &data)
    }
}

/// Mandatory failure until contract tests are RED and independent verification
/// is implemented in a separate code review / subsequent commit.
pub fn verify_new_authorization(
    _request: &PromotionRequest,
    _signed: &SignedAuthorization,
    _trust: &TrustView<'_>,
) -> Result<VerifiedApproval, VerifyError> {
    Err(VerifyError::NotImplemented)
}
