//! FOSS-478 isolated contract experiment.
//!
//! This crate is NOT linked into the OpenScion CLI or promotion service.
//! Only externally authenticated sessions, independently configured trust
//! anchors and trusted clock/revocation snapshots can authorize new changes.
//! Tests are deliberately authored before the verifier implementation.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const REQUEST_DOMAIN: &[u8] = b"openscion.promotion.request.v1\0";
pub const AUTH_DOMAIN: &[u8] = b"openscion.promotion.authorization.v1\0";
pub const MAX_AUTH_BYTES: usize = 4096;
pub const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
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
    /// Actual bounded evidence bundle bytes; never accept digest-only proof.
    pub evidence_bundle: &'a [u8],
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
    EvidenceMissing,
    EvidenceHashMismatch,
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
            Self::EvidenceMissing => "E_EVIDENCE_MISSING",
            Self::EvidenceHashMismatch => "E_EVIDENCE_HASH",
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
    let bytes = value.as_bytes();
    (min..=max).contains(&bytes.len())
        && bytes.first().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.last().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !value.contains("..")
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()
            || matches!(b, b'-' | b'_' | b'.'))
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

/// Bounded, strict wire reader. Variable-sized strings have a length prefix,
/// never trust decoded lengths or accept extra unknown wire fields.
struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }
    fn take(&mut self, size: usize) -> Result<&'a [u8], VerifyError> {
        let end = self.pos.checked_add(size).ok_or(VerifyError::MalformedWire)?;
        let data = self.bytes.get(self.pos..end).ok_or(VerifyError::MalformedWire)?;
        self.pos = end;
        Ok(data)
    }
    fn byte(&mut self) -> Result<u8, VerifyError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, VerifyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, VerifyError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], VerifyError> {
        self.take(N)?.try_into().map_err(|_| VerifyError::MalformedWire)
    }
    fn string(&mut self, max: usize) -> Result<String, VerifyError> {
        let count = self.u32()? as usize;
        if count == 0 || count > max { return Err(VerifyError::MalformedWire); }
        let s = std::str::from_utf8(self.take(count)?)
            .map_err(|_| VerifyError::MalformedWire)?;
        if !valid_token(s, 1, max) { return Err(VerifyError::MalformedWire); }
        Ok(s.to_owned())
    }
    fn optional_revision(&mut self) -> Result<Option<String>, VerifyError> {
        match self.byte()? {
            0 => Ok(None),
            1 => {
                let s = self.string(67)?;
                if !valid_revision(&s) { return Err(VerifyError::MalformedWire); }
                Ok(Some(s))
            }
            _ => Err(VerifyError::MalformedWire),
        }
    }
    fn end(&self) -> bool { self.pos == self.bytes.len() }
}

impl AuthorizationStatement {
    /// Decode externally supplied canonical bytes. Malformed lengths,
    /// unrecognized versions/domains and trailing extra fields fail closed.
    /// A raw signed JSON boolean can never be interpreted as authorization.
    pub fn decode_canonical(wire: &[u8]) -> Result<Self, VerifyError> {
        if wire.len() > MAX_AUTH_BYTES || wire.len() < AUTH_DOMAIN.len() + 8
            || !wire.starts_with(AUTH_DOMAIN)
        {
            return Err(VerifyError::MalformedWire);
        }
        let mut container = Decoder::new(&wire[AUTH_DOMAIN.len()..]);
        let size = container.u64()?;
        if size != (wire.len() - AUTH_DOMAIN.len() - 8) as u64 {
            // An extra suffix, misleading field length or alternate framing
            // cannot be reinterpreted as an independently signed statement.
            return Err(VerifyError::NonCanonical);
        }
        let body = container.take(size as usize)?;
        if !container.end() { return Err(VerifyError::NonCanonical); }
        let mut d = Decoder::new(body);
        let audience = d.string(128)?;
        let issuer_key_id = d.string(128)?;
        let issuer_key_version = d.u64()?;
        let algorithm = d.byte()?;
        let request_fingerprint = d.array()?;
        let channel = d.string(128)?;
        let expected_head = d.optional_revision()?;
        let candidate = d.string(67)?;
        if !valid_revision(&candidate) { return Err(VerifyError::MalformedWire); }
        let policy_id = d.string(128)?;
        let policy_digest = d.array()?;
        let policy_epoch = d.u64()?;
        let evidence_digest = d.array()?;
        let key_epoch = d.u64()?;
        let revocation_epoch = d.u64()?;
        let role = match d.byte()? {
            1 => Role::Agent,
            2 => Role::Reviewer,
            _ => return Err(VerifyError::MalformedWire),
        };
        let decision = d.byte()?;
        let nonce = d.array()?;
        let issued_at = d.u64()?;
        let expires_at = d.u64()?;
        if !d.end() { return Err(VerifyError::NonCanonical); }
        let decoded = Self {
            audience,
            issuer_key_id,
            issuer_key_version,
            algorithm,
            request_fingerprint,
            channel,
            expected_head,
            candidate,
            policy_id,
            policy_digest,
            policy_epoch,
            evidence_digest,
            key_epoch,
            revocation_epoch,
            role,
            decision,
            nonce,
            issued_at,
            expires_at,
        };
        if decoded.encode_canonical() != wire {
            return Err(VerifyError::NonCanonical);
        }
        Ok(decoded)
    }
}

/// Checks a NEW promotion approval. This function is stateless and never
/// moves heads or consumes nonces: the future single-owner authority must
/// repeat nonce/epoch/idempotency checks inside its atomic transaction.
///
/// An already durably accepted idempotent retry is NOT passed here after
/// issuer revocation. It is recovered separately from an authenticated,
/// integrity-checked durable receipt (SPEC-004 PROM-019).
pub fn verify_new_authorization(
    request: &PromotionRequest,
    signed: &SignedAuthorization,
    trust: &TrustView<'_>,
) -> Result<VerifiedApproval, VerifyError> {
    // The subject is resolved by a trusted transport, not request fields.
    let fingerprint = request.fingerprint(trust.authenticated_subject)?;
    let auth = AuthorizationStatement::decode_canonical(&signed.statement_bytes)?;

    // Fixed algorithm allowlist; never allow a peer-chosen fallback.
    if auth.algorithm != ALG_ED25519 {
        return Err(VerifyError::WrongAlgorithm);
    }
    let issuer = trust.issuers.iter()
        .find(|key| key.key_id == auth.issuer_key_id
            && key.key_version == auth.issuer_key_version)
        .ok_or(VerifyError::UntrustedIssuer)?;
    let verifying_key = VerifyingKey::from_bytes(&issuer.public_key)
        .map_err(|_| VerifyError::UntrustedIssuer)?;
    let signature = Signature::from_bytes(&signed.signature);
    verifying_key.verify_strict(&signed.statement_bytes, &signature)
        .map_err(|_| VerifyError::InvalidSignature)?;

    // Check every signed approval field against the server-derived request
    // fingerprint AND the individually decoded fields. No stale binding,
    // "passed=true", actor claim or wrong audience can authorize promotion.
    if auth.audience != trust.audience
        || auth.request_fingerprint != fingerprint
        || auth.channel != request.channel
        || auth.expected_head != request.expected_head
        || auth.candidate != request.candidate
        || auth.policy_id != request.policy_id
        || auth.policy_digest != request.policy_digest
        || auth.policy_epoch != request.policy_epoch
        || auth.evidence_digest != request.evidence_digest
    {
        return Err(VerifyError::ScopeMismatch);
    }
    // The presence of a signed digest alone does not prove that the
    // referenced evidence exists or was transferred without corruption.
    // Hash the independently supplied bounded bytes before any acceptance.
    if trust.evidence_bundle.is_empty() || trust.evidence_bundle.len() > MAX_EVIDENCE_BYTES {
        return Err(VerifyError::EvidenceMissing);
    }
    if sha256(trust.evidence_bundle) != request.evidence_digest {
        return Err(VerifyError::EvidenceHashMismatch);
    }

    if !valid_token(trust.audience, 1, 128)
        || request.channel != trust.policy.channel
        || request.policy_id != trust.policy.policy_id
        || request.policy_digest != trust.policy.policy_digest
        || request.policy_epoch != trust.policy.policy_epoch
    {
        return Err(VerifyError::PolicyStale);
    }
    if auth.decision != DECISION_ALLOW { return Err(VerifyError::DecisionDenied); }
    if auth.role != Role::Reviewer || issuer.role != Role::Reviewer {
        return Err(VerifyError::RoleDenied);
    }
    if !valid_token(&issuer.principal_id, 1, 128)
        || issuer.principal_id == trust.authenticated_subject
    {
        return Err(VerifyError::SeparationOfDuties);
    }

    let now = trust.now.ok_or(VerifyError::TimeUnavailable)?;
    let revocation = trust.revocation.ok_or(VerifyError::RevocationUnknown)?;
    if revocation.fresh_until < now {
        return Err(VerifyError::RevocationUnknown);
    }
    if auth.key_epoch == 0 || issuer.key_epoch == 0
        || auth.issuer_key_version == 0 || revocation.epoch == 0
        || auth.key_epoch != issuer.key_epoch
        || auth.revocation_epoch != revocation.epoch
    {
        return Err(VerifyError::EpochStale);
    }
    if issuer.revoked || now < issuer.active_from || now > issuer.active_until {
        return Err(VerifyError::KeyRevoked);
    }
    if auth.issued_at > now { return Err(VerifyError::NotYetValid); }
    if auth.expires_at < now
        || auth.expires_at <= auth.issued_at
        || auth.expires_at - auth.issued_at > MAX_AUTH_TTL_SECONDS
    {
        return Err(VerifyError::Expired);
    }
    // Nonce collision screening is read-only. Authority transaction must
    // recheck against authoritative used_nonces immediately before commit.
    if trust.used_nonces.contains(&NonceKey {
        issuer_key_id: issuer.key_id.clone(),
        nonce: auth.nonce,
    }) {
        return Err(VerifyError::NonceReplay);
    }
    Ok(VerifiedApproval {
        fingerprint,
        issuer_key_id: issuer.key_id.clone(),
        issuer_key_version: issuer.key_version,
        nonce: auth.nonce,
        policy_epoch: auth.policy_epoch,
        key_epoch: auth.key_epoch,
        revocation_epoch: auth.revocation_epoch,
    })
}
