//! Immutable declarations of candidate intent and unpromoted revisions.
//!
//! Actor identity is an unverified claim. No method in this module moves a
//! mutable channel, establishes approval, or promises release provenance.

use super::identity::{ObjectId, ObjectKind};
use super::{ObjectError, ObjectErrorKind, ObjectStore};
use std::collections::HashSet;
use std::fmt;

const PROPOSAL_MAGIC: &[u8; 8] = b"OPROP001";
const REVISION_MAGIC: &[u8; 8] = b"OREV0001";
pub const MAX_PROPOSAL_BYTES: usize = 4096;
pub const MAX_REVISION_BYTES: usize = 105;
pub const MAX_ANCESTRY_DEPTH: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeErrorKind {
    InvalidProposal,
    InvalidRevision,
    WrongType,
    TooLarge,
    Missing,
    Corrupt,
    UnsafePath,
    InvalidStore,
    Io,
}

impl ChangeErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidProposal => "E_PROPOSAL_INVALID",
            Self::InvalidRevision => "E_REVISION_INVALID",
            Self::WrongType => "E_OBJECT_TYPE",
            Self::TooLarge => "E_OBJECT_SIZE",
            Self::Missing => "E_OBJECT_MISSING",
            Self::Corrupt => "E_OBJECT_CORRUPT",
            Self::UnsafePath => "E_UNSAFE_PATH",
            Self::InvalidStore => "E_INVALID_STORE",
            Self::Io => "E_IO",
        }
    }

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidProposal | Self::InvalidRevision | Self::WrongType | Self::TooLarge => 8,
            Self::Missing => 9,
            Self::Corrupt => 10,
            Self::UnsafePath => 3,
            Self::InvalidStore => 6,
            Self::Io => 7,
        }
    }
}

#[derive(Debug)]
pub struct ChangeError {
    pub kind: ChangeErrorKind,
    pub message: String,
}

impl ChangeError {
    fn new(kind: ChangeErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message: message.to_owned(),
        }
    }
}

impl fmt::Display for ChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChangeError {}

impl From<ObjectError> for ChangeError {
    fn from(error: ObjectError) -> Self {
        let kind = match error.kind {
            ObjectErrorKind::WrongType | ObjectErrorKind::InvalidId => ChangeErrorKind::WrongType,
            ObjectErrorKind::TooLarge => ChangeErrorKind::TooLarge,
            ObjectErrorKind::Missing => ChangeErrorKind::Missing,
            ObjectErrorKind::Corrupt => ChangeErrorKind::Corrupt,
            ObjectErrorKind::UnsafePath => ChangeErrorKind::UnsafePath,
            ObjectErrorKind::InvalidStore => ChangeErrorKind::InvalidStore,
            ObjectErrorKind::Io | ObjectErrorKind::AlreadyExists => ChangeErrorKind::Io,
            ObjectErrorKind::InvalidSnapshot => ChangeErrorKind::Corrupt,
        };
        Self { kind, message: error.message }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    base: Option<ObjectId>,
    snapshot: ObjectId,
    actor_claim: String,
    intent: String,
}

impl Proposal {
    pub fn new(
        base: Option<ObjectId>,
        snapshot: ObjectId,
        actor_claim: &str,
        intent: &str,
    ) -> Result<Self, ChangeError> {
        if let Some(ref parent) = base {
            if parent.kind() != ObjectKind::Revision {
                return Err(ChangeError::new(ChangeErrorKind::WrongType, "base must be a revision"));
            }
        }
        if snapshot.kind() != ObjectKind::Snapshot {
            return Err(ChangeError::new(ChangeErrorKind::WrongType, "candidate must be a snapshot"));
        }
        if actor_claim.is_empty()
            || actor_claim.len() > 80
            || !actor_claim.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(ChangeError::new(ChangeErrorKind::InvalidProposal, "invalid declared actor"));
        }
        if intent.is_empty()
            || intent.len() > 2048
            || intent.chars().any(|c| c == '\0' || c == '\r' || (c.is_control() && c != '\n' && c != '\t'))
        {
            return Err(ChangeError::new(ChangeErrorKind::InvalidProposal, "invalid change intent"));
        }
        Ok(Self {
            base,
            snapshot,
            actor_claim: actor_claim.to_owned(),
            intent: intent.to_owned(),
        })
    }

    pub fn base(&self) -> Option<&ObjectId> { self.base.as_ref() }
    pub fn snapshot(&self) -> &ObjectId { &self.snapshot }
    /// This is an unverified claim, not an authenticated identity.
    pub fn actor_claim(&self) -> &str { &self.actor_claim }
    pub fn intent(&self) -> &str { &self.intent }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 1 + 32 + 32 + 2 + self.actor_claim.len() + 2 + self.intent.len());
        out.extend_from_slice(PROPOSAL_MAGIC);
        match &self.base {
            Some(base) => {
                out.push(1);
                out.extend_from_slice(base.digest());
            }
            None => out.push(0),
        }
        out.extend_from_slice(self.snapshot.digest());
        out.extend_from_slice(&(self.actor_claim.len() as u16).to_be_bytes());
        out.extend_from_slice(self.actor_claim.as_bytes());
        out.extend_from_slice(&(self.intent.len() as u16).to_be_bytes());
        out.extend_from_slice(self.intent.as_bytes());
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ChangeError> {
        if raw.len() > MAX_PROPOSAL_BYTES || raw.len() < 8 + 1 + 32 + 2 + 1 + 2 + 1
            || raw.get(..8) != Some(PROPOSAL_MAGIC.as_slice())
        {
            return Err(invalid_proposal());
        }
        let mut offset = 8;
        let present = take(raw, &mut offset, 1)?[0];
        let base = match present {
            0 => None,
            1 => Some(ObjectId::from_digest(ObjectKind::Revision, read_digest(raw, &mut offset)?)),
            _ => return Err(invalid_proposal()),
        };
        let snapshot = ObjectId::from_digest(ObjectKind::Snapshot, read_digest(raw, &mut offset)?);
        let actor_len = read_u16(raw, &mut offset)?;
        let actor = std::str::from_utf8(take(raw, &mut offset, actor_len)?).map_err(|_| invalid_proposal())?;
        let intent_len = read_u16(raw, &mut offset)?;
        let intent = std::str::from_utf8(take(raw, &mut offset, intent_len)?).map_err(|_| invalid_proposal())?;
        if offset != raw.len() {
            return Err(invalid_proposal());
        }
        let proposal = Self::new(base, snapshot, actor, intent).map_err(|_| invalid_proposal())?;
        if proposal.encode() != raw {
            return Err(invalid_proposal());
        }
        Ok(proposal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    parent: Option<ObjectId>,
    snapshot: ObjectId,
    proposal: ObjectId,
}

impl Revision {
    fn from_proposal(proposal_id: ObjectId, proposal: &Proposal) -> Self {
        Self {
            parent: proposal.base.clone(),
            snapshot: proposal.snapshot.clone(),
            proposal: proposal_id,
        }
    }

    pub fn parent(&self) -> Option<&ObjectId> { self.parent.as_ref() }
    pub fn snapshot(&self) -> &ObjectId { &self.snapshot }
    pub fn proposal(&self) -> &ObjectId { &self.proposal }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_REVISION_BYTES);
        out.extend_from_slice(REVISION_MAGIC);
        match &self.parent {
            Some(parent) => {
                out.push(1);
                out.extend_from_slice(parent.digest());
            }
            None => out.push(0),
        }
        out.extend_from_slice(self.snapshot.digest());
        out.extend_from_slice(self.proposal.digest());
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ChangeError> {
        if raw.len() < 73 || raw.len() > MAX_REVISION_BYTES
            || raw.get(..8) != Some(REVISION_MAGIC.as_slice())
        {
            return Err(invalid_revision());
        }
        let mut offset = 8;
        let parent = match take(raw, &mut offset, 1).map_err(|_| invalid_revision())?[0] {
            0 => None,
            1 => Some(ObjectId::from_digest(
                ObjectKind::Revision,
                read_digest(raw, &mut offset).map_err(|_| invalid_revision())?,
            )),
            _ => return Err(invalid_revision()),
        };
        let snapshot = ObjectId::from_digest(
            ObjectKind::Snapshot,
            read_digest(raw, &mut offset).map_err(|_| invalid_revision())?,
        );
        let proposal = ObjectId::from_digest(
            ObjectKind::Proposal,
            read_digest(raw, &mut offset).map_err(|_| invalid_revision())?,
        );
        if offset != raw.len() {
            return Err(invalid_revision());
        }
        let revision = Self { parent, snapshot, proposal };
        if revision.encode() != raw {
            return Err(invalid_revision());
        }
        Ok(revision)
    }
}

impl ObjectStore {
    pub fn put_proposal(&self, proposal: &Proposal) -> Result<ObjectId, ChangeError> {
        self.get_snapshot(proposal.snapshot())?;
        if let Some(parent) = proposal.base() {
            self.verify_ancestry(parent)?;
        }
        self.put_object(ObjectKind::Proposal, &proposal.encode())
            .map_err(Into::into)
    }

    pub fn get_proposal(&self, id: &ObjectId) -> Result<Proposal, ChangeError> {
        let proposal = self.read_proposal_subject(id)?;
        if let Some(base) = proposal.base() {
            self.verify_ancestry(base)?;
        }
        Ok(proposal)
    }

    pub fn create_revision(&self, proposal_id: &ObjectId) -> Result<ObjectId, ChangeError> {
        let proposal = self.get_proposal(proposal_id)?;
        let revision = Revision::from_proposal(proposal_id.clone(), &proposal);
        self.put_object(ObjectKind::Revision, &revision.encode())
            .map_err(Into::into)
    }

    pub fn get_revision(&self, id: &ObjectId) -> Result<Revision, ChangeError> {
        // Validate all the way to a root without recursive Rust calls.
        self.verify_ancestry(id)?;
        let raw = self.get_object(id, ObjectKind::Revision)?;
        Revision::decode(&raw)
    }

    pub fn ancestry(&self, id: &ObjectId) -> Result<Vec<ObjectId>, ChangeError> {
        self.verify_ancestry(id)
    }

    /// Read and verify proposal bytes and candidate snapshot only; this
    /// intentionally does not descend to the base revision. Full ancestry
    /// verification belongs to the iterative visitor below.
    fn read_proposal_subject(&self, id: &ObjectId) -> Result<Proposal, ChangeError> {
        let raw = self.get_object(id, ObjectKind::Proposal)?;
        let proposal = Proposal::decode(&raw)?;
        self.get_snapshot(proposal.snapshot())?;
        Ok(proposal)
    }

    /// Verify every revision and proposal binding iteratively, including
    /// the complete parent lineage. This is bounded and rejects cycles.
    /// It does not authenticate actor_claim or authorize promotion.
    fn verify_ancestry(&self, start: &ObjectId) -> Result<Vec<ObjectId>, ChangeError> {
        let mut visited = HashSet::new();
        let mut chain = Vec::new();
        let mut current = Some(start.clone());
        while let Some(next) = current {
            if chain.len() >= MAX_ANCESTRY_DEPTH || !visited.insert(next.clone()) {
                return Err(ChangeError::new(
                    ChangeErrorKind::InvalidRevision,
                    "ancestor chain exceeds bound or contains a cycle",
                ));
            }
            let raw = self.get_object(&next, ObjectKind::Revision)?;
            let revision = Revision::decode(&raw)?;
            let proposal = self.read_proposal_subject(revision.proposal())?;
            if proposal.base() != revision.parent()
                || proposal.snapshot() != revision.snapshot()
            {
                return Err(ChangeError::new(
                    ChangeErrorKind::InvalidRevision,
                    "revision contains inconsistent proposal references",
                ));
            }
            current = revision.parent().cloned();
            chain.push(next);
        }
        Ok(chain)
    }
}

fn take<'a>(input: &'a [u8], offset: &mut usize, count: usize) -> Result<&'a [u8], ChangeError> {
    let end = offset.checked_add(count).ok_or_else(invalid_proposal)?;
    let slice = input.get(*offset..end).ok_or_else(invalid_proposal)?;
    *offset = end;
    Ok(slice)
}

fn read_digest(raw: &[u8], offset: &mut usize) -> Result<[u8; 32], ChangeError> {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(take(raw, offset, 32)?);
    Ok(digest)
}

fn read_u16(raw: &[u8], offset: &mut usize) -> Result<usize, ChangeError> {
    let bytes = take(raw, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
}

fn invalid_proposal() -> ChangeError {
    ChangeError::new(ChangeErrorKind::InvalidProposal, "invalid canonical proposal bytes")
}

fn invalid_revision() -> ChangeError {
    ChangeError::new(ChangeErrorKind::InvalidRevision, "invalid canonical revision bytes")
}
