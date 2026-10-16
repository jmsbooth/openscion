use super::{ObjectError, ObjectErrorKind};
use sha2::{Digest, Sha256};
use std::fmt;

/// Immutable object namespace, independent of any filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    Blob,
    Snapshot,
    Proposal,
    Revision,
}

impl ObjectKind {
    pub(crate) const fn tag(self) -> &'static str {
        match self {
            Self::Blob => "b1",
            Self::Snapshot => "s1",
            Self::Proposal => "p1",
            Self::Revision => "r1",
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Blob => b"openscion.blob.v1\0",
            Self::Snapshot => b"openscion.snapshot.v1\0",
            Self::Proposal => b"openscion.proposal.v1\0",
            Self::Revision => b"openscion.revision.v1\0",
        }
    }
}

/// Exactly 32 bytes of digest plus a type namespace.
///
/// Domain-separated digests prevent interchanging a blob and snapshot with
/// an identical raw payload. This ID does not certify authorship or trust.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectId {
    kind: ObjectKind,
    digest: [u8; 32],
}

impl ObjectId {
    pub fn for_content(kind: ObjectKind, payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(kind.domain());
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        let digest = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        Self {
            kind,
            digest: result,
        }
    }

    pub fn parse(input: &str) -> Result<Self, ObjectError> {
        if input.len() != 67 {
            return Err(ObjectError::new(ObjectErrorKind::InvalidId, "invalid object ID length"));
        }
        let kind = match input.get(..3) {
            Some("b1_") => ObjectKind::Blob,
            Some("s1_") => ObjectKind::Snapshot,
            Some("p1_") => ObjectKind::Proposal,
            Some("r1_") => ObjectKind::Revision,
            _ => {
                return Err(ObjectError::new(
                    ObjectErrorKind::InvalidId,
                    "invalid object ID prefix",
                ))
            }
        };
        let encoded = input.as_bytes().get(3..).ok_or_else(|| {
            ObjectError::new(ObjectErrorKind::InvalidId, "invalid object ID bytes")
        })?;
        let mut digest = [0u8; 32];
        for (i, pair) in encoded.chunks_exact(2).enumerate() {
            let hi = nibble(pair[0]).ok_or_else(|| {
                ObjectError::new(ObjectErrorKind::InvalidId, "invalid object ID hex")
            })?;
            let lo = nibble(pair[1]).ok_or_else(|| {
                ObjectError::new(ObjectErrorKind::InvalidId, "invalid object ID hex")
            })?;
            digest[i] = (hi << 4) | lo;
        }
        Ok(Self { kind, digest })
    }

    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) const fn from_digest(kind: ObjectKind, digest: [u8; 32]) -> Self {
        Self { kind, digest }
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_", self.kind.tag())?;
        for b in self.digest {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Strict lowercase hexadecimal only (canonical ID representation).
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
