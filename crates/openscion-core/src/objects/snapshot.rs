use super::identity::{ObjectId, ObjectKind};
use super::safe_path::validate_entry_paths;
use super::{ObjectError, ObjectErrorKind, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_ENTRIES};

const MAGIC: &[u8; 8] = b"OSNAP001";
const HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEntry {
    pub path: String,
    pub blob: ObjectId,
    pub executable: bool,
}

/// A canonical deterministic list of portable regular-file entries.
///
/// Snapshot represents content identity only. It does not identify actors,
/// approvals or a change's parent revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    entries: Vec<SnapshotEntry>,
}

impl Snapshot {
    pub fn new(entries: &[SnapshotEntry]) -> Result<Self, ObjectError> {
        if entries.len() > MAX_SNAPSHOT_ENTRIES {
            return Err(snapshot_size_error());
        }
        validate_entry_paths(entries.iter().map(|entry| entry.path.as_str()))?;
        let mut size = HEADER_LEN;
        for entry in entries {
            if entry.blob.kind() != ObjectKind::Blob {
                return Err(ObjectError::new(
                    ObjectErrorKind::WrongType,
                    "snapshot can only reference blobs",
                ));
            }
            size = size
                .checked_add(2 + entry.path.len() + 1 + 32)
                .ok_or_else(snapshot_size_error)?;
            if size > MAX_SNAPSHOT_BYTES || entries.len() > u32::MAX as usize {
                return Err(snapshot_size_error());
            }
        }
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        Ok(Self { entries: sorted })
    }

    pub fn entries(&self) -> &[SnapshotEntry] {
        &self.entries
    }

    pub fn encode(&self) -> Vec<u8> {
        // Snapshot::new / ::decode guarantee these lengths are in range.
        let capacity = HEADER_LEN
            + self
                .entries
                .iter()
                .map(|e| 2 + e.path.len() + 1 + 32)
                .sum::<usize>();
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&(entry.path.len() as u16).to_be_bytes());
            out.extend_from_slice(entry.path.as_bytes());
            out.push(u8::from(entry.executable));
            out.extend_from_slice(entry.blob.digest());
        }
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, ObjectError> {
        if input.len() < HEADER_LEN
            || input.len() > MAX_SNAPSHOT_BYTES
            || input.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(invalid_snapshot());
        }

        let count = u32::from_be_bytes([input[8], input[9], input[10], input[11]]) as usize;
        if count > MAX_SNAPSHOT_ENTRIES {
            return Err(invalid_snapshot());
        }
        if count > (input.len() - HEADER_LEN) / 36 {
            return Err(invalid_snapshot());
        }
        let mut offset = HEADER_LEN;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let length_bytes = take(input, &mut offset, 2)?;
            let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
            let raw_path = take(input, &mut offset, length)?;
            let path = std::str::from_utf8(raw_path)
                .map_err(|_| invalid_snapshot())?
                .to_owned();
            let mode = take(input, &mut offset, 1)?[0];
            if mode > 1 {
                return Err(invalid_snapshot());
            }
            let raw_digest = take(input, &mut offset, 32)?;
            let mut digest = [0u8; 32];
            digest.copy_from_slice(raw_digest);
            entries.push(SnapshotEntry {
                path,
                blob: ObjectId::from_digest(ObjectKind::Blob, digest),
                executable: mode == 1,
            });
        }
        if offset != input.len() {
            return Err(invalid_snapshot());
        }

        // Re-encoding also verifies strictly canonical byte-order and
        // path normalization. A reordered manifest is NOT silently accepted.
        let snapshot = Self::new(&entries).map_err(|_| invalid_snapshot())?;
        if snapshot.encode().as_slice() != input {
            return Err(invalid_snapshot());
        }
        Ok(snapshot)
    }
}

fn take<'a>(input: &'a [u8], offset: &mut usize, size: usize) -> Result<&'a [u8], ObjectError> {
    let end = offset.checked_add(size).ok_or_else(invalid_snapshot)?;
    let result = input.get(*offset..end).ok_or_else(invalid_snapshot)?;
    *offset = end;
    Ok(result)
}

fn invalid_snapshot() -> ObjectError {
    ObjectError::new(
        ObjectErrorKind::InvalidSnapshot,
        "invalid canonical snapshot bytes",
    )
}

fn snapshot_size_error() -> ObjectError {
    ObjectError::new(ObjectErrorKind::TooLarge, "snapshot exceeds encoding limit")
}
