use super::{ObjectError, ObjectErrorKind};
use std::collections::HashSet;

/// Normalized portable regular-file path, not an operating system path.
///
/// Unicode is deliberately excluded until a versioned normalization scheme
/// is specified and tested on case-insensitive filesystems.
pub(crate) fn validate_path(path: &str) -> Result<(), ObjectError> {
    if path.is_empty() || path.len() > 1024 || !path.is_ascii() {
        return Err(unsafe_path());
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(unsafe_path());
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > 64 {
        return Err(unsafe_path());
    }
    for (index, component) in components.iter().enumerate() {
        if component.is_empty()
            || *component == "."
            || *component == ".."
            || component.ends_with('.')
        {
            return Err(unsafe_path());
        }
        if index == 0 && (component.eq_ignore_ascii_case(".openscion")
            || component.eq_ignore_ascii_case(".git")) {
            return Err(unsafe_path());
        }

        // Windows reserves device basenames, including names followed by
        // extensions, across several filesystem APIs.
        let basename = component.split('.').next().unwrap_or(component);
        let name = basename.to_ascii_uppercase();
        let reserved = matches!(name.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || matches!(name.as_bytes(), [b'C', b'O', b'M', b'1'..=b'9'])
            || matches!(name.as_bytes(), [b'L', b'P', b'T', b'1'..=b'9']);
        if reserved {
            return Err(unsafe_path());
        }
    }
    Ok(())
}

pub(crate) fn validate_entry_paths<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<(), ObjectError> {
    let mut seen = HashSet::new();
    for path in paths {
        validate_path(path)?;
        if !seen.insert(path.to_ascii_lowercase()) {
            return Err(ObjectError::new(
                ObjectErrorKind::InvalidSnapshot,
                "duplicate or case-colliding snapshot path",
            ));
        }
    }

    for path in &seen {
        let segments: Vec<&str> = path.split('/').collect();
        for count in 1..segments.len() {
            if seen.contains(&segments[..count].join("/")) {
                return Err(ObjectError::new(
                    ObjectErrorKind::InvalidSnapshot,
                    "snapshot path is both a file and an ancestor directory",
                ));
            }
        }
    }
    Ok(())
}

fn unsafe_path() -> ObjectError {
    ObjectError::new(ObjectErrorKind::UnsafePath, "unsafe or nonportable snapshot path")
}
