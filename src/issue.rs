use std::fmt;
use crate::SegmentId;

#[derive(Debug)]
pub(crate) enum FileRef {
    Directory,
    Manifest,
    Segment(SegmentId),
}

impl fmt::Display for FileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileRef::Directory       => f.write_str("directory"),
            FileRef::Manifest        => f.write_str("manifest"),
            FileRef::Segment(id)     => write!(f, "{:08x}.seg", id.0),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{issue} [{file}]")]
pub(crate) struct FileIssue {
    pub(crate) file: FileRef,
    pub(crate) issue: Issue,
}


#[derive(Debug, thiserror::Error)]
pub(crate) enum Issue {
    // ── Fatal ─────────────────────────────────────────────────────────────
    #[error("directory not found")]
    DirectoryNotFound,
    #[error("directory not readable")]
    DirectoryNotReadable,
    #[error("manifest not found")]
    ManifestNotFound,
    #[error("manifest not readable")]
    ManifestNotReadable,
    #[error("manifest checksum corrupt at offset {offset}")]
    ManifestChecksumCorrupt { offset: u64 },
    #[error("manifest is empty (no segments recorded)")]
    ManifestEmpty,
    #[error("sealed segment file missing")]
    SealedSegmentMissing,
    #[error("sealed segment size mismatch: expected {expected}, actual {actual}")]
    SealedSegmentSizeMismatch { expected: u64, actual: u64 },
    #[error("active segment file missing")]
    ActiveSegmentMissing,

    // ── Approval ──────────────────────────────────────────────────────────
    #[error("sealed segment checksum corrupt at offset {corrupt_at}")]
    SealedSegmentChecksumCorrupt { corrupt_at: u64 },

    // ── Auto ──────────────────────────────────────────────────────────────
    #[error("dead segment file not found on disk")]
    DeadSegmentNotFound,
    #[error("orphan segment found on disk with no manifest record")]
    OrphanSegmentFound,
    #[error("manifest has torn tail; truncatable to {truncate_to}")]
    ManifestTornTail { truncate_to: u64 },
    #[error("active segment has torn tail; truncatable to {truncate_to}")]
    ActiveSegmentTornTail { truncate_to: u64 },
}


/// A diagnostic snapshot of issues found during a store scan.
///
/// Carried by [`OpenError`](crate::OpenError) and [`RecoveryError`](crate::RecoveryError)
/// variants. Display with `{}` for a human-readable list.
#[derive(Debug)]
pub struct IssueReport {
    issues: Vec<FileIssue>,
}

impl fmt::Display for IssueReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} issue(s):", self.issues.len())?;
        for issue in &self.issues {
            write!(f, "\n  {issue}")?;
        }
        Ok(())
    }
}

impl IssueReport {
    pub(crate) fn new() -> Self {
        Self { issues: Vec::new() }
    }

    pub(crate) fn push(&mut self, file: FileRef, issue: Issue) {
        self.issues.push(FileIssue { file, issue });
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &FileIssue> {
        self.issues.iter()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }
}
