use std::io;

use tracing::{info, warn};
use crate::SegmentId;
use crate::files;
use crate::frame::FrameCursor;
use crate::manifest;
use crate::scan::ScanReport;
use crate::state::{ManifestOp, Op};
use crate::{
    StoreCfg,
    issue::{
        FileIssue, FileRef,
        Issue::{
            ActiveSegmentMissing, ActiveSegmentTornTail,
            DeadSegmentNotFound, DirectoryNotFound, DirectoryNotReadable, ManifestChecksumCorrupt,
            ManifestEmpty, ManifestNotFound, ManifestNotReadable, ManifestTornTail,
            OrphanSegmentFound, SealedSegmentChecksumCorrupt, SealedSegmentMissing,
            SealedSegmentSizeMismatch,
        },
        IssueReport,
    },
};

/// Error returned by [`Store::recover`].
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// No automatic recovery path exists for the issues found (e.g. missing manifest,
    /// corrupt sealed segment). Manual intervention is required.
    #[error("recovery not possible")]
    NotPossible,
    /// Issues were found that require explicit approval but `approved` was false.
    /// Call [`Store::recover`] to apply them.
    #[error("recovery requires approval")]
    ApprovalRequired,
    /// Recovery ran but issues persisted after all fix-up actions were applied.
    #[error("issues remain after recovery: {0}")]
    RemainingIssues(IssueReport),
    /// An I/O error occurred while applying a fix-up action.
    #[error(transparent)]
    IoError(#[from] io::Error),
}

pub fn attempt_recovery(
    cfg: &StoreCfg,
    report: &ScanReport,
    approved: bool,
) -> Result<(), RecoveryError> {
    if !report.issues.is_empty() {
        warn!(issues = ?report.issues, "store has issues; attempting recovery");
    }

    let mut fix_ups = Vec::new();
    for issue in report.issues.iter() {
        if let Some(fix_up) = create_fix_up(issue) {
            if fix_up.approval_required && !approved {
                return Err(RecoveryError::ApprovalRequired);
            } else {
                fix_ups.push(fix_up)
            }
        } else {
            return Err(RecoveryError::NotPossible);
        }
    }

    fix_ups.sort_by(|a, b| a.phase.cmp(&b.phase));

    for fix_up in fix_ups {
        fix_up.action.log();
        fix_up.action.apply(cfg)?;
    }

    Ok(())
}

#[derive(Ord, Eq, PartialEq, PartialOrd)]
enum FixUpPhase {
    ManifestFileClean,
    ManifestAppends,
    SegmentFileClean,
}

struct FixUp {
    phase: FixUpPhase,
    approval_required: bool,
    action: FixUpAction,
}

enum FixUpAction {
    OrphanFound(SegmentId),
    DeadSegmentMissing(SegmentId),
    TruncateManifest(u64),
    TruncateSegment(SegmentId, u64),
    CreateActiveSegment(SegmentId),
}

impl FixUpAction {
    fn log(&self) {
        match self {
            Self::TruncateManifest(offset) =>
                info!(offset, "recovery: truncating manifest torn tail"),
            Self::TruncateSegment(id, offset) =>
                warn!(segment = ?id, offset, "recovery: truncating segment (data loss)"),
            Self::CreateActiveSegment(id) =>
                warn!(segment = ?id, "recovery: recreating missing active segment (data loss)"),
            Self::DeadSegmentMissing(id) =>
                info!(segment = ?id, "recovery: recording already-absent dead segment"),
            Self::OrphanFound(id) =>
                info!(segment = ?id, "recovery: recording orphan segment in manifest"),
        }
    }

    pub fn apply(&self, cfg: &StoreCfg) -> Result<(), RecoveryError> {
        match self {
            Self::TruncateManifest(offset)        => truncate_manifest(cfg, *offset),
            Self::TruncateSegment(id, offset)     => truncate_segment(cfg, *id, *offset),
            Self::CreateActiveSegment(id)         => create_active_segment(cfg, *id),
            Self::DeadSegmentMissing(id)          => dead_segment_missing(cfg, *id),
            Self::OrphanFound(id)                 => orphan_found(cfg, *id),
        }
    }
}

fn truncate_manifest(cfg: &StoreCfg, offset: u64) -> Result<(), RecoveryError> {
    let (file, _) = files::open_manifest_rw(cfg).map_err(RecoveryError::IoError)?;
    file.set_len(offset).map_err(RecoveryError::IoError)?;
    file.sync_all().map_err(RecoveryError::IoError)
}

fn truncate_segment(cfg: &StoreCfg, id: SegmentId, offset: u64) -> Result<(), RecoveryError> {
    let (file, _) = files::open_segment_rw(cfg, id).map_err(RecoveryError::IoError)?;
    file.set_len(offset).map_err(RecoveryError::IoError)?;
    file.sync_all().map_err(RecoveryError::IoError)
}

fn create_active_segment(cfg: &StoreCfg, id: SegmentId) -> Result<(), RecoveryError> {
    files::create_segment(cfg, id).map(|_| ()).map_err(RecoveryError::IoError)
}

fn dead_segment_missing(cfg: &StoreCfg, id: SegmentId) -> Result<(), RecoveryError> {
    append_manifest_op(cfg, Op::SegmentDeleted { id })
}

fn orphan_found(cfg: &StoreCfg, id: SegmentId) -> Result<(), RecoveryError> {
    append_manifest_op(cfg, Op::RecordOrphan { id })
}

fn append_manifest_op(cfg: &StoreCfg, op: Op) -> Result<(), RecoveryError> {
    let (file, _) = files::open_manifest_rw(cfg).map_err(RecoveryError::IoError)?;
    let offset = file.metadata().map_err(RecoveryError::IoError)?.len();
    let mut cursor = FrameCursor::new(offset);
    manifest::write_op(&mut cursor, &file, &ManifestOp::bare(op)).map_err(RecoveryError::IoError)
}

fn create_fix_up(issue: &FileIssue) -> Option<FixUp> {
    match issue.issue {
        DirectoryNotFound => None,
        DirectoryNotReadable => None,
        ManifestNotFound => None,
        ManifestNotReadable => None,
        ManifestChecksumCorrupt { .. } => None,
        ManifestEmpty => None,
        SealedSegmentMissing => None,
        SealedSegmentSizeMismatch { .. } => None,
        ActiveSegmentMissing => segment_id(issue).and_then(|id| approval(
            FixUpPhase::SegmentFileClean,
            FixUpAction::CreateActiveSegment(id),
        )),
        SealedSegmentChecksumCorrupt { corrupt_at } => segment_id(issue).and_then(|id| approval(
            FixUpPhase::SegmentFileClean,
            FixUpAction::TruncateSegment(id, corrupt_at),
        )),
        DeadSegmentNotFound => segment_id(issue).and_then(|id| auto(
            FixUpPhase::ManifestAppends,
            FixUpAction::DeadSegmentMissing(id),
        )),
        OrphanSegmentFound => segment_id(issue).and_then(|id| auto(
            FixUpPhase::ManifestAppends,
            FixUpAction::OrphanFound(id),
        )),
        ManifestTornTail { truncate_to } => auto(
            FixUpPhase::ManifestFileClean,
            FixUpAction::TruncateManifest(truncate_to),
        ),
        ActiveSegmentTornTail { truncate_to } => segment_id(issue).and_then(|id| auto(
            FixUpPhase::SegmentFileClean,
            FixUpAction::TruncateSegment(id, truncate_to),
        )),
    }
}

fn segment_id(issue: &FileIssue) -> Option<SegmentId> {
    if let FileRef::Segment(id) = issue.file { Some(id) } else { None }
}

fn auto(phase: FixUpPhase, action: FixUpAction) -> Option<FixUp> {
    Some(FixUp { phase, approval_required: false, action })
}

fn approval(phase: FixUpPhase, action: FixUpAction) -> Option<FixUp> {
    Some(FixUp { phase, approval_required: true, action })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files;
    use crate::frame::FrameCursor;
    use crate::manifest::write_op;
    use crate::scan;
    use crate::state::{ManifestOp, Op};
    use crate::{EntryId, SegmentId, StoreCfg};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    fn cfg(dir: &Path) -> StoreCfg {
        StoreCfg { base_dir: dir.to_path_buf(), segment_rollover_trigger_bytes: 64 * 1024 * 1024 }
    }
    fn seg(n: u32) -> SegmentId { SegmentId(n) }
    fn entry(n: u64) -> EntryId { EntryId(n) }

    fn format(cfg: &StoreCfg) {
        let (manifest, offset) = files::create_manifest(cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();
        files::create_segment(cfg, seg(1)).unwrap();
    }

    fn recover(cfg: &StoreCfg, approved: bool) -> Result<(), RecoveryError> {
        let report = scan::scan(cfg);
        attempt_recovery(cfg, &report, approved)
    }

    fn is_clean(cfg: &StoreCfg) -> bool {
        scan::scan(cfg).issues.is_empty()
    }

    fn append_garbage(path: &std::path::PathBuf) {
        let mut f = OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
    }

    // ── Auto fix-ups ──────────────────────────────────────────────────────────

    #[test]
    fn manifest_torn_tail_auto_recovers() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        append_garbage(&dir.path().join("MANIFEST"));

        assert!(matches!(recover(&cfg, false), Ok(())));
        assert!(is_clean(&cfg));
    }

    #[test]
    fn active_segment_torn_tail_auto_recovers() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        append_garbage(&dir.path().join("00000001.seg"));

        assert!(matches!(recover(&cfg, false), Ok(())));
        assert!(is_clean(&cfg));
    }

    #[test]
    fn dead_segment_not_found_auto_recovers() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);

        // RecordOrphan puts seg(2) in the dead set; no file exists for it
        let (file, _) = files::open_manifest_rw(&cfg).unwrap();
        let offset = file.metadata().unwrap().len();
        write_op(&mut FrameCursor::new(offset), &file, &ManifestOp::bare(Op::RecordOrphan { id: seg(2) })).unwrap();

        assert!(matches!(recover(&cfg, false), Ok(())));
        assert!(is_clean(&cfg));
    }

    #[test]
    fn orphan_segment_auto_recovers() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        files::create_segment(&cfg, seg(9)).unwrap();

        assert!(matches!(recover(&cfg, false), Ok(())));
        assert!(is_clean(&cfg));
        // file remains — dead-segment cleanup is not recovery's job
        assert!(dir.path().join("00000009.seg").exists());
    }

    // ── Approval fix-ups ──────────────────────────────────────────────────────

    #[test]
    fn active_segment_missing_requires_approval() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        files::delete_segment(&cfg, seg(1)).unwrap();

        assert!(matches!(recover(&cfg, false), Err(RecoveryError::ApprovalRequired)));
        assert!(matches!(recover(&cfg, true), Ok(())));
        assert!(is_clean(&cfg));
    }

    // ── Fatal issues ──────────────────────────────────────────────────────────

    #[test]
    fn fatal_issue_returns_not_possible() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        // No manifest — ManifestNotFound is unrecoverable
        assert!(matches!(recover(&cfg, false), Err(RecoveryError::NotPossible)));
    }

    // ── Multi-issue ───────────────────────────────────────────────────────────

    #[test]
    fn torn_manifest_and_orphan_both_fixed() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        append_garbage(&dir.path().join("MANIFEST"));
        files::create_segment(&cfg, seg(9)).unwrap();

        assert!(matches!(recover(&cfg, false), Ok(())));
        assert!(is_clean(&cfg));
        assert!(dir.path().join("00000009.seg").exists());
    }
}
