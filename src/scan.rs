use std::collections::HashSet;
use std::io;

use crate::files;
use crate::frame::{FrameScanner, ScanStatus};
use crate::index::SegmentIndex;
use crate::issue::{FileRef, IssueReport, Issue};
use crate::manifest;
use crate::state::StoreState;
use crate::{EntryId, SegmentId, StoreCfg};

const INDEX_STRIDE: u64 = 64;

// ── Report types ──────────────────────────────────────────────────────────────

pub struct ScanReport {
    pub state: StoreState,
    pub manifest_next_offset: u64,
    pub segments: Vec<SegmentReport>,
    pub issues: IssueReport,
}

pub struct SegmentReport {
    pub id:            SegmentId,
    pub num_entries:   u64,
    pub write_offset:  u64,
    pub last_entry_id: Option<EntryId>,
    pub index:         SegmentIndex,
}

/// Scan a segment file using [`FrameScanner::scan_all`], verifying checksums
/// and recording index checkpoints every [`INDEX_STRIDE`] entries.
///
/// `expected_len = Some(n)` → sealed segment: verify file size first.
/// `expected_len = None`    → active segment: scan to write frontier.
pub fn scan_segment(
    cfg: &StoreCfg,
    id: SegmentId,
    expected_len: Option<u64>,
    issues: &mut IssueReport,
) -> SegmentReport {
    let is_sealed = expected_len.is_some();
    let mut empty = |issue| {
        issues.push(FileRef::Segment(id), issue);
        SegmentReport {
            id,
            num_entries:   0,
            write_offset:  0,
            last_entry_id: None,
            index:         SegmentIndex::new(vec![]),
        }
    };

    if let Some(expected) = expected_len {
        match files::segment_size(cfg, id) {
            Err(_) => return empty(Issue::SealedSegmentMissing),
            Ok(actual) if actual != expected =>
                return empty(Issue::SealedSegmentSizeMismatch { expected, actual }),
            Ok(_) => {}
        }
    }

    let (file, offset) = match files::open_segment(cfg, id) {
        Ok(r) => r,
        Err(_) => {
            let issue = if is_sealed { Issue::SealedSegmentMissing } else { Issue::ActiveSegmentMissing };
            return empty(issue);
        }
    };

    let summary = match FrameScanner::new(file, offset).scan_all(INDEX_STRIDE) {
        Ok(s) => s,
        Err(_) => {
            let issue = if is_sealed { Issue::SealedSegmentMissing } else { Issue::ActiveSegmentMissing };
            return empty(issue);
        }
    };

    let index = SegmentIndex::new(summary.checkpoints);

    match summary.status {
        ScanStatus::Clean => SegmentReport {
            id,
            num_entries:   summary.count,
            write_offset:  summary.next_offset,
            last_entry_id: summary.last_id,
            index,
        },
        ScanStatus::TornTail | ScanStatus::ChecksumCorrupt => {
            let issue = if is_sealed {
                Issue::SealedSegmentChecksumCorrupt { corrupt_at: summary.next_offset }
            } else {
                Issue::ActiveSegmentTornTail { truncate_to: summary.next_offset }
            };
            issues.push(FileRef::Segment(id), issue);
            SegmentReport { id, num_entries: summary.count, write_offset: 0, last_entry_id: summary.last_id, index }
        }
    }
}

// ── Scan ──────────────────────────────────────────────────────────────────────

fn empty_report(issues: IssueReport) -> ScanReport {
    ScanReport { state: StoreState::empty(), manifest_next_offset: 0, segments: Vec::new(), issues }
}

pub fn scan(cfg: &StoreCfg) -> ScanReport {
    let mut issues = IssueReport::new();

    // ── Phase 0: verify the store directory exists ────────────────────────────
    if !cfg.base_dir.exists() {
        issues.push(FileRef::Directory, Issue::DirectoryNotFound);
        return empty_report(issues);
    }

    // ── Phase 1: open and integrity-scan the manifest ─────────────────────────

    let (manifest_for_scan, manifest_offset) = match files::open_manifest_read(cfg) {
        Ok(r) => r,
        Err(e) => {
            let issue = if e.kind() == io::ErrorKind::NotFound {
                Issue::ManifestNotFound
            } else {
                Issue::ManifestNotReadable
            };
            issues.push(FileRef::Manifest, issue);
            return empty_report(issues);
        }
    };

    let manifest_summary = match FrameScanner::new(manifest_for_scan, manifest_offset).scan_all(1) {
        Ok(s) => s,
        Err(_) => {
            issues.push(FileRef::Manifest, Issue::ManifestNotReadable);
            return empty_report(issues);
        }
    };

    match manifest_summary.status {
        ScanStatus::TornTail => {
            issues.push(FileRef::Manifest, Issue::ManifestTornTail {
                truncate_to: manifest_summary.next_offset,
            });
        }
        ScanStatus::ChecksumCorrupt => {
            issues.push(FileRef::Manifest, Issue::ManifestChecksumCorrupt {
                offset: manifest_summary.next_offset,
            });
            return empty_report(issues);
        }
        ScanStatus::Clean => {}
    }

    // ── Phase 2: replay ops from a fresh manifest handle ─────────────────────

    let (manifest_for_replay, _) = match files::open_manifest_read(cfg) {
        Ok(r) => r,
        Err(_) => {
            issues.push(FileRef::Manifest, Issue::ManifestNotReadable);
            return empty_report(issues);
        }
    };

    let replay = match manifest::replay(manifest_for_replay, manifest_offset) {
        Ok(r) => r,
        Err(manifest::ReplayError::InvalidOp { offset, .. })
        | Err(manifest::ReplayError::ApplyFailed { offset, .. }) => {
            issues.push(FileRef::Manifest, Issue::ManifestChecksumCorrupt { offset });
            return empty_report(issues);
        }
        Err(manifest::ReplayError::Io(_)) => {
            issues.push(FileRef::Manifest, Issue::ManifestNotReadable);
            return empty_report(issues);
        }
    };

    if replay.state.is_empty() {
        issues.push(FileRef::Manifest, Issue::ManifestEmpty);
        return empty_report(issues);
    }

    // ── Phase 3: scan segment files ───────────────────────────────────────────

    let disk_ids = match files::collect_segment_ids(cfg) {
        Ok(ids) => ids,
        Err(e) => {
            let issue = if e.kind() == io::ErrorKind::NotFound {
                Issue::DirectoryNotFound
            } else {
                Issue::DirectoryNotReadable
            };
            issues.push(FileRef::Directory, issue);
            return empty_report(issues);
        }
    };

    find_orphans(&replay.state, &disk_ids, &mut issues);
    find_missing_dead(&replay.state, &disk_ids, &mut issues);

    let segments = replay
        .state
        .segments()
        .iter()
        .map(|seg| {
            let expected_len = replay.state.seal(seg.id).map(|s| s.final_size);
            scan_segment(cfg, seg.id, expected_len, &mut issues)
        })
        .collect();

    ScanReport {
        state: replay.state,
        manifest_next_offset: replay.next_offset,
        segments,
        issues,
    }
}

fn find_missing_dead(state: &StoreState, disk_ids: &[SegmentId], issues: &mut IssueReport) {
    let on_disk: HashSet<SegmentId> = disk_ids.iter().copied().collect();
    for id in state.dead().iter().copied().filter(|id| !on_disk.contains(id)) {
        issues.push(FileRef::Segment(id), Issue::DeadSegmentNotFound);
    }
}

fn find_orphans(state: &StoreState, disk_ids: &[SegmentId], issues: &mut IssueReport) {
    let known: HashSet<SegmentId> = state
        .segments()
        .iter()
        .map(|s| s.id)
        .chain(state.dead().iter().copied())
        .collect();
    for id in disk_ids.iter().copied().filter(|id| !known.contains(id)) {
        issues.push(FileRef::Segment(id), Issue::OrphanSegmentFound);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameCursor;
    use crate::issue::{FileIssue, FileRef, Issue};
    use crate::manifest::write_op;
    use crate::state::{ManifestOp, Op};
    use crate::{EntryId, StoreCfg};
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    use std::path::Path;
    use tempfile::tempdir;

    fn cfg(dir: &Path) -> StoreCfg {
        StoreCfg { base_dir: dir.to_path_buf(), segment_rollover_trigger_bytes: 64 * 1024 * 1024 }
    }
    fn seg(n: u32) -> SegmentId { SegmentId(n) }
    fn entry(n: u64) -> EntryId { EntryId(n) }

    fn has_issue<F: Fn(&FileIssue) -> bool>(report: &ScanReport, pred: F) -> bool {
        report.issues.iter().any(|fi| pred(fi))
    }

    fn setup(dir: &Path) -> (StoreCfg, std::fs::File, u64) {
        let cfg = cfg(dir);
        let (manifest, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();
        files::create_segment(&cfg, seg(1)).unwrap();
        (cfg, manifest, cursor.position())
    }

    fn write_frames(cfg: &StoreCfg, id: SegmentId, base_entry: EntryId, count: usize) {
        let (file, offset) = files::open_segment_rw(cfg, id).unwrap();
        let mut cursor = FrameCursor::new(offset);
        for i in 0..count {
            cursor.write(EntryId(base_entry.0 + i as u64), format!("entry-{i}").as_bytes());
        }
        cursor.flush(&file).unwrap();
    }

    // ── scan_segment tests ────────────────────────────────────────────────────

    fn issues_for_segment(cfg: &StoreCfg, id: SegmentId, expected_len: Option<u64>) -> (SegmentReport, IssueReport) {
        let mut issues = IssueReport::new();
        let report = scan_segment(cfg, id, expected_len, &mut issues);
        (report, issues)
    }

    #[test]
    fn scan_segment_empty_returns_zero_entries() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        files::create_segment(&cfg, seg(1)).unwrap();
        let (r, issues) = issues_for_segment(&cfg, seg(1), None);
        assert_eq!(r.num_entries, 0);
        assert!(r.index.is_empty());
        assert!(issues.is_empty());
    }

    #[test]
    fn scan_segment_records_first_checkpoint_and_stride() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        files::create_segment(&cfg, seg(1)).unwrap();
        // Write 130 frames starting at external id 10.
        write_frames(&cfg, seg(1), entry(10), 130);

        let (r, issues) = issues_for_segment(&cfg, seg(1), None);
        assert_eq!(r.num_entries, 130);
        // Checkpoints at frame 0 (id=10), 64 (id=74), 128 (id=138).
        assert_eq!(r.index.len(), 3);
        assert_eq!(r.index.checkpoint(0).unwrap().0, entry(10));
        assert_eq!(r.index.checkpoint(1).unwrap().0, entry(74));
        assert_eq!(r.index.checkpoint(2).unwrap().0, entry(138));
        assert!(issues.is_empty());
    }

    #[test]
    fn scan_segment_size_mismatch_pushes_issue() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        files::create_segment(&cfg, seg(1)).unwrap();
        let (_, issues) = issues_for_segment(&cfg, seg(1), Some(9999));
        assert!(issues.iter().any(|fi| matches!(fi.issue, Issue::SealedSegmentSizeMismatch { .. })));
    }

    #[test]
    fn scan_segment_missing_pushes_issue() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (_, issues) = issues_for_segment(&cfg, seg(1), None);
        assert!(issues.iter().any(|fi| matches!(fi.issue, Issue::ActiveSegmentMissing)));
    }

    #[test]
    fn scan_segment_torn_tail_returns_partial_results() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        files::create_segment(&cfg, seg(1)).unwrap();
        write_frames(&cfg, seg(1), entry(0), 3);

        let seg_path = dir.path().join("00000001.seg");
        let mut f = std::fs::OpenOptions::new().append(true).open(seg_path).unwrap();
        f.write_all(&[0x00, 0x01]).unwrap();
        f.sync_all().unwrap();

        let (r, issues) = issues_for_segment(&cfg, seg(1), None);
        assert_eq!(r.num_entries, 3);
        assert_eq!(r.index.len(), 1);
        assert!(issues.iter().any(|fi| matches!(fi.issue, Issue::ActiveSegmentTornTail { .. })));
    }

    // ── scan() integration tests ──────────────────────────────────────────────

    #[test]
    fn missing_directory_reported() {
        let cfg = StoreCfg {
            base_dir: "/tmp/woodshed_nonexistent_dir_abc123".into(),
            segment_rollover_trigger_bytes: 64 * 1024 * 1024,
        };
        let report = scan(&cfg);
        assert!(report.issues.iter().any(|fi| matches!(fi.issue, Issue::DirectoryNotFound)));
    }

    #[test]
    fn clean_store_no_issues() {
        let dir = tempdir().unwrap();
        let (cfg, _, _) = setup(dir.path());
        let report = scan(&cfg);
        assert!(report.issues.is_empty());
        assert_eq!(report.segments.len(), 1);
    }

    #[test]
    fn missing_active_segment_reported() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (manifest, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();
        let report = scan(&cfg);
        assert!(has_issue(&report, |fi| matches!(fi.issue, Issue::ActiveSegmentMissing)));
    }

    #[test]
    fn torn_active_segment_tail_reported() {
        let dir = tempdir().unwrap();
        let (cfg, _, _) = setup(dir.path());

        let (seg_file, seg_offset) = files::open_segment_rw(&cfg, seg(1)).unwrap();
        let mut cursor = FrameCursor::new(seg_offset);
        // MAGIC_LEN(8) + HEADER_LEN(20) + payload(8) = 36
        cursor.write(EntryId(1), b"complete");
        cursor.flush(&seg_file).unwrap();
        seg_file.write_at(&[0x00, 0x01], cursor.position()).unwrap();

        let report = scan(&cfg);
        assert!(has_issue(&report, |fi| matches!(fi.issue, Issue::ActiveSegmentTornTail { truncate_to: 36 })));
    }

    #[test]
    fn manifest_torn_tail_reported() {
        let dir = tempdir().unwrap();
        let (cfg, manifest, write_pos) = setup(dir.path());
        manifest.write_at(&[0x00, 0x01], write_pos).unwrap();

        let report = scan(&cfg);
        assert!(has_issue(&report, |fi| matches!(fi.issue, Issue::ManifestTornTail { .. })));
    }

    #[test]
    fn sealed_segment_exact_size_no_issue() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (manifest, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();
        let (seg_file, _) = files::create_segment(&cfg, seg(1)).unwrap();
        let seg_size = seg_file.metadata().unwrap().len();
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::RollSegment {
            sealed_id: seg(1), first_entry: entry(0), last_entry: entry(99),
            entry_count: 100, final_size: seg_size,
            new_id: seg(2), new_first_entry: entry(100),
        })).unwrap();
        files::create_segment(&cfg, seg(2)).unwrap();

        let report = scan(&cfg);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn sealed_segment_size_mismatch_reported() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (manifest, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();
        files::create_segment(&cfg, seg(1)).unwrap();
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::RollSegment {
            sealed_id: seg(1), first_entry: entry(0), last_entry: entry(99),
            entry_count: 100, final_size: 9999,
            new_id: seg(2), new_first_entry: entry(100),
        })).unwrap();
        files::create_segment(&cfg, seg(2)).unwrap();

        let report = scan(&cfg);
        assert!(has_issue(&report, |fi| matches!(fi.issue, Issue::SealedSegmentSizeMismatch { .. })));
    }

    #[test]
    fn missing_dead_segment_reported() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (manifest, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();
        files::create_segment(&cfg, seg(1)).unwrap();
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::RollSegment {
            sealed_id: seg(1), first_entry: entry(0), last_entry: entry(99),
            entry_count: 100, final_size: 8,
            new_id: seg(2), new_first_entry: entry(100),
        })).unwrap();
        files::create_segment(&cfg, seg(2)).unwrap();
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::TruncateStart { first_entry: entry(100), drop: vec![seg(1)] })).unwrap();
        files::delete_segment(&cfg, seg(1)).unwrap();

        let report = scan(&cfg);
        assert!(has_issue(&report, |fi| matches!(fi.issue, Issue::DeadSegmentNotFound) && matches!(fi.file, FileRef::Segment(id) if id == seg(1))));
        assert!(!has_issue(&report, |fi| matches!(fi.issue, Issue::OrphanSegmentFound)));
    }

    #[test]
    fn orphan_below_live_range_found() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (manifest, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);
        write_op(&mut cursor, &manifest, &ManifestOp::bare(Op::CreateSegment { id: seg(5), first_entry: entry(0) })).unwrap();
        files::create_segment(&cfg, seg(5)).unwrap();
        files::create_segment(&cfg, seg(2)).unwrap();

        let report = scan(&cfg);
        assert!(has_issue(&report, |fi| matches!(fi.issue, Issue::OrphanSegmentFound) && matches!(fi.file, FileRef::Segment(id) if id == seg(2))));
    }

    #[test]
    fn orphan_above_live_range_found() {
        let dir = tempdir().unwrap();
        let (cfg, _, _) = setup(dir.path());
        files::create_segment(&cfg, seg(9)).unwrap();

        let report = scan(&cfg);
        assert!(has_issue(&report, |fi| matches!(fi.issue, Issue::OrphanSegmentFound) && matches!(fi.file, FileRef::Segment(id) if id == seg(9))));
    }
}
