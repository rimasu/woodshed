use std::fs::File;
use std::io::{self, Read};

use crate::frame::{FrameScanner, ScanError};
use crate::state::{ApplyError, DecodeError, ManifestOp, StoreState};

// ── Write ─────────────────────────────────────────────────────────────────────

pub fn write_op(cursor: &mut crate::frame::FrameCursor, file: &File, op: &ManifestOp) -> Result<(), io::Error> {
    cursor.write(crate::EntryId(0), &op.encode());
    cursor.flush(file)?;
    file.sync_all()
}

// ── Replay ────────────────────────────────────────────────────────────────────

pub struct ReplayResult {
    pub state:       StoreState,
    pub next_offset: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("invalid op at offset {offset}: {source}")]
    InvalidOp { offset: u64, #[source] source: DecodeError },
    #[error("op apply failed at offset {offset}: {source}")]
    ApplyFailed { offset: u64, #[source] source: ApplyError },
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Replay all ops from the manifest into a fresh [`StoreState`].
///
/// Checksums and torn-tail detection are handled by the scan phase before
/// replay is called. This function performs a pure decode-and-apply pass
/// with no checksum verification.
pub fn replay(file: File, offset: u64) -> Result<ReplayResult, ReplayError> {
    let mut scanner     = FrameScanner::new(file, offset);
    let mut state       = StoreState::empty();
    let mut next_offset = offset;

    loop {
        match scanner.read() {
            Ok(None) => break,
            Ok(Some(mut reader)) => {
                let frame_offset = reader.frame_start();
                let mut payload = Vec::new();
                reader.read_to_end(&mut payload)?;
                let entry = ManifestOp::decode(&payload)
                    .map_err(|source| ReplayError::InvalidOp { offset: frame_offset, source })?;
                state.apply(entry)
                    .map_err(|source| ReplayError::ApplyFailed { offset: frame_offset, source })?;
            }
            // Truncated header: scan should have caught this, but handle gracefully.
            Err(ScanError::Truncated { .. }) => break,
            Err(ScanError::Io(e)) => return Err(ReplayError::Io(e)),
            Err(ScanError::ChecksumMismatch { .. }) => break,
        }
        // Update after the match so the scrutinee temporary (which carries the scanner
        // borrow) is fully dropped before position() is called.
        next_offset = scanner.position();
    }

    Ok(ReplayResult { state, next_offset })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameCursor;
    use crate::state::{ManifestOp, Op};
    use crate::{EntryId, SegmentId, StoreCfg};
    use crate::files;
    use std::os::unix::fs::FileExt;
    use std::path::Path;
    use tempfile::tempdir;

    fn cfg(dir: &Path) -> StoreCfg {
        StoreCfg { base_dir: dir.to_path_buf(), segment_rollover_trigger_bytes: 64 * 1024 * 1024 }
    }

    fn seg(n: u32) -> SegmentId { SegmentId(n) }
    fn entry(n: u64) -> EntryId { EntryId(n) }

    #[test]
    fn empty_manifest_replays_to_empty_state() {
        let dir = tempdir().unwrap();
        let (file, offset) = files::create_manifest(&cfg(dir.path())).unwrap();
        let result = replay(file, offset).unwrap();
        assert!(result.state.is_empty());
        assert_eq!(result.next_offset, offset);
    }

    #[test]
    fn write_and_replay_single_op() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (file, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);

        write_op(&mut cursor, &file, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();

        let (read_file, _) = files::open_manifest_read(&cfg).unwrap();
        let result = replay(read_file, offset).unwrap();

        assert_eq!(result.state.segments().len(), 1);
        assert_eq!(result.state.active_segment_id(), Some(seg(1)));
    }

    #[test]
    fn write_and_replay_multiple_ops() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (file, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);

        write_op(&mut cursor, &file, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();
        write_op(&mut cursor, &file, &ManifestOp::bare(Op::RollSegment {
            sealed_id: seg(1), first_entry: entry(0), last_entry: entry(99),
            entry_count: 100, final_size: 4096,
            new_id: seg(2), new_first_entry: entry(100),
        })).unwrap();

        let (read_file, _) = files::open_manifest_read(&cfg).unwrap();
        let result = replay(read_file, offset).unwrap();

        assert_eq!(result.state.segments().len(), 2);
        assert_eq!(result.state.active_segment_id(), Some(seg(2)));
        assert_eq!(result.state.seal(seg(1)).unwrap().first_entry, entry(0));
        assert_eq!(result.state.seal(seg(1)).unwrap().last_entry, entry(99));
    }

    #[test]
    fn truncated_tail_frame_replays_partial() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (file, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);

        write_op(&mut cursor, &file, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();

        // Write a partial frame at the tail — simulates a torn write.
        file.write_at(&[0x01, 0x00, 0x00], cursor.position()).unwrap();

        let (read_file, _) = files::open_manifest_read(&cfg).unwrap();
        let result = replay(read_file, offset).unwrap();

        // Torn tail is treated as EOF; already-replayed ops are preserved.
        assert_eq!(result.state.segments().len(), 1);
    }

    #[test]
    fn next_offset_advances_past_each_op() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (file, offset) = files::create_manifest(&cfg).unwrap();
        let mut cursor = FrameCursor::new(offset);

        write_op(&mut cursor, &file, &ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) })).unwrap();

        let (read_file, _) = files::open_manifest_read(&cfg).unwrap();
        let result = replay(read_file, offset).unwrap();

        assert_eq!(result.next_offset, cursor.position());
    }
}
