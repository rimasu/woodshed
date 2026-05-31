use crate::{EntryId, SegmentId};

// ── SegmentIndex ──────────────────────────────────────────────────────────────

/// Per-segment entry index: a list of `(external_id, byte_offset)` checkpoint
/// pairs recorded at a fixed stride during segment scanning. IDs are strictly
/// monotone but not necessarily contiguous.
pub struct SegmentIndex {
    checkpoints: Vec<(EntryId, u64)>,
}

impl SegmentIndex {
    pub fn new(checkpoints: Vec<(EntryId, u64)>) -> Self {
        Self { checkpoints }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.checkpoints.len() }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool { self.checkpoints.is_empty() }

    #[cfg(test)]
    pub fn checkpoint(&self, i: usize) -> Option<(EntryId, u64)> {
        self.checkpoints.get(i).copied()
    }

    /// First checkpoint entry id, or `None` if empty.
    pub fn first_id(&self) -> Option<EntryId> {
        self.checkpoints.first().map(|(id, _)| *id)
    }

    /// Return the `(checkpoint_entry_id, byte_offset)` pair whose entry id is
    /// the largest checkpoint ≤ `target`. Returns `None` if no checkpoint
    /// precedes or equals `target`.
    pub fn find(&self, target: EntryId) -> Option<(EntryId, u64)> {
        let pos = self.checkpoints.partition_point(|(id, _)| id.0 <= target.0);
        if pos == 0 { return None; }
        Some(self.checkpoints[pos - 1])
    }

    /// Remove checkpoints whose entry id is strictly less than `first_entry`.
    pub fn truncate_start(&mut self, first_entry: EntryId) {
        let n = self.checkpoints.partition_point(|(id, _)| id.0 < first_entry.0);
        self.checkpoints.drain(..n);
    }

    /// Remove checkpoints whose entry id is strictly greater than `last_valid`.
    pub fn truncate_end(&mut self, last_valid: EntryId) {
        let keep = self.checkpoints.partition_point(|(id, _)| id.0 <= last_valid.0);
        self.checkpoints.truncate(keep);
    }
}

// ── EntryIndex ────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub struct IndexPosition {
    pub segment:     SegmentId,
    pub checkpoint:  EntryId,
    pub byte_offset: u64,
}

pub struct EntryIndex {
    segments: Vec<(SegmentId, SegmentIndex)>,
}

impl EntryIndex {
    pub fn new() -> Self {
        Self { segments: Vec::new() }
    }

    /// Add a segment's index. Segments must be added in ascending first-id order.
    pub fn add_segment(&mut self, id: SegmentId, index: SegmentIndex) {
        debug_assert!(self.segments.last().is_none_or(|(_, prev)| {
            match (prev.first_id(), index.first_id()) {
                (Some(a), Some(b)) => a.0 <= b.0,
                _ => true,
            }
        }));
        self.segments.push((id, index));
    }

    /// Return the position to start scanning from to reach `target`.
    /// Returns `None` if the target precedes all indexed checkpoints.
    pub fn find(&self, target: EntryId) -> Option<IndexPosition> {
        let pos = self.segments.partition_point(|(_, idx)| {
            idx.first_id().is_some_and(|id| id.0 <= target.0)
        });
        if pos == 0 { return None; }
        let (seg_id, seg_idx) = &self.segments[pos - 1];
        seg_idx.find(target).map(|(checkpoint, byte_offset)| IndexPosition {
            segment: *seg_id,
            checkpoint,
            byte_offset,
        })
    }

    /// Remove index entries covering entries before `first_entry`.
    pub fn truncate_start(&mut self, first_entry: EntryId) {
        let pos = self.segments.partition_point(|(_, idx)| {
            idx.first_id().is_some_and(|id| id.0 <= first_entry.0)
        });
        if pos == 0 { return; }
        self.segments.drain(..pos - 1);
        self.segments[0].1.truncate_start(first_entry);
    }

    /// Remove index entries covering entries after `last_valid`.
    pub fn truncate_end(&mut self, last_valid: EntryId) {
        let pos = self.segments.partition_point(|(_, idx)| {
            idx.first_id().is_some_and(|id| id.0 <= last_valid.0)
        });
        self.segments.truncate(pos);
        if let Some((_, idx)) = self.segments.last_mut() {
            idx.truncate_end(last_valid);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(n: u32) -> SegmentId { SegmentId(n) }
    fn entry(n: u64) -> EntryId { EntryId(n) }

    // ── SegmentIndex ──────────────────────────────────────────────────────────

    /// Two checkpoints: entry(0) at offset 8, entry(64) at offset 1024.
    fn seg_index() -> SegmentIndex {
        SegmentIndex::new(vec![(entry(0), 8), (entry(64), 1024)])
    }

    #[test]
    fn seg_find_exact_match() {
        assert_eq!(seg_index().find(entry(64)), Some((entry(64), 1024)));
    }

    #[test]
    fn seg_find_floor() {
        assert_eq!(seg_index().find(entry(100)), Some((entry(64), 1024)));
    }

    #[test]
    fn seg_find_before_first_checkpoint_returns_none() {
        let s = SegmentIndex::new(vec![(entry(50), 8)]);
        assert!(s.find(entry(10)).is_none());
    }

    #[test]
    fn seg_find_on_empty_returns_none() {
        assert!(SegmentIndex::new(vec![]).find(entry(0)).is_none());
    }

    #[test]
    fn seg_truncate_start_removes_earlier_checkpoints() {
        let mut s = seg_index();
        s.truncate_start(entry(64));
        assert!(s.find(entry(0)).is_none());
        assert_eq!(s.find(entry(64)), Some((entry(64), 1024)));
    }

    #[test]
    fn seg_truncate_end_removes_later_checkpoints() {
        let mut s = seg_index();
        s.truncate_end(entry(63));
        assert_eq!(s.find(entry(0)), Some((entry(0), 8)));
        // entry(64) checkpoint removed; floor falls back to entry(0)
        assert_eq!(s.find(entry(64)), Some((entry(0), 8)));
    }

    #[test]
    fn seg_truncate_end_on_boundary_keeps_that_checkpoint() {
        let mut s = seg_index();
        s.truncate_end(entry(64));
        assert_eq!(s.find(entry(64)), Some((entry(64), 1024)));
    }

    #[test]
    fn seg_checkpoint_accessor() {
        let s = seg_index();
        assert_eq!(s.checkpoint(0), Some((entry(0), 8)));
        assert_eq!(s.checkpoint(1), Some((entry(64), 1024)));
        assert!(s.checkpoint(2).is_none());
    }

    // ── gappy ids ─────────────────────────────────────────────────────────────

    #[test]
    fn seg_find_with_gappy_ids() {
        // checkpoints at 1, 100, 500 — large gaps between ids
        let s = SegmentIndex::new(vec![(entry(1), 8), (entry(100), 500), (entry(500), 9000)]);
        assert_eq!(s.find(entry(1)),   Some((entry(1), 8)));
        assert_eq!(s.find(entry(50)),  Some((entry(1), 8)));
        assert_eq!(s.find(entry(100)), Some((entry(100), 500)));
        assert_eq!(s.find(entry(300)), Some((entry(100), 500)));
        assert_eq!(s.find(entry(500)), Some((entry(500), 9000)));
        assert_eq!(s.find(entry(999)), Some((entry(500), 9000)));
        assert!(s.find(entry(0)).is_none());
    }

    // ── EntryIndex ────────────────────────────────────────────────────────────

    fn populated() -> EntryIndex {
        let mut idx = EntryIndex::new();
        // seg(1): checkpoints at entry(0) and entry(64)
        idx.add_segment(seg(1), SegmentIndex::new(vec![(entry(0), 8), (entry(64), 1024)]));
        // seg(2): checkpoints at entry(128) and entry(192)
        idx.add_segment(seg(2), SegmentIndex::new(vec![(entry(128), 8), (entry(192), 1024)]));
        idx
    }

    #[test]
    fn find_exact_match() {
        assert_eq!(
            populated().find(entry(64)),
            Some(IndexPosition { segment: seg(1), checkpoint: entry(64), byte_offset: 1024 })
        );
    }

    #[test]
    fn find_between_points_returns_floor() {
        assert_eq!(
            populated().find(entry(100)),
            Some(IndexPosition { segment: seg(1), checkpoint: entry(64), byte_offset: 1024 })
        );
    }

    #[test]
    fn find_before_all_segments_returns_none() {
        let mut idx = EntryIndex::new();
        idx.add_segment(seg(1), SegmentIndex::new(vec![(entry(50), 8)]));
        assert!(idx.find(entry(10)).is_none());
    }

    #[test]
    fn find_on_empty_index_returns_none() {
        assert!(EntryIndex::new().find(entry(0)).is_none());
    }

    #[test]
    fn find_last_point() {
        assert_eq!(
            populated().find(entry(999)),
            Some(IndexPosition { segment: seg(2), checkpoint: entry(192), byte_offset: 1024 })
        );
    }

    #[test]
    fn truncate_start_drops_earlier_segment() {
        let mut idx = populated();
        idx.truncate_start(entry(128));
        assert!(idx.find(entry(64)).is_none());
        assert_eq!(
            idx.find(entry(128)),
            Some(IndexPosition { segment: seg(2), checkpoint: entry(128), byte_offset: 8 })
        );
    }

    #[test]
    fn truncate_start_at_first_entry_keeps_all() {
        let mut idx = populated();
        idx.truncate_start(entry(0));
        assert_eq!(
            idx.find(entry(0)),
            Some(IndexPosition { segment: seg(1), checkpoint: entry(0), byte_offset: 8 })
        );
    }

    #[test]
    fn truncate_end_drops_later_segment() {
        let mut idx = populated();
        idx.truncate_end(entry(127));
        assert_eq!(
            idx.find(entry(64)),
            Some(IndexPosition { segment: seg(1), checkpoint: entry(64), byte_offset: 1024 })
        );
        // seg2 gone; entry 128 now floors to seg1's last checkpoint
        assert_eq!(
            idx.find(entry(128)),
            Some(IndexPosition { segment: seg(1), checkpoint: entry(64), byte_offset: 1024 })
        );
    }

    #[test]
    fn truncate_end_on_exact_boundary_keeps_that_point() {
        let mut idx = populated();
        idx.truncate_end(entry(128));
        assert_eq!(
            idx.find(entry(128)),
            Some(IndexPosition { segment: seg(2), checkpoint: entry(128), byte_offset: 8 })
        );
        // entry(192) checkpoint trimmed; floors to entry(128)
        assert_eq!(
            idx.find(entry(192)),
            Some(IndexPosition { segment: seg(2), checkpoint: entry(128), byte_offset: 8 })
        );
    }

    #[test]
    fn truncate_end_mid_segment() {
        let mut idx = populated();
        idx.truncate_end(entry(191));
        assert_eq!(
            idx.find(entry(128)),
            Some(IndexPosition { segment: seg(2), checkpoint: entry(128), byte_offset: 8 })
        );
        assert_eq!(
            idx.find(entry(192)),
            Some(IndexPosition { segment: seg(2), checkpoint: entry(128), byte_offset: 8 })
        );
    }
}
