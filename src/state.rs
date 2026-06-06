use std::collections::{HashMap, HashSet};

use yatlv::{FrameBuilder, FrameBuilderLike, FrameParser};

use crate::{EntryId, SegmentId};

// ── ManifestOp ────────────────────────────────────────────────────────────────

/// A manifest record: a structural [`Op`] paired with zero or more metadata key-value pairs.
///
/// On replay each pair overwrites the corresponding key in [`StoreState`]'s metadata map,
/// so repeated writes to the same key are last-write-wins. The `meta` vec is empty for
/// ops that carry no metadata.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManifestOp {
    pub op:   Op,
    pub meta: Vec<(u8, Vec<u8>)>,
}

impl ManifestOp {
    /// Wrap a structural op with no metadata.
    pub fn bare(op: Op) -> Self { Self { op, meta: vec![] } }

    /// Wrap a structural op with metadata pairs.
    pub fn with_meta(op: Op, meta: Vec<(u8, Vec<u8>)>) -> Self { Self { op, meta } }
}

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoreState {
    segments: Vec<SegmentEntry>,
    seals: HashMap<SegmentId, SealInfo>,
    active_segment_id: Option<SegmentId>,
    dead: HashSet<SegmentId>,
    first_entry: EntryId,
    meta: Vec<(u8, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct SegmentEntry {
    pub id: SegmentId,
    pub first_entry: EntryId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SealInfo {
    pub first_entry:  EntryId,
    pub last_entry:   EntryId,
    pub entry_count:  u32,
    pub final_size:   u64,
}

impl StoreState {
    pub fn empty() -> Self {
        Self {
            segments: Vec::new(),
            seals: HashMap::new(),
            active_segment_id: None,
            dead: HashSet::new(),
            first_entry: EntryId(0),
            meta: Vec::new(),
        }
    }

    pub fn segments(&self) -> &[SegmentEntry] { &self.segments }
    pub fn seal(&self, id: SegmentId) -> Option<&SealInfo> { self.seals.get(&id) }
    #[cfg(test)]
    pub fn active_segment_id(&self) -> Option<SegmentId> { self.active_segment_id }
    pub fn dead(&self) -> &HashSet<SegmentId> { &self.dead }
    pub fn first_entry(&self) -> EntryId { self.first_entry }
    /// Current metadata key-value pairs. Last write per key wins across manifest replay.
    pub fn metadata(&self) -> &[(u8, Vec<u8>)] { &self.meta }

    pub fn active_segment(&self) -> Option<&SegmentEntry> {
        let id = self.active_segment_id?;
        self.segments.iter().find(|s| s.id == id)
    }

    pub fn is_empty(&self) -> bool { self.segments.is_empty() }
}

// ── Operations ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// Create the first segment. Only valid on an empty store.
    CreateSegment { id: SegmentId, first_entry: EntryId },

    /// Seal the active segment and open the next. Single atomic operation.
    RollSegment {
        sealed_id:       SegmentId,
        first_entry:     EntryId,
        last_entry:      EntryId,
        entry_count:     u32,
        final_size:      u64,
        new_id:          SegmentId,
        new_first_entry: EntryId,
    },

    /// Advance the log head. Listed segments move to dead; first_entry is the new log head.
    TruncateStart { first_entry: EntryId, drop: Vec<SegmentId> },

    /// Roll back the log tail. Listed segments move to dead; new_active_id is re-activated.
    TruncateEnd {
        new_active_id: SegmentId,
        byte_offset: u64,
        drop: Vec<SegmentId>,
    },

    /// Record that a dead segment's file has been deleted. Removes it from dead set.
    SegmentDeleted { id: SegmentId },

    /// Record a segment file found on disk with no manifest history. Added to the
    /// dead set so routine cleanup will delete it and next_seg_id will fence past it.
    RecordOrphan { id: SegmentId },

    /// No structural effect. Exists solely to carry metadata pairs to disk when no
    /// structural operation is being performed at the same time.
    Metadata,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("create_segment requires an empty store")]
    StoreNotEmpty,
    #[error("roll_segment: {0:?} is not the active segment")]
    NotActiveSegment(SegmentId),
    #[error("truncate_start: {0:?} is before the current first entry")]
    TruncateStartBeforeFirst(EntryId),
    #[error("truncate_end: segment {0:?} not found")]
    SegmentNotFound(SegmentId),
    #[error("segment_deleted: {0:?} is not dead")]
    SegmentNotDead(SegmentId),
}

// ── State machine ─────────────────────────────────────────────────────────────

impl StoreState {
    pub fn apply(&mut self, entry: ManifestOp) -> Result<(), ApplyError> {
        match entry.op {
            Op::CreateSegment { id, first_entry } => self.create_segment(id, first_entry)?,
            Op::RollSegment { sealed_id, first_entry, last_entry, entry_count, final_size, new_id, new_first_entry } =>
                self.roll_segment(sealed_id, first_entry, last_entry, entry_count, final_size, new_id, new_first_entry)?,
            Op::TruncateStart { first_entry, drop } => self.truncate_start(first_entry, drop)?,
            Op::TruncateEnd { new_active_id, byte_offset, drop } =>
                self.truncate_end(new_active_id, byte_offset, drop)?,
            Op::SegmentDeleted { id } => self.segment_deleted(id)?,
            Op::RecordOrphan { id } => { self.dead.insert(id); }
            Op::Metadata => {}
        }
        for (key, value) in entry.meta {
            match self.meta.iter_mut().find(|(k, _)| *k == key) {
                Some(pair) => pair.1 = value,
                None => self.meta.push((key, value)),
            }
        }
        Ok(())
    }

    fn create_segment(&mut self, id: SegmentId, first_entry: EntryId) -> Result<(), ApplyError> {
        if !self.is_empty() {
            return Err(ApplyError::StoreNotEmpty);
        }
        self.first_entry = first_entry;
        self.segments.push(SegmentEntry { id, first_entry });
        self.active_segment_id = Some(id);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn roll_segment(
        &mut self,
        sealed_id: SegmentId,
        first_entry: EntryId,
        last_entry: EntryId,
        entry_count: u32,
        final_size: u64,
        new_id: SegmentId,
        new_first_entry: EntryId,
    ) -> Result<(), ApplyError> {
        if self.active_segment_id != Some(sealed_id) {
            return Err(ApplyError::NotActiveSegment(sealed_id));
        }
        self.seals.insert(sealed_id, SealInfo { first_entry, last_entry, entry_count, final_size });
        self.segments.push(SegmentEntry { id: new_id, first_entry: new_first_entry });
        self.active_segment_id = Some(new_id);
        Ok(())
    }

    fn truncate_start(&mut self, first_entry: EntryId, drop: Vec<SegmentId>) -> Result<(), ApplyError> {
        if first_entry < self.first_entry {
            return Err(ApplyError::TruncateStartBeforeFirst(first_entry));
        }
        for id in drop {
            self.kill_segment(id);
        }
        self.first_entry = first_entry;
        Ok(())
    }

    fn truncate_end(
        &mut self,
        new_active_id: SegmentId,
        _byte_offset: u64,
        drop: Vec<SegmentId>,
    ) -> Result<(), ApplyError> {
        for &id in &drop {
            if !self.segments.iter().any(|s| s.id == id) {
                return Err(ApplyError::SegmentNotFound(id));
            }
        }
        if !self.segments.iter().any(|s| s.id == new_active_id) {
            return Err(ApplyError::SegmentNotFound(new_active_id));
        }
        for id in drop {
            self.kill_segment(id);
        }
        self.seals.remove(&new_active_id);
        self.active_segment_id = Some(new_active_id);
        Ok(())
    }

    fn kill_segment(&mut self, id: SegmentId) {
        self.segments.retain(|s| s.id != id);
        self.seals.remove(&id);
        self.dead.insert(id);
    }

    fn segment_deleted(&mut self, id: SegmentId) -> Result<(), ApplyError> {
        if !self.dead.remove(&id) {
            return Err(ApplyError::SegmentNotDead(id));
        }
        Ok(())
    }
}

// ── Codec ─────────────────────────────────────────────────────────────────────
//
// Each ManifestOp is encoded as a yatlv frame.  Tags:
//   1  TAG_OP_TYPE         u8  — op discriminator (values 0x01–0x07 below)
//   2  TAG_SEGMENT_ID      u32 — primary segment id
//   3  TAG_FIRST_ENTRY     u64
//   4  TAG_LAST_ENTRY      u64
//   5  TAG_ENTRY_COUNT     u32
//   6  TAG_FINAL_SIZE      u64
//   7  TAG_NEW_SEGMENT_ID  u32
//   8  TAG_NEW_FIRST_ENTRY u64
//   9  TAG_BYTE_OFFSET     u64
//  10  TAG_DROP_ID         u32, repeated once per dropped segment id
//  11  TAG_META            sub-frame, repeated once per metadata pair:
//        1  TAG_META_KEY   u8
//        2  TAG_META_VALUE bytes

const TAG_OP_TYPE: u16         = 1;
const TAG_SEGMENT_ID: u16      = 2;
const TAG_FIRST_ENTRY: u16     = 3;
const TAG_LAST_ENTRY: u16      = 4;
const TAG_ENTRY_COUNT: u16     = 5;
const TAG_FINAL_SIZE: u16      = 6;
const TAG_NEW_SEGMENT_ID: u16  = 7;
const TAG_NEW_FIRST_ENTRY: u16 = 8;
const TAG_BYTE_OFFSET: u16     = 9;
const TAG_DROP_ID: u16         = 10;
const TAG_META: u16            = 11;
const TAG_META_KEY: u16        = 1;
const TAG_META_VALUE: u16      = 2;

const OP_CREATE_SEGMENT: u8  = 0x01;
const OP_ROLL_SEGMENT: u8    = 0x02;
const OP_TRUNCATE_START: u8  = 0x03;
const OP_TRUNCATE_END: u8    = 0x04;
const OP_SEGMENT_DELETED: u8 = 0x05;
const OP_RECORD_ORPHAN: u8   = 0x06;
const OP_META: u8            = 0x07;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("unknown op type: {0:#x}")]
    UnknownOpType(u8),
    #[error("malformed frame: {0:?}")]
    Format(yatlv::Error),
}

impl From<yatlv::Error> for DecodeError {
    fn from(e: yatlv::Error) -> Self { DecodeError::Format(e) }
}

impl ManifestOp {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut frame = FrameBuilder::new(&mut buf);
            frame.add_u8(TAG_OP_TYPE, match &self.op {
                Op::CreateSegment { .. }  => OP_CREATE_SEGMENT,
                Op::RollSegment { .. }    => OP_ROLL_SEGMENT,
                Op::TruncateStart { .. }  => OP_TRUNCATE_START,
                Op::TruncateEnd { .. }    => OP_TRUNCATE_END,
                Op::SegmentDeleted { .. } => OP_SEGMENT_DELETED,
                Op::RecordOrphan { .. }   => OP_RECORD_ORPHAN,
                Op::Metadata              => OP_META,
            });
            match &self.op {
                Op::CreateSegment { id, first_entry } => {
                    frame.add_u32(TAG_SEGMENT_ID, id.0);
                    frame.add_u64(TAG_FIRST_ENTRY, first_entry.0);
                }
                Op::RollSegment { sealed_id, first_entry, last_entry, entry_count, final_size, new_id, new_first_entry } => {
                    frame.add_u32(TAG_SEGMENT_ID, sealed_id.0);
                    frame.add_u64(TAG_FIRST_ENTRY, first_entry.0);
                    frame.add_u64(TAG_LAST_ENTRY, last_entry.0);
                    frame.add_u32(TAG_ENTRY_COUNT, *entry_count);
                    frame.add_u64(TAG_FINAL_SIZE, *final_size);
                    frame.add_u32(TAG_NEW_SEGMENT_ID, new_id.0);
                    frame.add_u64(TAG_NEW_FIRST_ENTRY, new_first_entry.0);
                }
                Op::TruncateStart { first_entry, drop } => {
                    frame.add_u64(TAG_FIRST_ENTRY, first_entry.0);
                    for id in drop { frame.add_u32(TAG_DROP_ID, id.0); }
                }
                Op::TruncateEnd { new_active_id, byte_offset, drop } => {
                    frame.add_u32(TAG_NEW_SEGMENT_ID, new_active_id.0);
                    frame.add_u64(TAG_BYTE_OFFSET, *byte_offset);
                    for id in drop { frame.add_u32(TAG_DROP_ID, id.0); }
                }
                Op::SegmentDeleted { id } => { frame.add_u32(TAG_SEGMENT_ID, id.0); }
                Op::RecordOrphan { id }   => { frame.add_u32(TAG_SEGMENT_ID, id.0); }
                Op::Metadata              => {}
            }
            for (key, value) in &self.meta {
                let mut meta = frame.add_frame(TAG_META);
                meta.add_u8(TAG_META_KEY, *key);
                meta.add_data(TAG_META_VALUE, value);
            }
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<ManifestOp, DecodeError> {
        let frame = FrameParser::new(bytes)?;
        let op_type = frame.get_u8(TAG_OP_TYPE)?;
        let op = match op_type {
            OP_CREATE_SEGMENT => Op::CreateSegment {
                id:          SegmentId(frame.get_u32(TAG_SEGMENT_ID)?),
                first_entry: EntryId(frame.get_u64(TAG_FIRST_ENTRY)?),
            },
            OP_ROLL_SEGMENT => Op::RollSegment {
                sealed_id:       SegmentId(frame.get_u32(TAG_SEGMENT_ID)?),
                first_entry:     EntryId(frame.get_u64(TAG_FIRST_ENTRY)?),
                last_entry:      EntryId(frame.get_u64(TAG_LAST_ENTRY)?),
                entry_count:     frame.get_u32(TAG_ENTRY_COUNT)?,
                final_size:      frame.get_u64(TAG_FINAL_SIZE)?,
                new_id:          SegmentId(frame.get_u32(TAG_NEW_SEGMENT_ID)?),
                new_first_entry: EntryId(frame.get_u64(TAG_NEW_FIRST_ENTRY)?),
            },
            OP_TRUNCATE_START => {
                let first_entry = EntryId(frame.get_u64(TAG_FIRST_ENTRY)?);
                let drop = frame.get_u32s(TAG_DROP_ID)
                    .map(|r| r.map(SegmentId))
                    .collect::<Result<Vec<_>, _>>()?;
                Op::TruncateStart { first_entry, drop }
            }
            OP_TRUNCATE_END => {
                let new_active_id = SegmentId(frame.get_u32(TAG_NEW_SEGMENT_ID)?);
                let byte_offset   = frame.get_u64(TAG_BYTE_OFFSET)?;
                let drop = frame.get_u32s(TAG_DROP_ID)
                    .map(|r| r.map(SegmentId))
                    .collect::<Result<Vec<_>, _>>()?;
                Op::TruncateEnd { new_active_id, byte_offset, drop }
            }
            OP_SEGMENT_DELETED => Op::SegmentDeleted { id: SegmentId(frame.get_u32(TAG_SEGMENT_ID)?) },
            OP_RECORD_ORPHAN   => Op::RecordOrphan   { id: SegmentId(frame.get_u32(TAG_SEGMENT_ID)?) },
            OP_META            => Op::Metadata,
            tag                => return Err(DecodeError::UnknownOpType(tag)),
        };
        let meta = frame.get_frames(TAG_META)
            .map(|r| {
                let f     = r?;
                let key   = f.get_u8(TAG_META_KEY)?;
                let value = f.get_data(TAG_META_VALUE)?.to_vec();
                Ok((key, value))
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        Ok(ManifestOp { op, meta })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(n: u32) -> SegmentId { SegmentId(n) }
    fn entry(n: u64) -> EntryId { EntryId(n) }

    fn apply(s: &mut StoreState, op: Op) -> Result<(), ApplyError> {
        s.apply(ManifestOp::bare(op))
    }

    fn state_with_one_segment() -> StoreState {
        let mut s = StoreState::empty();
        apply(&mut s, Op::CreateSegment { id: seg(1), first_entry: entry(0) }).unwrap();
        s
    }

    fn roll(s: &mut StoreState, sealed: u32, first: u64, last: u64, count: u32, size: u64, new: u32, new_first: u64) {
        apply(s, Op::RollSegment {
            sealed_id: seg(sealed), first_entry: entry(first), last_entry: entry(last),
            entry_count: count, final_size: size,
            new_id: seg(new), new_first_entry: entry(new_first),
        }).unwrap();
    }

    // ── state machine ─────────────────────────────────────────────────────────

    #[test]
    fn create_segment_initialises_state() {
        let s = state_with_one_segment();
        assert_eq!(s.first_entry(), entry(0));
        assert_eq!(s.segments().len(), 1);
        assert_eq!(s.active_segment_id(), Some(seg(1)));
        assert!(s.seal(seg(1)).is_none());
    }

    #[test]
    fn create_segment_fails_if_not_empty() {
        let mut s = state_with_one_segment();
        assert!(matches!(
            apply(&mut s, Op::CreateSegment { id: seg(2), first_entry: entry(0) }),
            Err(ApplyError::StoreNotEmpty)
        ));
    }

    #[test]
    fn roll_segment_seals_and_opens_next() {
        let mut s = state_with_one_segment();
        roll(&mut s, 1, 0, 99, 100, 1024, 2, 100);
        assert_eq!(s.segments().len(), 2);
        assert_eq!(s.seal(seg(1)), Some(&SealInfo {
            first_entry: entry(0), last_entry: entry(99), entry_count: 100, final_size: 1024,
        }));
        assert_eq!(s.active_segment_id(), Some(seg(2)));
        assert!(s.seal(seg(2)).is_none());
    }

    #[test]
    fn roll_segment_wrong_id_fails() {
        let mut s = state_with_one_segment();
        assert!(matches!(
            apply(&mut s, Op::RollSegment {
                sealed_id: seg(99), first_entry: entry(0), last_entry: entry(99),
                entry_count: 100, final_size: 0,
                new_id: seg(2), new_first_entry: entry(100),
            }),
            Err(ApplyError::NotActiveSegment(_))
        ));
    }

    #[test]
    fn truncate_start_moves_segments_to_dead() {
        let mut s = state_with_one_segment();
        roll(&mut s, 1, 0, 99, 100, 1024, 2, 100);
        roll(&mut s, 2, 100, 199, 100, 1024, 3, 200);
        apply(&mut s, Op::TruncateStart { first_entry: entry(150), drop: vec![seg(1)] }).unwrap();
        assert_eq!(s.first_entry(), entry(150));
        assert_eq!(s.segments().len(), 2);
        assert_eq!(s.segments()[0].id, seg(2));
        assert_eq!(*s.dead(), HashSet::from([seg(1)]));
        assert!(s.seal(seg(1)).is_none());
    }

    #[test]
    fn truncate_start_before_first_fails() {
        let mut s = state_with_one_segment();
        apply(&mut s, Op::TruncateStart { first_entry: entry(50), drop: vec![] }).unwrap();
        assert!(matches!(
            apply(&mut s, Op::TruncateStart { first_entry: entry(10), drop: vec![] }),
            Err(ApplyError::TruncateStartBeforeFirst(_))
        ));
    }

    #[test]
    fn truncate_end_moves_segments_to_dead_and_reactivates() {
        let mut s = state_with_one_segment();
        roll(&mut s, 1, 0, 99, 100, 1024, 2, 100);
        roll(&mut s, 2, 100, 199, 100, 1024, 3, 200);
        apply(&mut s, Op::TruncateEnd {
            new_active_id: seg(1), byte_offset: 512, drop: vec![seg(2), seg(3)],
        }).unwrap();
        assert_eq!(s.segments().len(), 1);
        assert_eq!(s.active_segment_id(), Some(seg(1)));
        assert!(s.seal(seg(1)).is_none());
        assert_eq!(*s.dead(), HashSet::from([seg(2), seg(3)]));
    }

    #[test]
    fn truncate_end_unknown_segment_fails() {
        let mut s = state_with_one_segment();
        assert!(matches!(
            apply(&mut s, Op::TruncateEnd { new_active_id: seg(99), byte_offset: 0, drop: vec![] }),
            Err(ApplyError::SegmentNotFound(_))
        ));
    }

    #[test]
    fn segment_deleted_removes_from_dead_set() {
        let mut s = state_with_one_segment();
        roll(&mut s, 1, 0, 99, 100, 1024, 2, 100);
        apply(&mut s, Op::TruncateStart { first_entry: entry(100), drop: vec![seg(1)] }).unwrap();
        apply(&mut s, Op::SegmentDeleted { id: seg(1) }).unwrap();
        assert!(!s.dead().contains(&seg(1)));
    }

    #[test]
    fn segment_deleted_on_live_segment_fails() {
        let mut s = state_with_one_segment();
        assert!(matches!(
            apply(&mut s, Op::SegmentDeleted { id: seg(1) }),
            Err(ApplyError::SegmentNotDead(_))
        ));
    }

    #[test]
    fn record_orphan_adds_to_dead_set() {
        let mut s = state_with_one_segment();
        apply(&mut s, Op::RecordOrphan { id: seg(99) }).unwrap();
        assert!(s.dead().contains(&seg(99)));
        assert_eq!(s.segments().len(), 1);
    }

    #[test]
    fn record_orphan_idempotent() {
        let mut s = state_with_one_segment();
        apply(&mut s, Op::RecordOrphan { id: seg(99) }).unwrap();
        apply(&mut s, Op::RecordOrphan { id: seg(99) }).unwrap();
        assert!(s.dead().contains(&seg(99)));
    }

    // ── metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn noop_applies_meta_pairs() {
        let mut s = state_with_one_segment();
        s.apply(ManifestOp::with_meta(Op::Metadata, vec![(1, b"val1".to_vec()), (2, b"val2".to_vec())])).unwrap();
        let meta = s.metadata();
        assert_eq!(meta.iter().find(|(k, _)| *k == 1).map(|(_, v)| v.as_slice()), Some(b"val1".as_ref()));
        assert_eq!(meta.iter().find(|(k, _)| *k == 2).map(|(_, v)| v.as_slice()), Some(b"val2".as_ref()));
    }

    #[test]
    fn meta_last_write_wins() {
        let mut s = state_with_one_segment();
        s.apply(ManifestOp::with_meta(Op::Metadata, vec![(1, b"first".to_vec())])).unwrap();
        s.apply(ManifestOp::with_meta(Op::Metadata, vec![(1, b"second".to_vec())])).unwrap();
        let meta = s.metadata();
        assert_eq!(meta.iter().find(|(k, _)| *k == 1).map(|(_, v)| v.as_slice()), Some(b"second".as_ref()));
        assert_eq!(meta.len(), 1);
    }

    #[test]
    fn structural_op_carries_meta() {
        let mut s = state_with_one_segment();
        s.apply(ManifestOp::with_meta(
            Op::RollSegment {
                sealed_id: seg(1), first_entry: entry(0), last_entry: entry(9),
                entry_count: 10, final_size: 512,
                new_id: seg(2), new_first_entry: entry(10),
            },
            vec![(42, b"data".to_vec())],
        )).unwrap();
        assert_eq!(s.active_segment_id(), Some(seg(2)));
        assert_eq!(s.metadata().iter().find(|(k, _)| *k == 42).map(|(_, v)| v.as_slice()), Some(b"data".as_ref()));
    }

    // ── codec roundtrips ──────────────────────────────────────────────────────

    fn roundtrip(e: ManifestOp) -> ManifestOp {
        ManifestOp::decode(&e.encode()).unwrap()
    }

    #[test]
    fn codec_create_segment() {
        let e = ManifestOp::bare(Op::CreateSegment { id: seg(7), first_entry: entry(42) });
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_roll_segment() {
        let e = ManifestOp::bare(Op::RollSegment {
            sealed_id: seg(1), first_entry: entry(0), last_entry: entry(99),
            entry_count: 100, final_size: 65536,
            new_id: seg(2), new_first_entry: entry(100),
        });
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_truncate_start() {
        let e = ManifestOp::bare(Op::TruncateStart { first_entry: entry(500), drop: vec![seg(1), seg(2)] });
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_truncate_end() {
        let e = ManifestOp::bare(Op::TruncateEnd {
            new_active_id: seg(2), byte_offset: 1024, drop: vec![seg(3), seg(4)],
        });
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_segment_deleted() {
        let e = ManifestOp::bare(Op::SegmentDeleted { id: seg(9) });
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_record_orphan() {
        let e = ManifestOp::bare(Op::RecordOrphan { id: seg(42) });
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_noop() {
        let e = ManifestOp::bare(Op::Metadata);
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_with_meta() {
        let e = ManifestOp::with_meta(Op::Metadata, vec![(1u8, b"hello".to_vec()), (255u8, vec![0xde, 0xad])]);
        assert_eq!(roundtrip(e.clone()), e);
    }

    #[test]
    fn codec_unknown_op_type() {
        let mut buf = Vec::new();
        { let mut f = FrameBuilder::new(&mut buf); f.add_u8(TAG_OP_TYPE, 0xff); }
        assert!(matches!(ManifestOp::decode(&buf), Err(DecodeError::UnknownOpType(0xff))));
    }

    #[test]
    fn codec_empty_payload() {
        assert!(matches!(ManifestOp::decode(&[]), Err(DecodeError::Format(_))));
    }

    #[test]
    fn codec_truncated_create_segment() {
        let encoded = ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) }).encode();
        assert!(matches!(ManifestOp::decode(&encoded[..5]), Err(DecodeError::Format(_))));
    }
}
