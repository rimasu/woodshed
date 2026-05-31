use std::collections::{HashMap, HashSet};

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
// Wire format (all integers big-endian):
//   CreateSegment:  [0x01][id:4][first_entry:8]   [meta]
//   RollSegment:    [0x02][sealed_id:4][first_entry:8][last_entry:8][entry_count:4][final_size:8][new_id:4][new_first_entry:8]   [meta]
//   TruncateStart:  [0x03][first_entry:8][drop_count:4][id:4 × N]   [meta]
//   TruncateEnd:    [0x04][new_active_id:4][byte_offset:8][drop_count:4][id:4 × N]   [meta]
//   SegmentDeleted: [0x05][id:4]   [meta]
//   RecordOrphan:   [0x06][id:4]   [meta]
//   NoOp:           [0x07]   [meta]
//
// Trailing meta section (shared by all ops):
//   [pairs_count:2][key:1][value_len:2][value × N] ...

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
    #[error("truncated op payload")]
    Truncated,
}

impl ManifestOp {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.op {
            Op::CreateSegment { id, first_entry } => {
                buf.push(OP_CREATE_SEGMENT);
                buf.extend_from_slice(&id.0.to_be_bytes());
                buf.extend_from_slice(&first_entry.0.to_be_bytes());
            }
            Op::RollSegment { sealed_id, first_entry, last_entry, entry_count, final_size, new_id, new_first_entry } => {
                buf.push(OP_ROLL_SEGMENT);
                buf.extend_from_slice(&sealed_id.0.to_be_bytes());
                buf.extend_from_slice(&first_entry.0.to_be_bytes());
                buf.extend_from_slice(&last_entry.0.to_be_bytes());
                buf.extend_from_slice(&entry_count.to_be_bytes());
                buf.extend_from_slice(&final_size.to_be_bytes());
                buf.extend_from_slice(&new_id.0.to_be_bytes());
                buf.extend_from_slice(&new_first_entry.0.to_be_bytes());
            }
            Op::TruncateStart { first_entry, drop } => {
                buf.push(OP_TRUNCATE_START);
                buf.extend_from_slice(&first_entry.0.to_be_bytes());
                buf.extend_from_slice(&(drop.len() as u32).to_be_bytes());
                for id in drop {
                    buf.extend_from_slice(&id.0.to_be_bytes());
                }
            }
            Op::TruncateEnd { new_active_id, byte_offset, drop } => {
                buf.push(OP_TRUNCATE_END);
                buf.extend_from_slice(&new_active_id.0.to_be_bytes());
                buf.extend_from_slice(&byte_offset.to_be_bytes());
                buf.extend_from_slice(&(drop.len() as u32).to_be_bytes());
                for id in drop {
                    buf.extend_from_slice(&id.0.to_be_bytes());
                }
            }
            Op::SegmentDeleted { id } => {
                buf.push(OP_SEGMENT_DELETED);
                buf.extend_from_slice(&id.0.to_be_bytes());
            }
            Op::RecordOrphan { id } => {
                buf.push(OP_RECORD_ORPHAN);
                buf.extend_from_slice(&id.0.to_be_bytes());
            }
            Op::Metadata => {
                buf.push(OP_META);
            }
        }
        // Trailing meta section: [pairs_count:2][key:1][value_len:2][value × N] ...
        buf.extend_from_slice(&(self.meta.len() as u16).to_be_bytes());
        for (key, value) in &self.meta {
            buf.push(*key);
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(value);
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<ManifestOp, DecodeError> {
        let mut d = Decoder::new(bytes);
        let op = match d.u8()? {
            OP_CREATE_SEGMENT => Op::CreateSegment {
                id:          SegmentId(d.u32()?),
                first_entry: EntryId(d.u64()?),
            },
            OP_ROLL_SEGMENT => Op::RollSegment {
                sealed_id:       SegmentId(d.u32()?),
                first_entry:     EntryId(d.u64()?),
                last_entry:      EntryId(d.u64()?),
                entry_count:     d.u32()?,
                final_size:      d.u64()?,
                new_id:          SegmentId(d.u32()?),
                new_first_entry: EntryId(d.u64()?),
            },
            OP_TRUNCATE_START => {
                let first_entry = EntryId(d.u64()?);
                let drop_count  = d.u32()? as usize;
                let mut drop = Vec::with_capacity(drop_count.min(64));
                for _ in 0..drop_count { drop.push(SegmentId(d.u32()?)); }
                Op::TruncateStart { first_entry, drop }
            }
            OP_TRUNCATE_END => {
                let new_active_id = SegmentId(d.u32()?);
                let byte_offset   = d.u64()?;
                let drop_count    = d.u32()? as usize;
                let mut drop = Vec::with_capacity(drop_count.min(64));
                for _ in 0..drop_count { drop.push(SegmentId(d.u32()?)); }
                Op::TruncateEnd { new_active_id, byte_offset, drop }
            }
            OP_SEGMENT_DELETED => Op::SegmentDeleted { id: SegmentId(d.u32()?) },
            OP_RECORD_ORPHAN   => Op::RecordOrphan   { id: SegmentId(d.u32()?) },
            OP_META            => Op::Metadata,
            tag                => return Err(DecodeError::UnknownOpType(tag)),
        };
        // Trailing meta section — absent in pre-meta manifests, treated as empty.
        let meta = if d.remaining() >= 2 {
            let pairs_count = d.u16()? as usize;
            let mut meta = Vec::with_capacity(pairs_count.min(32));
            for _ in 0..pairs_count {
                let key       = d.u8()?;
                let value_len = d.u16()? as usize;
                let value     = d.bytes(value_len)?.to_vec();
                meta.push((key, value));
            }
            meta
        } else {
            vec![]
        };
        Ok(ManifestOp { op, meta })
    }
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        let b = self.buf.get(self.pos).copied().ok_or(DecodeError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let end = self.pos.checked_add(2).ok_or(DecodeError::Truncated)?;
        let chunk: &[u8; 2] = self.buf.get(self.pos..end)
            .ok_or(DecodeError::Truncated)?
            .try_into().unwrap();
        self.pos = end;
        Ok(u16::from_be_bytes(*chunk))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let end = self.pos.checked_add(4).ok_or(DecodeError::Truncated)?;
        let chunk: &[u8; 4] = self.buf.get(self.pos..end)
            .ok_or(DecodeError::Truncated)?
            .try_into().unwrap();
        self.pos = end;
        Ok(u32::from_be_bytes(*chunk))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let end = self.pos.checked_add(8).ok_or(DecodeError::Truncated)?;
        let chunk: &[u8; 8] = self.buf.get(self.pos..end)
            .ok_or(DecodeError::Truncated)?
            .try_into().unwrap();
        self.pos = end;
        Ok(u64::from_be_bytes(*chunk))
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(len).ok_or(DecodeError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
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
        assert!(matches!(ManifestOp::decode(&[0xff]), Err(DecodeError::UnknownOpType(0xff))));
    }

    #[test]
    fn codec_empty_payload() {
        assert!(matches!(ManifestOp::decode(&[]), Err(DecodeError::Truncated)));
    }

    #[test]
    fn codec_truncated_create_segment() {
        let encoded = ManifestOp::bare(Op::CreateSegment { id: seg(1), first_entry: entry(0) }).encode();
        assert!(matches!(ManifestOp::decode(&encoded[..5]), Err(DecodeError::Truncated)));
    }
}
