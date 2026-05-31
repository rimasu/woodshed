use std::collections::HashMap;
use std::fs::File;
use std::io;

use crate::files;
use crate::frame::{FrameCursor, FrameReader, FrameScanner};
use crate::index::EntryIndex;
use crate::issue::IssueReport;
use crate::recovery::{RecoveryError, attempt_recovery};
use crate::scan::{self, ScanReport};
use crate::state::{ManifestOp, Op, StoreState};
use crate::{EntryId, SegmentId, StoreCfg};

// ── Store ─────────────────────────────────────────────────────────────────────

/// An append-only log store backed by a manifest and one or more segment files.
///
/// # Typical write workflow
///
/// ```no_run
/// # use woodshed::{Store, StoreCfg};
/// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
/// let mut store = Store::open_or_create(cfg)?;
///
/// let mut w = store.writer();
/// w.push(1, b"hello");
/// w.push(2, b"world");
/// let commit = w.write()?;   // frames reach the OS page cache
/// commit.sync()?;             // fsync — data is now durable
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// `write` and `sync` are intentionally separate so that callers can reply to
/// an RPC (e.g. a Raft AppendEntries) before the fsync completes.
///
/// # Typical read workflow
///
/// ```no_run
/// # use woodshed::{Store, StoreCfg, LendingIterator};
/// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
/// # let store = Store::open_or_create(cfg)?;
/// let mut reader = store.scan(1);
/// while let Some(Ok((id, mut entry))) = reader.next() {
///     let mut buf = Vec::new();
///     std::io::Read::read_to_end(&mut entry, &mut buf)?;
///     println!("id={id}: {} bytes", buf.len());
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Store {
    cfg:                StoreCfg,
    state:              StoreState,
    index:              EntryIndex,
    manifest:           File,
    manifest_cursor:    FrameCursor,
    segments:           HashMap<SegmentId, File>,
    active_id:          SegmentId,
    active_cursor:      FrameCursor,
    /// First entry id of the active segment (from manifest).
    active_first_entry: EntryId,
    /// Number of frames written to the active segment.
    active_entry_count: u64,
    /// Id of the last frame written across all segments, or None if empty.
    last_entry_id:      Option<EntryId>,
    next_seg_id:        SegmentId,
    /// True when the active segment exceeded the rollover threshold on the last
    /// commit. The actual rollover happens at the start of the next non-empty commit
    /// so that `new_first_entry` in the RollSegment op is known.
    rollover_pending:   bool,
}

/// Error returned by [`Store::open`] and [`Store::open_or_create`].
///
/// ```no_run
/// # use woodshed::{Store, StoreCfg, OpenError};
/// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
/// match Store::open(cfg.clone()) {
///     Ok(store) => { /* normal path */ }
///     Err(OpenError::ApprovedRecoveredRequired(report)) => {
///         eprintln!("manual approval needed: {report}");
///         Store::recover(&cfg)?;
///     }
///     Err(OpenError::RecoveryNotPossible(report)) => {
///         eprintln!("unrecoverable: {report}");
///     }
///     Err(e) => return Err(e.into()),
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("recovery requires approval: {0}")]
    ApprovedRecoveredRequired(IssueReport),
    #[error("recovery not possible: {0}")]
    RecoveryNotPossible(IssueReport),
    #[error("recovery failed: {0}")]
    RecoveryFailed(#[source] RecoveryError),
}

// ── Open ──────────────────────────────────────────────────────────────────────

impl Store {
    /// Open the store at `cfg.base_dir`, creating a fresh store if none exists.
    ///
    /// Equivalent to calling [`Store::open`] after creating the store files
    /// when they are absent. Prefer this for normal startup where a missing
    /// store is expected on first run.
    pub fn open_or_create(cfg: StoreCfg) -> Result<Self, OpenError> {
        if !files::manifest_exists(&cfg) {
            let create = || -> io::Result<()> {
                let (manifest, offset) = files::create_manifest(&cfg)?;
                let seg_id = SegmentId(1);
                files::create_segment(&cfg, seg_id)?;
                let mut cursor = FrameCursor::new(offset);
                let entry = ManifestOp::bare(Op::CreateSegment { id: seg_id, first_entry: EntryId(0) });
                cursor.write(EntryId(0), &entry.encode());
                cursor.flush(&manifest)
            };
            create().map_err(|e| OpenError::RecoveryFailed(RecoveryError::IoError(e)))?;
        }
        Self::open(cfg)
    }

    /// Open an existing store, automatically recovering minor issues (torn tails,
    /// orphan files) on the way.
    ///
    /// Returns [`OpenError::ApprovedRecoveredRequired`] when issues are present
    /// but fixable — call [`Store::recover`] to apply the fixes, then retry.
    /// Returns [`OpenError::RecoveryNotPossible`] for unrecoverable corruption.
    pub fn open(cfg: StoreCfg) -> Result<Self, OpenError> {
        let report = scan::scan(&cfg);

        if report.issues.is_empty() {
            return Self::from_scan_report(cfg, report);
        }

        attempt_recovery(&cfg, &report, false)
            .map_err(|e| match e {
                RecoveryError::NotPossible    => OpenError::RecoveryNotPossible(report.issues),
                RecoveryError::ApprovalRequired => OpenError::ApprovedRecoveredRequired(report.issues),
                _ => OpenError::RecoveryFailed(e),
            })?;

        let report = scan::scan(&cfg);
        Self::from_scan_report(cfg, report).map_err(|e| match e {
            OpenError::RecoveryNotPossible(issues) =>
                OpenError::RecoveryFailed(RecoveryError::RemainingIssues(issues)),
            other => other,
        })
    }

    /// Apply all fixable issues found during a scan, with full approval.
    ///
    /// Call this when [`Store::open`] returns
    /// [`OpenError::ApprovedRecoveredRequired`], then retry [`Store::open`].
    ///
    /// ```no_run
    /// # use woodshed::{Store, StoreCfg, OpenError};
    /// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
    /// let store = match Store::open(cfg.clone()) {
    ///     Ok(s) => s,
    ///     Err(OpenError::ApprovedRecoveredRequired(_)) => {
    ///         Store::recover(&cfg)?;
    ///         Store::open(cfg)?
    ///     }
    ///     Err(e) => return Err(e.into()),
    /// };
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn recover(cfg: &StoreCfg) -> Result<(), RecoveryError> {
        let report = scan::scan(cfg);
        attempt_recovery(cfg, &report, true)
    }

    /// Id of the oldest accessible entry.
    pub fn first_entry_id(&self) -> u64 {
        self.state.first_entry().0
    }

    /// Id of the last written entry, or `None` if the store is empty.
    pub fn last_entry_id(&self) -> Option<u64> {
        self.last_entry_id.map(|id| id.0)
    }

    fn from_scan_report(cfg: StoreCfg, report: ScanReport) -> Result<Self, OpenError> {
        if !report.issues.is_empty() {
            return Err(OpenError::RecoveryNotPossible(report.issues));
        }

        let active = report.state.active_segment()
            .expect("no issues guarantees a non-empty state with an active segment");
        let active_id = active.id;
        let active_first_entry = active.first_entry;

        let active_report = report.segments.iter()
            .find(|s| s.id == active_id)
            .expect("scan produces a report for every segment in state");

        let active_entry_count = active_report.num_entries;
        let active_write_offset = active_report.write_offset;

        // last_entry_id: prefer active segment's last frame; fall back to last sealed segment.
        let last_entry_id = active_report.last_entry_id.or_else(|| {
            report.state.segments().iter().rev().skip(1)
                .find_map(|seg| report.state.seal(seg.id).map(|s| s.last_entry))
        });

        let max_id = report.state.segments().iter().map(|s| s.id.0)
            .chain(report.state.dead().iter().map(|id| id.0))
            .max()
            .unwrap_or(0);
        let next_seg_id = SegmentId(max_id + 1);

        let mut index = EntryIndex::new();
        for seg in report.segments {
            index.add_segment(seg.id, seg.index);
        }

        let manifest_cursor = FrameCursor::new(report.manifest_next_offset);
        let (manifest, _) = files::open_manifest_rw(&cfg)
            .expect("manifest open failed after clean scan — filesystem race?");

        Ok(Store {
            cfg,
            state: report.state,
            index,
            manifest,
            manifest_cursor,
            segments: HashMap::new(),
            active_id,
            active_cursor: FrameCursor::new(active_write_offset),
            active_first_entry,
            active_entry_count,
            last_entry_id,
            next_seg_id,
            rollover_pending: false,
        })
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

impl Store {
    /// Execute the pending rollover, using `new_first_entry` as the first entry
    /// id of the new segment. Called at the start of the next non-empty commit.
    fn do_rollover(&mut self, new_first_entry: EntryId) -> io::Result<()> {
        let sealed_id    = self.active_id;
        let final_size   = self.active_cursor.position();
        let first_entry  = self.active_first_entry;
        let last_entry   = self.last_entry_id.unwrap_or(first_entry);
        let entry_count  = self.active_entry_count as u32;
        let new_id       = self.next_seg_id;

        metrics::counter!("wal.segment_rollovers_total").increment(1);
        files::create_segment(&self.cfg, new_id)?;

        let op = ManifestOp::bare(Op::RollSegment {
            sealed_id,
            first_entry,
            last_entry,
            entry_count,
            final_size,
            new_id,
            new_first_entry,
        });
        self.manifest_cursor.write(EntryId(0), &op.encode());
        self.manifest_cursor.flush(&self.manifest)?;
        self.manifest.sync_all()?;
        self.state.apply(op).expect("rollover op must be valid against current state");

        self.next_seg_id = SegmentId(new_id.0 + 1);
        self.active_id = new_id;
        // Reset cursor position to start of new segment; buffered bytes remain.
        self.active_cursor.set_position(files::MAGIC_LEN as u64);
        self.active_first_entry = new_first_entry;
        self.active_entry_count = 0;

        Ok(())
    }

    /// Begin a write batch. Push entries with [`StoreWriter::push`], then call
    /// [`StoreWriter::write`] to flush them to the page cache.
    pub fn writer(&mut self) -> StoreWriter<'_> {
        StoreWriter { store: self, first_id: None, last_id: None, count: 0 }
    }
}

// ── Truncation ────────────────────────────────────────────────────────────────

impl Store {
    /// Advance the log head to `first_entry`, atomically writing `meta` pairs.
    ///
    /// Used after a snapshot is applied: entries before the snapshot's last log
    /// index are no longer needed and segments that fall entirely before
    /// `first_entry` become eligible for deletion via
    /// [`delete_dead_segments`](Self::delete_dead_segments).
    ///
    /// The `meta` pairs are written to the manifest in the same operation,
    /// making this suitable for atomically recording the snapshot's last log id
    /// alongside the truncation.
    ///
    /// ```no_run
    /// # use woodshed::{Store, StoreCfg};
    /// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
    /// # let mut store = Store::open_or_create(cfg)?;
    /// // After installing a snapshot through index 999:
    /// let snapshot_last_index = 1000u64;
    /// store.truncate_start(snapshot_last_index, &[(1, snapshot_last_index.to_be_bytes().to_vec())])?;
    /// store.delete_dead_segments()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn truncate_start(&mut self, first_entry: u64, meta: &[(u8, Vec<u8>)]) -> io::Result<()> {
        let first_entry = EntryId(first_entry);
        if first_entry < self.state.first_entry() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "truncate_start: first_entry is before the current log head",
            ));
        }

        let to_evict: Vec<SegmentId> = self.state.segments().iter()
            .filter(|seg| {
                self.state.seal(seg.id)
                    .is_some_and(|info| info.last_entry < first_entry)
            })
            .map(|seg| seg.id)
            .collect();

        let entry = ManifestOp::with_meta(
            Op::TruncateStart { first_entry, drop: to_evict.clone() },
            meta.to_vec(),
        );
        self.manifest_cursor.write(EntryId(0), &entry.encode());
        self.manifest_cursor.flush(&self.manifest)?;
        self.manifest.sync_all()?;
        self.state.apply(entry).expect("truncate_start was pre-validated");
        metrics::counter!("wal.truncate_start_total").increment(1);

        for id in &to_evict {
            self.segments.remove(id);
        }
        self.index.truncate_start(first_entry);

        Ok(())
    }

    /// Roll back the log tail so that `last_valid` is the last entry.
    pub fn truncate_end(&mut self, last_valid: u64) -> io::Result<()> {
        let last_valid = EntryId(last_valid);
        // No-op if last_valid is at or beyond the current last entry.
        if self.last_entry_id.is_none_or(|last| last_valid >= last) {
            return Ok(());
        }

        // Find the segment containing last_valid using sealed first-entry partitioning.
        let segs = self.state.segments();
        let p = segs.partition_point(|s| s.first_entry.0 <= last_valid.0);
        let target_id = if p == 0 { segs[0].id } else { segs[p - 1].id };
        let to_drop: Vec<SegmentId> = segs[p.saturating_sub(1) + 1..]
            .iter().map(|s| s.id).collect();

        // Walk from nearest checkpoint to find the byte offset after last_valid.
        let start_offset = self.index.find(last_valid)
            .filter(|pos| pos.segment == target_id)
            .map(|pos| pos.byte_offset)
            .unwrap_or(files::MAGIC_LEN as u64);

        let (seg_file, _) = files::open_segment(&self.cfg, target_id)?;
        let mut scanner = FrameScanner::new(seg_file, start_offset);
        let byte_offset = scanner.scan_to_after(last_valid)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Truncate the segment file.
        let (rw_file, _) = files::open_segment_rw(&self.cfg, target_id)?;
        rw_file.set_len(byte_offset)?;
        rw_file.sync_all()?;

        let entry = ManifestOp::bare(Op::TruncateEnd {
            new_active_id: target_id,
            byte_offset,
            drop: to_drop.clone(),
        });
        self.manifest_cursor.write(EntryId(0), &entry.encode());
        self.manifest_cursor.flush(&self.manifest)?;
        self.manifest.sync_all()?;
        self.state.apply(entry).expect("truncate_end op was pre-validated");

        for id in &to_drop {
            self.segments.remove(id);
        }
        self.segments.remove(&target_id);

        self.active_id = target_id;
        self.active_cursor = FrameCursor::new(byte_offset);
        self.last_entry_id = Some(last_valid);
        self.rollover_pending = false;
        self.index.truncate_end(last_valid);

        // Recompute active metadata from sealed info or reset.
        if let Some(seal) = self.state.seal(target_id) {
            // target was sealed but is now re-active after truncation; its data
            // is partially intact. active_first_entry and count are approximate
            // (count is not exact post-truncation, which is fine since it's only
            // used for the next RollSegment op).
            self.active_first_entry = seal.first_entry;
            self.active_entry_count = 0; // unknown after truncation; conservative
        } else {
            self.active_first_entry = self.state.segments().iter()
                .find(|s| s.id == target_id)
                .map(|s| s.first_entry)
                .unwrap_or(EntryId(0));
            self.active_entry_count = 0;
        }

        Ok(())
    }
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

impl Store {
    /// Delete all dead segment files from disk and record each deletion in the
    /// manifest.
    ///
    /// Segments become dead after [`truncate_start`](Self::truncate_start) or
    /// [`truncate_end`](Self::truncate_end) removes all live entries they
    /// contained. Woodshed never deletes files automatically — the caller is
    /// responsible for deciding when to reclaim disk space by calling this
    /// method. A natural time to call it is immediately after a snapshot has
    /// been applied and `truncate_start` has been called.
    ///
    /// Returns the number of segment files deleted.
    ///
    /// ```no_run
    /// # use woodshed::{Store, StoreCfg};
    /// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
    /// # let mut store = Store::open_or_create(cfg)?;
    /// // After installing a snapshot through index 999:
    /// store.truncate_start(1000, &[])?;
    /// let deleted = store.delete_dead_segments()?;
    /// println!("reclaimed {deleted} segment(s)");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn delete_dead_segments(&mut self) -> io::Result<usize> {
        let dead: Vec<SegmentId> = self.state.dead().iter().copied().collect();
        let mut deleted = 0;

        for id in dead {
            files::delete_segment(&self.cfg, id)?;
            let entry = ManifestOp::bare(Op::SegmentDeleted { id });
            self.manifest_cursor.write(EntryId(0), &entry.encode());
            self.manifest_cursor.flush(&self.manifest)?;
            self.manifest.sync_all()?;
            self.state.apply(entry).expect("SegmentDeleted on a dead segment must be valid");
            deleted += 1;
        }

        Ok(deleted)
    }
}

// ── Metadata ──────────────────────────────────────────────────────────────────

impl Store {
    pub fn metadata(&self) -> &[(u8, Vec<u8>)] {
        self.state.metadata()
    }

    pub fn write_metadata(&mut self, pairs: Vec<(u8, Vec<u8>)>) -> io::Result<()> {
        let entry = ManifestOp::with_meta(Op::Metadata, pairs);
        self.manifest_cursor.write(EntryId(0), &entry.encode());
        self.manifest_cursor.flush(&self.manifest)?;
        self.manifest.sync_all()?;
        self.state.apply(entry).expect("NoOp must always be valid");
        Ok(())
    }
}

// ── Commit ────────────────────────────────────────────────────────────────────

/// A pending `sync_all` for the active segment, returned by [`StoreWriter::write`].
///
/// Frames have been written to the OS page cache but are not yet durable.
/// Call [`Commit::sync`] to make them durable. Dropping without syncing is
/// allowed but will produce a compiler warning via `#[must_use]`.
#[must_use]
pub struct Commit<'a>(Option<&'a File>);

impl Commit<'_> {
    pub fn sync(self) -> io::Result<()> {
        if let Some(file) = self.0 {
            let t0 = std::time::Instant::now();
            file.sync_all()?;
            metrics::histogram!("wal.sync.seconds").record(t0.elapsed().as_secs_f64());
        }
        Ok(())
    }
}

// ── StoreWriter ───────────────────────────────────────────────────────────────

/// A write batch obtained from [`Store::writer`].
///
/// Push entries with [`push`](Self::push), then call [`write`](Self::write) to
/// flush them to the OS page cache. Entries within a batch are written
/// atomically from the reader's perspective — a torn batch leaves a recoverable
/// torn tail, never partial frames.
///
/// ```no_run
/// # use woodshed::{Store, StoreCfg};
/// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
/// # let mut store = Store::open_or_create(cfg)?;
/// let mut w = store.writer();
/// for (id, payload) in [(1u64, b"a" as &[u8]), (2, b"bb"), (3, b"ccc")] {
///     w.push(id, payload);
/// }
/// let commit = w.write()?;
/// // do other work here before syncing ...
/// commit.sync()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct StoreWriter<'a> {
    store:    &'a mut Store,
    first_id: Option<EntryId>,
    last_id:  Option<EntryId>,
    count:    u64,
}

impl<'a> StoreWriter<'a> {
    /// Buffer `payload` as an entry with caller-provided `id`. IDs must be
    /// strictly increasing across the lifetime of the store.
    pub fn push(&mut self, id: u64, payload: &[u8]) {
        let eid = EntryId(id);
        self.store.active_cursor.write(eid, payload);
        if self.first_id.is_none() { self.first_id = Some(eid); }
        self.last_id = Some(eid);
        self.count += 1;
    }

    /// Write all buffered entries to the active segment (without `sync_all`)
    /// and return a [`Commit`] that the caller must use to make the data
    /// durable. Triggers a lazy segment rollover when needed.
    pub fn write(self) -> io::Result<Commit<'a>> {
        if self.count == 0 {
            return Ok(Commit(None));
        }
        let store = self.store;
        let first = self.first_id.unwrap();
        let last  = self.last_id.unwrap();
        let count = self.count;

        // If a rollover was deferred from the previous write, execute it now
        // that we know the first id of the new batch.
        if store.rollover_pending {
            store.do_rollover(first)?;
            store.rollover_pending = false;
        }

        let id = store.active_id;
        if !store.segments.contains_key(&id) {
            let (file, _) = files::open_segment_rw(&store.cfg, id)?;
            store.segments.insert(id, file);
        }

        let pos_before = store.active_cursor.position();
        let t0 = std::time::Instant::now();
        {
            let file = store.segments.get(&id).unwrap();
            store.active_cursor.flush(file)?;
        }
        metrics::histogram!("wal.write.seconds").record(t0.elapsed().as_secs_f64());
        metrics::counter!("wal.entries_written_total").increment(count);
        metrics::counter!("wal.bytes_written_total")
            .increment(store.active_cursor.position() - pos_before);

        store.last_entry_id      = Some(last);
        store.active_entry_count += count;

        if store.active_cursor.position() > store.cfg.segment_rollover_trigger_bytes {
            store.rollover_pending = true;
        }

        let active_id = store.active_id;
        let file = store.segments.get(&active_id).unwrap();
        Ok(Commit(Some(file)))
    }
}

// ── StoreReader ───────────────────────────────────────────────────────────────

impl Store {
    /// Return a lending iterator over entries with id >= `from`.
    ///
    /// The iterator borrows `self` for its lifetime. Each call to
    /// [`LendingIterator::next`](crate::LendingIterator::next) yields
    /// `Ok((id, entry))` where `entry` implements [`std::io::Read`].
    /// The entry reader must be dropped before calling `next` again.
    ///
    /// ```no_run
    /// # use woodshed::{Store, StoreCfg, LendingIterator};
    /// # let cfg = StoreCfg { base_dir: "/tmp/mystore".into(), segment_rollover_trigger_bytes: 64 << 20 };
    /// # let store = Store::open_or_create(cfg)?;
    /// let mut reader = store.scan(100);
    /// while let Some(Ok((id, mut entry))) = reader.next() {
    ///     let mut buf = Vec::new();
    ///     std::io::Read::read_to_end(&mut entry, &mut buf)?;
    ///     println!("id={id}: {} bytes", buf.len());
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn scan(&self, from: u64) -> StoreReader<'_> {
        let from = EntryId(from);

        // If from is beyond last_entry_id (or store is empty) yield nothing.
        if self.last_entry_id.is_none_or(|last| from > last) {
            return StoreReader { store: self, scanner: None };
        }

        let (seg_id, byte_offset) = self.scan_start(from);
        let scanner = files::open_segment(&self.cfg, seg_id)
            .ok()
            .and_then(|(file, _)| {
                let mut s = FrameScanner::new(file, byte_offset);
                s.seek_to_id(from).ok()?;
                Some((seg_id, s))
            });

        StoreReader { store: self, scanner }
    }

    fn scan_start(&self, from: EntryId) -> (SegmentId, u64) {
        if let Some(pos) = self.index.find(from) {
            return (pos.segment, pos.byte_offset);
        }
        // No checkpoint covers from; start at the beginning of the first segment.
        let seg = self.state.segments().first().unwrap();
        (seg.id, files::MAGIC_LEN as u64)
    }
}

pub struct EntryReader<'a>(FrameReader<'a>);

impl io::Read for EntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

pub struct StoreReader<'store> {
    store:   &'store Store,
    scanner: Option<(SegmentId, FrameScanner)>,
}

impl<'store> crate::LendingIterator for StoreReader<'store> {
    type Item<'a> = io::Result<(u64, EntryReader<'a>)> where Self: 'a;

    fn next<'this>(&'this mut self) -> Option<Self::Item<'this>> {
        loop {
            let scanner_ptr: *mut FrameScanner = match self.scanner.as_mut() {
                None => return None,
                Some((_, s)) => s,
            };
            // Safety: exclusive borrow held for 'this; caller cannot call next()
            // again while holding the returned EntryReader<'this>.
            let scanner_ref: &'this mut FrameScanner = unsafe { &mut *scanner_ptr };

            match scanner_ref.read() {
                Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))),
                Ok(Some(frame_reader)) => {
                    let id = frame_reader.id().0;
                    return Some(Ok((id, EntryReader(frame_reader))));
                }
                Ok(None) => {}
            }

            // Segment exhausted — advance to the next one.
            let (current, _) = self.scanner.take().unwrap();
            let segs = self.store.state.segments();
            let pos = segs.iter().position(|s| s.id == current)?;
            let next_seg = segs.get(pos + 1)?;
            match files::open_segment(&self.store.cfg, next_seg.id) {
                Ok((file, _)) => {
                    self.scanner = Some((next_seg.id, FrameScanner::new(file, files::MAGIC_LEN as u64)));
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameCursor;
    use crate::manifest::write_op;
    use crate::state::ManifestOp;
    use crate::state::Op;
    use crate::LendingIterator;
    use std::io::{Read, Write};
    use std::path::Path;
    use tempfile::tempdir;

    fn collect(mut r: StoreReader<'_>) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(item) = r.next() {
            let (id, mut reader) = item.unwrap();
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).unwrap();
            out.push((id, buf));
        }
        out
    }

    fn count(mut r: StoreReader<'_>) -> usize {
        let mut n = 0;
        while let Some(item) = r.next() { item.unwrap(); n += 1; }
        n
    }

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

    #[test]
    fn open_clean_store_succeeds() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        assert!(Store::open(cfg).is_ok());
    }

    #[test]
    fn open_missing_manifest_is_fatal() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        assert!(matches!(Store::open(cfg), Err(_)));
    }

    #[test]
    fn open_empty_manifest_is_fatal() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        files::create_manifest(&cfg).unwrap();
        assert!(matches!(Store::open(cfg), Err(_)));
    }

    #[test]
    fn open_torn_active_segment_auto_recovers() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);

        let seg_path = dir.path().join("00000001.seg");
        let mut f = std::fs::OpenOptions::new().append(true).open(seg_path).unwrap();
        f.write_all(&[0x00, 0x01]).unwrap();

        assert!(matches!(Store::open(cfg), Ok(_)));
    }

    #[test]
    fn writer_commit_persists_entries() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);

        let mut store = Store::open(cfg).unwrap();
        let pos_before = store.active_cursor.position();

        let mut w = store.writer();
        w.push(1, b"hello");
        w.push(2, b"world");
        w.write().unwrap().sync().unwrap();

        assert!(store.active_cursor.position() > pos_before);
    }

    #[test]
    fn scan_empty_store_yields_nothing() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        let store = Store::open(cfg).unwrap();
        assert_eq!(count(store.scan(1)), 0);
    }

    #[test]
    fn scan_reads_written_entries() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        let mut store = Store::open(cfg).unwrap();

        let mut w = store.writer();
        w.push(1, b"hello");
        w.push(2, b"world");
        w.write().unwrap().sync().unwrap();

        let entries = collect(store.scan(1));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (1, b"hello".to_vec()));
        assert_eq!(entries[1], (2, b"world".to_vec()));
    }

    #[test]
    fn scan_from_mid_range() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        let mut store = Store::open(cfg).unwrap();

        let mut w = store.writer();
        w.push(1, b"a");
        w.push(2, b"b");
        w.push(3, b"c");
        w.write().unwrap().sync().unwrap();

        let entries = collect(store.scan(2));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (2, b"b".to_vec()));
        assert_eq!(entries[1], (3, b"c".to_vec()));
    }

    #[test]
    fn scan_from_beyond_last_entry_yields_nothing() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        let mut store = Store::open(cfg).unwrap();
        let mut w = store.writer();
        w.push(1, b"x");
        w.write().unwrap().sync().unwrap();
        assert_eq!(count(store.scan(99)), 0);
    }

    #[test]
    fn scan_across_rollover() {
        let dir = tempdir().unwrap();
        let cfg = StoreCfg { base_dir: dir.path().to_path_buf(), segment_rollover_trigger_bytes: 0 };
        format(&cfg);
        let mut store = Store::open(cfg).unwrap();

        // First commit lands in seg(1); rollover deferred.
        let mut w = store.writer();
        w.push(1, b"first");
        w.write().unwrap().sync().unwrap();

        // Second commit triggers deferred rollover, then lands in seg(2).
        let mut w = store.writer();
        w.push(2, b"second");
        w.write().unwrap().sync().unwrap();

        let entries = collect(store.scan(1));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (1, b"first".to_vec()));
        assert_eq!(entries[1], (2, b"second".to_vec()));
    }

    #[test]
    fn writer_commit_rolls_over_at_threshold() {
        let dir = tempdir().unwrap();
        let cfg = StoreCfg { base_dir: dir.path().to_path_buf(), segment_rollover_trigger_bytes: 0 };
        format(&cfg);

        let mut store = Store::open(cfg).unwrap();
        assert_eq!(store.active_id, seg(1));

        // First commit: write to seg1, rollover deferred.
        let mut w = store.writer();
        w.push(1, b"a");
        w.write().unwrap().sync().unwrap();
        assert_eq!(store.active_id, seg(1));
        assert!(store.rollover_pending);

        // Second commit: rollover fires, now on seg2.
        let mut w = store.writer();
        w.push(2, b"b");
        w.write().unwrap().sync().unwrap();
        assert_eq!(store.active_id, seg(2));
        // With threshold=0, rollover_pending is set again immediately after each
        // commit — that's correct; the next commit will roll again.
    }

    #[test]
    fn last_entry_id_tracks_writes() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        let mut store = Store::open(cfg).unwrap();

        assert_eq!(store.last_entry_id(), None);

        let mut w = store.writer();
        w.push(5, b"a");
        w.push(10, b"b");
        w.write().unwrap().sync().unwrap();

        assert_eq!(store.last_entry_id(), Some(10));
    }

    #[test]
    fn scan_with_gappy_ids() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        format(&cfg);
        let mut store = Store::open(cfg).unwrap();

        let mut w = store.writer();
        w.push(1, b"a");
        w.push(5, b"b");
        w.push(100, b"c");
        w.write().unwrap().sync().unwrap();

        // Seek to id=5 should skip id=1.
        let entries = collect(store.scan(5));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (5, b"b".to_vec()));
        assert_eq!(entries[1], (100, b"c".to_vec()));
    }

    // ── Snapshot-join scenario ─────────────────────────────────────────────────
    // A new node receives a snapshot covering indices 1..N, then must accept
    // AppendEntries for N+1 onward. The log store starts fresh, gets
    // truncate_start(N+1) before any entries are written, then entries arrive
    // with IDs starting at N+1.

    #[test]
    fn truncate_start_on_fresh_store_then_append_and_scan() {
        let dir = tempdir().unwrap();
        let mut store = Store::open_or_create(cfg(dir.path())).unwrap();

        // Purge to snapshot index 10; no entries have been written yet.
        store.truncate_start(11, &[]).unwrap();
        assert_eq!(store.first_entry_id(), 11);
        assert_eq!(store.last_entry_id(), None);

        // Append entries starting at the post-snapshot index.
        let mut w = store.writer();
        w.push(11, b"a");
        w.push(12, b"b");
        w.push(13, b"c");
        w.write().unwrap().sync().unwrap();

        assert_eq!(store.last_entry_id(), Some(13));

        let entries = collect(store.scan(11));
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], (11, b"a".to_vec()));
        assert_eq!(entries[1], (12, b"b".to_vec()));
        assert_eq!(entries[2], (13, b"c".to_vec()));
    }

    #[test]
    fn scan_from_high_id_after_purge() {
        let dir = tempdir().unwrap();
        let mut store = Store::open_or_create(cfg(dir.path())).unwrap();

        store.truncate_start(11, &[]).unwrap();

        let mut w = store.writer();
        w.push(11, b"a");
        w.push(12, b"b");
        w.push(13, b"c");
        w.write().unwrap().sync().unwrap();

        // Scanning from the last id only — matches what get_log_state does.
        let entries = collect(store.scan(13));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (13, b"c".to_vec()));

        // Scanning from mid-range.
        let entries = collect(store.scan(12));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (12, b"b".to_vec()));
    }

    #[test]
    fn first_entry_id_after_truncate_start() {
        let dir = tempdir().unwrap();
        let mut store = Store::open_or_create(cfg(dir.path())).unwrap();

        assert_eq!(store.first_entry_id(), 0);
        store.truncate_start(7, &[]).unwrap();
        assert_eq!(store.first_entry_id(), 7);
    }

    #[test]
    fn truncate_start_evicts_sealed_segments() {
        let dir = tempdir().unwrap();
        let cfg = StoreCfg { base_dir: dir.path().to_path_buf(), segment_rollover_trigger_bytes: 0 };
        let mut store = Store::open_or_create(cfg).unwrap();

        // Commit 1 → seg1, rollover deferred.
        let mut w = store.writer();
        w.push(1, b"a");
        w.write().unwrap().sync().unwrap();

        // Commit 2 → triggers rollover: seals seg1 (last_entry=1), opens seg2.
        let mut w = store.writer();
        w.push(2, b"b");
        w.write().unwrap().sync().unwrap();
        assert_eq!(store.active_id, seg(2));

        // Purge: seg1 (last_entry=1) is fully behind first_entry=2 → evicted.
        store.truncate_start(2, &[]).unwrap();
        store.delete_dead_segments().unwrap();

        assert!(!dir.path().join("00000001.seg").exists());

        // seg2 is still readable.
        let entries = collect(store.scan(2));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (2, b"b".to_vec()));
    }

    // ── truncate_end ───────────────────────────────────────────────────────────

    #[test]
    fn truncate_end_removes_tail_entries() {
        let dir = tempdir().unwrap();
        let mut store = Store::open_or_create(cfg(dir.path())).unwrap();

        let mut w = store.writer();
        w.push(1, b"a");
        w.push(2, b"b");
        w.push(3, b"c");
        w.write().unwrap().sync().unwrap();

        store.truncate_end(2).unwrap();
        assert_eq!(store.last_entry_id(), Some(2));

        let entries = collect(store.scan(1));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (1, b"a".to_vec()));
        assert_eq!(entries[1], (2, b"b".to_vec()));
    }

    #[test]
    fn truncate_end_noop_when_at_or_beyond_last() {
        let dir = tempdir().unwrap();
        let mut store = Store::open_or_create(cfg(dir.path())).unwrap();

        let mut w = store.writer();
        w.push(1, b"a");
        w.push(2, b"b");
        w.write().unwrap().sync().unwrap();

        store.truncate_end(2).unwrap();
        assert_eq!(store.last_entry_id(), Some(2));

        store.truncate_end(99).unwrap();
        assert_eq!(store.last_entry_id(), Some(2));
    }

    // ── Metadata ───────────────────────────────────────────────────────────────

    #[test]
    fn metadata_write_and_read() {
        let dir = tempdir().unwrap();
        let mut store = Store::open_or_create(cfg(dir.path())).unwrap();

        assert!(store.metadata().is_empty());

        store.write_metadata(vec![(1u8, b"vote".to_vec()), (2u8, b"committed".to_vec())]).unwrap();

        let meta = store.metadata();
        assert_eq!(meta.iter().find(|(k, _)| *k == 1).map(|(_, v)| v.as_slice()), Some(b"vote".as_slice()));
        assert_eq!(meta.iter().find(|(k, _)| *k == 2).map(|(_, v)| v.as_slice()), Some(b"committed".as_slice()));
    }

    #[test]
    fn metadata_persists_across_reopen() {
        let dir = tempdir().unwrap();

        {
            let mut store = Store::open_or_create(cfg(dir.path())).unwrap();
            store.write_metadata(vec![(1u8, b"vote-bytes".to_vec())]).unwrap();
        }

        let store = Store::open_or_create(cfg(dir.path())).unwrap();
        let has_key = store.metadata().iter().any(|(k, v)| *k == 1 && v == b"vote-bytes");
        assert!(has_key);
    }

    #[test]
    fn metadata_last_write_wins() {
        let dir = tempdir().unwrap();
        let mut store = Store::open_or_create(cfg(dir.path())).unwrap();

        store.write_metadata(vec![(1u8, b"first".to_vec())]).unwrap();
        store.write_metadata(vec![(1u8, b"second".to_vec())]).unwrap();

        let val = store.metadata().iter().find(|(k, _)| *k == 1).map(|(_, v)| v.as_slice());
        assert_eq!(val, Some(b"second".as_slice()));
    }
}
