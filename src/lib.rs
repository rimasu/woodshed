//! A crash-safe, append-only log store designed for use as a Raft log backend.
//!
//! # Design
//!
//! A `woodshed` store consists of a **manifest** and one or more **segments**:
//!
//! - The **manifest** is a small append-only file that records structural
//!   operations (segment creation, sealing, truncation) and arbitrary key-value
//!   metadata. It is the authoritative source of store state; any issue found
//!   during a scan can be resolved by replaying the manifest.
//!
//! - **Segments** are append-only data files. Each frame in a segment carries an
//!   8-byte caller-provided `id` (typically the Raft log index), a 4-byte
//!   payload length, an 8-byte xxHash-64 checksum, and the payload bytes.
//!   Segments are sealed once they exceed a configurable size threshold; a new
//!   segment is then started for subsequent writes.
//!
//! # Crash safety
//!
//! Woodshed separates the write and sync steps so that a Raft leader can reply
//! to an `AppendEntries` RPC before calling `fsync`:
//!
//! 1. [`StoreWriter::write`] flushes frame bytes to the page cache (no `fsync`).
//!    It returns a [`Commit`] handle that borrows the segment file.
//! 2. The caller can do other work (e.g. send an RPC reply) while the data sits
//!    in the page cache.
//! 3. [`Commit::sync`] calls `fsync` to make the data durable.
//!
//! Manifest operations (segment creation, sealing, truncation) always sync
//! inline for crash safety.
//!
//! On startup, [`Store::open`] replays the manifest and scans segments to verify
//! checksums. Minor issues (torn tails, orphan files) are fixed automatically;
//! more serious issues require explicit approval via [`Store::recover`].
//!
//! # Identifiers
//!
//! Entry IDs are 64-bit integers supplied by the caller. Woodshed stores and
//! retrieves them verbatim — it makes no assumption about contiguity or starting
//! value. This allows Raft log indices to be used directly with no translation.
//!
//! # Example
//!
//! ```no_run
//! use woodshed::{Store, StoreCfg, LendingIterator};
//!
//! let cfg = StoreCfg {
//!     base_dir: "/var/lib/myapp/log".into(),
//!     segment_rollover_trigger_bytes: 64 * 1024 * 1024,
//! };
//!
//! let mut store = Store::open_or_create(cfg)?;
//!
//! // Write a batch of entries.
//! let mut w = store.writer();
//! w.push(1, b"first entry");
//! w.push(2, b"second entry");
//! let commit = w.write()?;   // flush to page cache
//! commit.sync()?;             // fsync to disk
//!
//! // Scan entries from id 1 onwards.
//! let mut reader = store.scan(1);
//! while let Some(Ok((id, mut entry))) = reader.next() {
//!     let mut buf = Vec::new();
//!     std::io::Read::read_to_end(&mut entry, &mut buf)?;
//!     println!("id={id} payload={buf:?}");
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub(crate) mod frame;
pub(crate) mod files;
pub(crate) mod index;
pub(crate) mod manifest;
pub(crate) mod scan;
pub(crate) mod state;
pub(crate) mod issue;
pub(crate) mod recovery;
pub(crate) mod store;

pub use store::{Store, StoreWriter, StoreReader, EntryReader, Commit, OpenError};
pub use recovery::RecoveryError;
pub use issue::IssueReport;

/// An iterator that yields items which may borrow from the iterator itself.
///
/// Unlike [`std::iter::Iterator`], the item lifetime is tied to each `next` call,
/// allowing zero-copy streaming without intermediate allocation. The item (and any
/// borrows it holds) must be dropped before calling `next` again.
pub trait LendingIterator {
    type Item<'a> where Self: 'a;
    fn next<'this>(&'this mut self) -> Option<Self::Item<'this>>;
}

/// Configuration for opening or creating a [`Store`].
#[derive(Clone)]
pub struct StoreCfg {
    /// Directory where the manifest and segment files are stored.
    pub base_dir: std::path::PathBuf,
    /// Approximate byte threshold at which the active segment is sealed and a new one opened.
    pub segment_rollover_trigger_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EntryId(pub(crate) u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SegmentId(pub(crate) u32);
