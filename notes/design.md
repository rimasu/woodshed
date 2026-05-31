# Woodshed — Design

Woodshed is an append-only log store. It exposes a sequence of entries, each
with a caller-provided `u64` identifier.

## Public Operations

- **Write** — append one or more entries. Returns a `Commit` handle; call
  `Commit::sync` to make the data durable via `fsync`.
- **Truncate start** — drop all entries before a given id (driven by Raft snapshot).
- **Truncate end** — roll back to a specific entry id (driven by Raft log conflict).
- **Scan** — read entries from a given id forwards via a zero-copy lending iterator.

Writing to the page cache and fsyncing are intentionally separate steps so that
a Raft leader can reply to an `AppendEntries` RPC before `fsync` completes.

---

## Entry Identity

Entry IDs are supplied by the caller via `StoreWriter::push(id, payload)`.
Woodshed stores and retrieves them verbatim. No assumption is made about
contiguity or starting value; this allows Raft log indices to be used directly
with no translation layer.

---

## Frame Format

All storage — both segment files and the manifest — uses the same frame format:

```
[id: 8][payload_len: 4][checksum: 8][payload: payload_len bytes]
```

All multi-byte integers are big-endian.

- `id` is the caller-provided entry id (segment frames) or `0` (manifest frames).
- `checksum` is xxHash-64 over the concatenation of the id bytes and the payload.
  This binds the checksum to the id, preventing silent id corruption.
- Frames are self-contained and can be verified in isolation.

Total header size: 20 bytes.

---

## On-Disk Layout

```
MANIFEST      — append-only manifest file recording segment lifecycle operations
<id>.seg      — segment files, named as 8 hex digits (e.g. 00000001.seg)
```

Segment IDs are opaque `u32` identifiers. Segment ordering is determined
entirely by the sequence of ops in the manifest, not by ID comparison.

Both file types begin with an 8-byte magic prefix before any frames:

| File     | Magic            |
|----------|------------------|
| Manifest | `\xffWDMNFT\x01` |
| Segment  | `\xffWDSEGM\x01` |

The leading `\xff` makes the file non-text. The trailing `\x01` is the format
version. Mismatched or absent magic is an immediate open error.

---

## Segment Files

A segment file is a flat sequence of record frames with no additional header:

```
[magic: 8][record frame]*
```

Each frame payload is raw entry bytes. A frame is valid if its checksum matches
`xxh64(id_bytes || payload)`. Scanning stops at the first invalid or truncated
frame — that is the write frontier.

Sealed segments have a known `final_size` recorded in the manifest. On open,
`file.metadata().len() == final_size` must hold. Any deviation is an integrity
violation.

The active (last) segment has no size check; its write frontier is found by
scanning to the first bad or missing frame.

---

## Manifest File

The manifest uses the same frame format as segment files (with `id = 0` for all
frames). It is append-only and records segment lifecycle operations. Volume is
low — one frame per structural change plus infrequent metadata updates.

Each frame payload begins with a 1-byte op tag followed by op-specific fields,
and ends with a trailing metadata section present on all ops:

```
[op-specific fields][pairs_count: 2][key: 1][value_len: 2][value: value_len bytes]* × pairs_count
```

The metadata section allows arbitrary key-value pairs (e.g. Raft vote, last
committed index) to be written atomically with any structural op. An empty
metadata section is encoded as `[0x00 0x00]` (pairs_count = 0).

### `create_segment` (op `0x01`)

```
[op: 1][segment_id: 4][first_entry_id: 8]
```

Records that a new segment has been created and is now active.

### `roll_segment` (op `0x02`)

```
[op: 1][sealed_id: 4][first_entry_id: 8][last_entry_id: 8]
        [entry_count: 4][final_size: 8]
        [new_id: 4][new_first_entry_id: 8]
```

Seals the current segment and opens the next in a single atomic operation.
One frame, one fsync — either the rollover happened or it didn't.

`final_size` is the expected byte length of the sealed segment file.
`entry_count` is used to verify the seal during recovery.

### `truncate_start` (op `0x03`)

```
[op: 1][first_entry_id: 8][drop_count: 4][segment_id: 4 × drop_count]
```

Records that the log head has advanced to `first_entry_id`. The listed segments
fall entirely before the new head and are marked dead (eligible for deletion via
`Store::delete_dead_segments`).

### `truncate_end` (op `0x04`)

```
[op: 1][new_active_id: 4][byte_offset: 8][drop_count: 4][segment_id: 4 × drop_count]
```

Records a log rollback. A single frame captures the complete state change:

- `new_active_id` — the segment that becomes the new active segment.
- `byte_offset` — the write frontier in that segment after truncation.
- `drop_count` + list — segments that existed after `new_active_id` and are now
  removed entirely.

Recovery applies this frame by:
1. Deleting the files for each listed segment.
2. `file.set_len(byte_offset)` on `new_active_id`'s file.
3. Treating `new_active_id` as active with write frontier `byte_offset`.

Any prior `roll_segment` entry sealing `new_active_id` is superseded.

### `segment_deleted` (op `0x05`)

```
[op: 1][segment_id: 4]
```

Records that a dead segment file has been physically deleted from disk. Written
by `Store::delete_dead_segments`.

### `record_orphan` (op `0x06`)

```
[op: 1][segment_id: 4]
```

Records an orphan segment file found on disk that has no prior manifest entry.
Written during recovery to bring the manifest into sync with the filesystem.

### `noop` (op `0x07`)

```
[op: 1]
```

A no-op structural op, used to attach metadata pairs to the manifest without
any structural side effect (e.g. writing Raft metadata at startup).

---

## In-Memory Entry Index

The in-memory index maps entry ids to `(segment_id, byte_offset)`. It is
rebuilt by scanning segment files on open and is never persisted.

The index is **sparse**: one checkpoint per 64 entries plus one per segment
boundary. To locate entry `id`:

1. Binary search the checkpoint list for the largest checkpoint ≤ `id`.
2. Seek to that checkpoint's byte offset and scan forward (at most 63 frames).

This keeps index memory at ~1% of a dense index while bounding scan cost at 63
frames regardless of segment size.

---

## Open / Recovery

Recovery proceeds in phases:

**Phase 0 — verify directory.**
Check that the store directory exists. Return `DirectoryNotFound` immediately if not.

**Phase 1 — scan and replay the manifest.**
Scan manifest frames to the last valid checksum, building the in-memory
`StoreState` (segment list, seal info, dead set, metadata). Torn tails are
tolerated and reported; checksum corruption is fatal.

**Phase 2 — scan segment files.**
For each live segment:
- Sealed: verify `file.metadata().len() == final_size`. Scan to build
  in-memory checkpoints.
- Active: scan frames to find the write frontier. Build checkpoints.

**Phase 3 — cross-check filesystem.**
Collect all `.seg` files on disk. Report missing dead segments and orphan
files (segments on disk with no manifest record).

Minor issues (torn manifest tail, orphan files, missing dead segments) are
fixed automatically by `Store::open`. Issues requiring data loss (active
segment truncation) require explicit approval via `Store::recover`.

---

## Segment Rollover

When the active segment exceeds `segment_rollover_trigger_bytes`, the rollover
is **deferred**: a `rollover_pending` flag is set on the `Store`. The actual
rollover executes at the start of the next non-empty `write()` so that
`new_first_entry` in the `roll_segment` op is known before the new segment
file is created.

Rollover steps:
1. Create the new segment file on disk.
2. Append a `roll_segment` frame to the manifest. Fsync the manifest.
3. Update in-memory state.

A crash between steps 1 and 2 leaves an orphan segment file that recovery
reports and then records via `record_orphan`. A crash after step 2 is clean.
