# woodshed

A crash-safe, append-only log store designed for use as a Raft log backend.

## Design

A woodshed store consists of a **manifest** and one or more **segment** files.

- The **manifest** is a small append-only file that records structural
  operations — segment creation, sealing, truncation — and arbitrary
  key-value metadata. It is the authoritative source of store state.

- **Segments** are append-only data files. Each frame carries a caller-provided
  `u64` id (typically the Raft log index), a payload length, an xxHash-64
  checksum, and the payload bytes. Segments are sealed once they exceed a
  configurable size threshold.

### Split write / sync

Woodshed separates the write and sync steps so that a Raft leader can reply
to an `AppendEntries` RPC before calling `fsync`:

```rust
let mut w = store.writer();
w.push(1, b"hello");
w.push(2, b"world");
let commit = w.write()?;   // frames reach the OS page cache
// reply to the RPC here …
commit.sync()?;             // fsync — data is now durable
```

### Caller-provided ids

Entry ids are supplied by the caller. Woodshed makes no assumption about
contiguity or starting value, allowing Raft log indices to be used directly
with no translation layer.

## Usage

```rust
use woodshed::{Store, StoreCfg, LendingIterator};

let cfg = StoreCfg {
    base_dir: "/var/lib/myapp/log".into(),
    segment_rollover_trigger_bytes: 64 * 1024 * 1024,
};

// Open or create the store.
let mut store = Store::open_or_create(cfg)?;

// Append a batch of entries.
let mut w = store.writer();
w.push(1, b"first entry");
w.push(2, b"second entry");
let commit = w.write()?;
commit.sync()?;

// Scan from a given id.
let mut reader = store.scan(1);
while let Some(Ok((id, mut entry))) = reader.next() {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf)?;
    println!("id={id}: {} bytes", buf.len());
}
```

### Opening with recovery

`Store::open` automatically fixes minor issues (torn tails, orphan files).
When manual approval is required it returns `OpenError::ApprovedRecoveredRequired`:

```rust
use woodshed::{Store, StoreCfg, OpenError};

let store = match Store::open(cfg.clone()) {
    Ok(s) => s,
    Err(OpenError::ApprovedRecoveredRequired(_)) => {
        Store::recover(&cfg)?;
        Store::open(cfg)?
    }
    Err(e) => return Err(e.into()),
};
```

### Log compaction

After installing a snapshot, advance the log head and reclaim disk space:

```rust
store.truncate_start(snapshot_last_index, &[])?;
store.delete_dead_segments()?;
```

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
