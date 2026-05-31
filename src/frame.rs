use std::io::{self, BufReader, Read};

use xxhash_rust::xxh64::Xxh64;

use crate::EntryId;

// Frame wire format:
//   [id: 8][payload_len: 4][checksum: 8][payload: N]
//
// Checksum is xxh64 over (id_bytes || payload).
// Manifest frames use id = 0 (EntryId(0)).

pub const HEADER_LEN: usize = size_of::<u64>()  // id
                             + size_of::<u32>()  // payload_len
                             + size_of::<u64>(); // checksum


struct FrameBuffer {
    buf: Vec<u8>,
}

impl FrameBuffer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn write(&mut self, id: EntryId, payload: &[u8]) {
        let mut hasher = Xxh64::new(0);
        hasher.update(&id.0.to_be_bytes());
        hasher.update(payload);
        let checksum = hasher.digest();
        self.buf.extend_from_slice(&id.0.to_be_bytes());
        self.buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(&checksum.to_be_bytes());
        self.buf.extend_from_slice(payload);
    }

    fn pending(&self) -> &[u8] {
        &self.buf
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn clear(&mut self) {
        self.buf.clear();
    }
}


pub struct FrameCursor {
    buf:      FrameBuffer,
    position: u64,
}

impl FrameCursor {
    pub fn new(position: u64) -> Self {
        Self { buf: FrameBuffer::new(), position }
    }

    pub fn position(&self) -> u64 { self.position }

    pub fn set_position(&mut self, pos: u64) { self.position = pos; }

    pub fn write(&mut self, id: EntryId, payload: &[u8]) {
        self.buf.write(id, payload);
    }

    /// Write buffered frames to `file` at the current position and advance the
    /// cursor. Does **not** call `sync_all` — callers are responsible for
    /// durability via a subsequent sync.
    pub fn flush(&mut self, file: &std::fs::File) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;
        file.write_all_at(self.buf.pending(), self.position)?;
        self.position += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }
}


pub struct FrameScanner {
    reader:   BufReader<std::fs::File>,
    position: u64,
    /// A frame whose 20-byte header has been read but whose payload has not
    /// yet been consumed. Stores the raw header bytes and the frame's start
    /// offset. Cleared by `read`, `check`, `skip`, and `seek_to_id`.
    peeked:   Option<([u8; HEADER_LEN], u64)>,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("checksum mismatch at offset {offset}")]
    ChecksumMismatch { offset: u64 },
    #[error("truncated frame at offset {offset}")]
    Truncated { offset: u64 },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

impl FrameScanner {
    pub fn new(file: std::fs::File, offset: u64) -> Self {
        Self { reader: BufReader::new(file), position: offset, peeked: None }
    }

    /// Peek at the next frame's header without consuming the payload. Returns
    /// the raw header bytes and the frame's start offset, or `None` at EOF.
    /// If the header is already peeked, returns it immediately.
    fn peek_header(&mut self) -> Result<Option<([u8; HEADER_LEN], u64)>, ScanError> {
        if let Some(p) = self.peeked {
            return Ok(Some(p));
        }
        let frame_start = self.position;
        let mut header = [0u8; HEADER_LEN];
        if self.reader.read(&mut header[..1])? == 0 { return Ok(None) }
        self.reader.read_exact(&mut header[1..])
            .map_err(|_| ScanError::Truncated { offset: frame_start })?;
        self.peeked = Some((header, frame_start));
        Ok(Some((header, frame_start)))
    }

    fn consume_peeked_payload(&mut self, payload_len: u32, frame_start: u64) -> Result<(), ScanError> {
        let n = payload_len as u64;
        let skipped = io::copy(&mut (&mut self.reader).take(n), &mut io::sink())?;
        if skipped < n {
            return Err(ScanError::Truncated { offset: frame_start });
        }
        self.position = frame_start + HEADER_LEN as u64 + n;
        self.peeked = None;
        Ok(())
    }

    /// Read the next frame header and return a streaming [`FrameReader`] for
    /// the payload. Returns `None` at clean EOF, `Err(Truncated)` on a partial
    /// header.
    pub fn read(&mut self) -> Result<Option<FrameReader<'_>>, ScanError> {
        let (header, frame_start) = match self.peek_header()? {
            None => return Ok(None),
            Some(p) => p,
        };
        self.peeked = None;

        let id          = EntryId(u64::from_be_bytes(header[..8].try_into().unwrap()));
        let payload_len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;

        Ok(Some(FrameReader {
            scanner: self,
            id,
            remaining: payload_len,
            payload_len,
            frame_start,
        }))
    }

    /// Read the next frame, verify its checksum, and discard the payload.
    /// Returns `(id, frame_start_offset)` on success, `None` at clean EOF.
    pub fn check(&mut self) -> Result<Option<(EntryId, u64)>, ScanError> {
        let (header, frame_start) = match self.peek_header()? {
            None => return Ok(None),
            Some(p) => p,
        };
        self.peeked = None;

        let id  = EntryId(u64::from_be_bytes(header[..8].try_into().unwrap()));
        let payload_len  = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
        let expected     = u64::from_be_bytes(header[12..20].try_into().unwrap());

        let mut hasher    = Xxh64::new(0);
        hasher.update(&id.0.to_be_bytes());
        let mut remaining = payload_len;
        let mut tmp       = [0u8; 8 * 1024];

        while remaining > 0 {
            let limit = remaining.min(tmp.len());
            let n = self.reader.read(&mut tmp[..limit]).map_err(ScanError::Io)?;
            if n == 0 {
                return Err(ScanError::Truncated { offset: frame_start });
            }
            hasher.update(&tmp[..n]);
            remaining -= n;
        }

        self.position = frame_start + HEADER_LEN as u64 + payload_len as u64;

        if hasher.digest() != expected {
            return Err(ScanError::ChecksumMismatch { offset: frame_start });
        }

        Ok(Some((id, frame_start)))
    }

    /// Scan all frames using [`check`], recording every `stride`-th frame as a
    /// `(id, file_offset)` checkpoint. Returns a [`ScanSummary`].
    pub fn scan_all(&mut self, stride: u64) -> Result<ScanSummary, io::Error> {
        let mut count       = 0u64;
        let mut checkpoints = Vec::new();
        let mut last_id     = None;
        let mut last_good   = self.position;

        loop {
            match self.check() {
                Ok(None) => return Ok(ScanSummary {
                    count,
                    checkpoints,
                    last_id,
                    next_offset: self.position(),
                    status: ScanStatus::Clean,
                }),
                Ok(Some((id, frame_offset))) => {
                    if count % stride == 0 {
                        checkpoints.push((id, frame_offset));
                    }
                    last_id = Some(id);
                    count += 1;
                    last_good = self.position();
                }
                Err(ScanError::Truncated { .. }) => return Ok(ScanSummary {
                    count,
                    checkpoints,
                    last_id,
                    next_offset: last_good,
                    status: ScanStatus::TornTail,
                }),
                Err(ScanError::ChecksumMismatch { .. }) => return Ok(ScanSummary {
                    count,
                    checkpoints,
                    last_id,
                    next_offset: last_good,
                    status: ScanStatus::ChecksumCorrupt,
                }),
                Err(ScanError::Io(e)) => return Err(e),
            }
        }
    }

    #[cfg(test)]
    pub fn skip(&mut self) -> Result<bool, ScanError> {
        let (header, frame_start) = match self.peek_header()? {
            None => return Ok(false),
            Some(p) => p,
        };
        self.peeked = None;
        let payload_len = u32::from_be_bytes(header[8..12].try_into().unwrap());
        self.consume_peeked_payload(payload_len, frame_start)?;
        Ok(true)
    }

    #[cfg(test)]
    pub fn skip_n(&mut self, n: usize) -> Result<usize, ScanError> {
        for i in 0..n {
            if !self.skip()? {
                return Ok(i);
            }
        }
        Ok(n)
    }

    /// Advance past all frames whose `id < target`. After returning,
    /// the next `read()` call will return the first frame with `id >= target`
    /// (or `None` if no such frame exists).
    pub fn seek_to_id(&mut self, target: EntryId) -> Result<(), ScanError> {
        loop {
            let (header, frame_start) = match self.peek_header()? {
                None => return Ok(()),
                Some(p) => p,
            };
            let id = EntryId(u64::from_be_bytes(header[..8].try_into().unwrap()));
            if id.0 >= target.0 {
                return Ok(()); // peeked header remains for next read()
            }
            self.peeked = None;
            let payload_len = u32::from_be_bytes(header[8..12].try_into().unwrap());
            self.consume_peeked_payload(payload_len, frame_start)?;
        }
    }

    /// Advance past the frame with `id == target` and return the byte
    /// offset immediately after it (the start of the next frame). Used by
    /// `truncate_end` to find the physical truncation point.
    pub fn scan_to_after(&mut self, target: EntryId) -> Result<u64, ScanError> {
        loop {
            let (header, frame_start) = match self.peek_header()? {
                None => return Err(ScanError::Truncated { offset: self.position }),
                Some(p) => p,
            };
            let id          = EntryId(u64::from_be_bytes(header[..8].try_into().unwrap()));
            let payload_len = u32::from_be_bytes(header[8..12].try_into().unwrap());
            self.peeked     = None;
            self.consume_peeked_payload(payload_len, frame_start)?;
            if id == target {
                return Ok(self.position);
            }
        }
    }

    pub fn position(&self) -> u64 {
        self.position
    }
}

// ── FrameReader ───────────────────────────────────────────────────────────────

/// A streaming reader for a single frame's payload. Advances the parent
/// [`FrameScanner`]'s position when the payload is fully consumed.
/// Does not verify the checksum; use [`FrameScanner::check`] for that.
pub struct FrameReader<'a> {
    scanner:     &'a mut FrameScanner,
    id:          EntryId,
    remaining:   usize,
    payload_len: usize,
    frame_start: u64,
}

impl FrameReader<'_> {
    pub fn frame_start(&self) -> u64 { self.frame_start }
    pub fn id(&self) -> EntryId      { self.id }
}

impl Drop for FrameReader<'_> {
    fn drop(&mut self) {
        if self.remaining > 0 {
            let _ = io::copy(
                &mut self.scanner.reader.by_ref().take(self.remaining as u64),
                &mut io::sink(),
            );
            self.scanner.position = self.frame_start + HEADER_LEN as u64 + self.payload_len as u64;
        }
    }
}

impl io::Read for FrameReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let limit = self.remaining.min(buf.len());
        let n = self.scanner.reader.read(&mut buf[..limit])?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.remaining -= n;
        if self.remaining == 0 {
            self.scanner.position =
                self.frame_start + HEADER_LEN as u64 + self.payload_len as u64;
        }
        Ok(n)
    }
}

// ── ScanSummary ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum ScanStatus {
    Clean,
    TornTail,
    ChecksumCorrupt,
}

pub struct ScanSummary {
    /// Number of clean frames read.
    pub count:       u64,
    /// `(id, start_offset)` of every `stride`-th frame (0-indexed).
    pub checkpoints: Vec<(EntryId, u64)>,
    /// External id of the last successfully read frame, or `None` if empty.
    pub last_id:     Option<EntryId>,
    /// Write frontier: position after the last clean frame (or start of the
    /// bad frame in error cases).
    pub next_offset: u64,
    pub status:      ScanStatus,
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::tempfile;

    fn write_to_file(frames: &[(u64, &[u8])]) -> std::fs::File {
        let mut file = tempfile().unwrap();
        let mut w = FrameBuffer::new();
        for (id, payload) in frames {
            w.write(EntryId(*id), payload);
        }
        file.write_all(w.pending()).unwrap();
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file
    }

    // ── read() tests ──────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_single_frame() {
        let file = write_to_file(&[(1, b"hello")]);
        let mut scanner = FrameScanner::new(file, 0);
        let mut reader = scanner.read().unwrap().unwrap();
        let id = reader.id();
        let offset = reader.frame_start();
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).unwrap();
        drop(reader);
        assert_eq!(id, EntryId(1));
        assert_eq!(offset, 0);
        assert_eq!(payload, b"hello");
        assert!(scanner.read().unwrap().is_none());
    }

    #[test]
    fn roundtrip_multiple_frames() {
        let frames: &[(u64, &[u8])] = &[(1, b"foo"), (2, b"bar"), (3, b"baz")];
        let file = write_to_file(frames);
        let mut scanner = FrameScanner::new(file, 0);
        for &(id, expected) in frames {
            let mut payload = Vec::new();
            {
                let mut reader = scanner.read().unwrap().unwrap();
                assert_eq!(reader.id(), EntryId(id));
                reader.read_to_end(&mut payload).unwrap();
            }
            assert_eq!(payload, expected);
        }
        assert!(scanner.read().unwrap().is_none());
    }

    #[test]
    fn empty_file_returns_none() {
        let file = tempfile().unwrap();
        let mut scanner = FrameScanner::new(file, 0);
        assert!(scanner.read().unwrap().is_none());
    }

    #[test]
    fn truncated_header_returns_error() {
        let mut file = tempfile().unwrap();
        file.write_all(&[0x00, 0x00]).unwrap();
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let mut scanner = FrameScanner::new(file, 0);
        assert!(matches!(scanner.read(), Err(ScanError::Truncated { .. })));
    }

    // ── check() tests ─────────────────────────────────────────────────────────

    #[test]
    fn check_succeeds_on_valid_frame() {
        let file = write_to_file(&[(42, b"hello")]);
        let mut scanner = FrameScanner::new(file, 0);
        assert_eq!(scanner.check().unwrap(), Some((EntryId(42), 0)));
        assert!(scanner.check().unwrap().is_none());
    }

    #[test]
    fn check_detects_checksum_mismatch() {
        let mut file = tempfile().unwrap();
        let mut w = FrameBuffer::new();
        w.write(EntryId(1), b"good payload");
        let mut pending = w.pending().to_vec();
        let last = pending.len() - 1;
        pending[last] ^= 0xff;
        file.write_all(&pending).unwrap();
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let mut scanner = FrameScanner::new(file, 0);
        assert!(matches!(scanner.check(), Err(ScanError::ChecksumMismatch { .. })));
    }

    #[test]
    fn check_detects_truncated_payload() {
        let mut file = tempfile().unwrap();
        let mut w = FrameBuffer::new();
        w.write(EntryId(1), b"hello");
        let pending = w.pending();
        // Write only the header + 2 bytes of payload
        file.write_all(&pending[..HEADER_LEN + 2]).unwrap();
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let mut scanner = FrameScanner::new(file, 0);
        assert!(matches!(scanner.check(), Err(ScanError::Truncated { .. })));
    }

    // ── scan_all() tests ──────────────────────────────────────────────────────

    #[test]
    fn scan_all_clean_returns_count_and_checkpoints() {
        let file = write_to_file(&[(1, b"a"), (2, b"b"), (3, b"c")]);
        let mut scanner = FrameScanner::new(file, 0);
        let summary = scanner.scan_all(1).unwrap();
        assert_eq!(summary.count, 3);
        assert_eq!(summary.checkpoints.len(), 3);
        assert_eq!(summary.checkpoints[0].0, EntryId(1));
        assert_eq!(summary.checkpoints[1].0, EntryId(2));
        assert_eq!(summary.checkpoints[2].0, EntryId(3));
        assert_eq!(summary.status, ScanStatus::Clean);
    }

    #[test]
    fn scan_all_stride_filters_checkpoints() {
        let file = write_to_file(&[(1, b"a"), (2, b"b"), (3, b"c"), (4, b"d")]);
        let mut scanner = FrameScanner::new(file, 0);
        let summary = scanner.scan_all(2).unwrap();
        assert_eq!(summary.count, 4);
        assert_eq!(summary.checkpoints.len(), 2); // frames 0 and 2
        assert_eq!(summary.checkpoints[0].0, EntryId(1));
        assert_eq!(summary.checkpoints[1].0, EntryId(3));
    }

    #[test]
    fn scan_all_torn_tail() {
        let mut file = tempfile().unwrap();
        let mut w = FrameBuffer::new();
        w.write(EntryId(1), b"good");
        file.write_all(w.pending()).unwrap();
        file.write_all(&[0x00, 0x01]).unwrap(); // partial frame
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let mut scanner = FrameScanner::new(file, 0);
        let summary = scanner.scan_all(1).unwrap();
        assert_eq!(summary.count, 1);
        assert_eq!(summary.status, ScanStatus::TornTail);
    }

    #[test]
    fn scan_all_checksum_corrupt() {
        let mut file = tempfile().unwrap();
        let mut w = FrameBuffer::new();
        w.write(EntryId(1), b"good payload");
        let mut pending = w.pending().to_vec();
        let last = pending.len() - 1;
        pending[last] ^= 0xff;
        file.write_all(&pending).unwrap();
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let mut scanner = FrameScanner::new(file, 0);
        let summary = scanner.scan_all(1).unwrap();
        assert_eq!(summary.count, 0);
        assert_eq!(summary.status, ScanStatus::ChecksumCorrupt);
    }

    // ── skip() tests ──────────────────────────────────────────────────────────

    #[test]
    fn skip_advances_past_frame() {
        let file = write_to_file(&[(1, b"skip me"), (2, b"read me")]);
        let mut scanner = FrameScanner::new(file, 0);
        assert!(scanner.skip().unwrap());
        let mut payload = Vec::new();
        {
            let mut reader = scanner.read().unwrap().unwrap();
            assert_eq!(reader.id(), EntryId(2));
            reader.read_to_end(&mut payload).unwrap();
        }
        assert_eq!(payload, b"read me");
        assert!(scanner.read().unwrap().is_none());
    }

    #[test]
    fn skip_at_eof_returns_false() {
        let file = write_to_file(&[(1, b"only")]);
        let mut scanner = FrameScanner::new(file, 0);
        assert!(scanner.skip().unwrap());
        assert!(!scanner.skip().unwrap());
    }

    #[test]
    fn skip_n_skips_exact_count() {
        let file = write_to_file(&[(1, b"a"), (2, b"b"), (3, b"c"), (4, b"d")]);
        let mut scanner = FrameScanner::new(file, 0);
        assert_eq!(scanner.skip_n(2).unwrap(), 2);
        let mut payload = Vec::new();
        {
            let mut reader = scanner.read().unwrap().unwrap();
            assert_eq!(reader.id(), EntryId(3));
            reader.read_to_end(&mut payload).unwrap();
        }
        assert_eq!(payload, b"c");
    }

    #[test]
    fn skip_n_stops_at_eof() {
        let file = write_to_file(&[(1, b"a"), (2, b"b")]);
        let mut scanner = FrameScanner::new(file, 0);
        assert_eq!(scanner.skip_n(10).unwrap(), 2);
    }

    // ── seek_to_id() tests ────────────────────────────────────────────────────

    #[test]
    fn seek_to_id_skips_before_target() {
        let file = write_to_file(&[(10, b"a"), (20, b"b"), (30, b"c")]);
        let mut scanner = FrameScanner::new(file, 0);
        scanner.seek_to_id(EntryId(20)).unwrap();
        let mut reader = scanner.read().unwrap().unwrap();
        assert_eq!(reader.id(), EntryId(20));
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"b");
    }

    #[test]
    fn seek_to_id_already_at_target() {
        let file = write_to_file(&[(5, b"hello")]);
        let mut scanner = FrameScanner::new(file, 0);
        scanner.seek_to_id(EntryId(5)).unwrap();
        let mut reader = scanner.read().unwrap().unwrap();
        assert_eq!(reader.id(), EntryId(5));
    }

    #[test]
    fn seek_to_id_past_all_frames_yields_none() {
        let file = write_to_file(&[(1, b"a"), (2, b"b")]);
        let mut scanner = FrameScanner::new(file, 0);
        scanner.seek_to_id(EntryId(99)).unwrap();
        assert!(scanner.read().unwrap().is_none());
    }

    #[test]
    fn seek_to_id_stops_at_first_frame_with_id_gte_target() {
        // Gappy IDs: 1, 5, 10 — seek to 4 should land on id=5
        let file = write_to_file(&[(1, b"a"), (5, b"b"), (10, b"c")]);
        let mut scanner = FrameScanner::new(file, 0);
        scanner.seek_to_id(EntryId(4)).unwrap();
        let mut reader = scanner.read().unwrap().unwrap();
        assert_eq!(reader.id(), EntryId(5));
    }

    // ── scan_to_after() tests ─────────────────────────────────────────────────

    #[test]
    fn scan_to_after_returns_offset_past_target() {
        let file = write_to_file(&[(1, b"a"), (2, b"b"), (3, b"c")]);
        let mut scanner = FrameScanner::new(file, 0);
        let after = scanner.scan_to_after(EntryId(2)).unwrap();
        // After scanning past id=2, the scanner is positioned at the start of id=3.
        let mut reader = scanner.read().unwrap().unwrap();
        assert_eq!(reader.id(), EntryId(3));
        // `after` equals two frames of size HEADER_LEN + 1 byte payload each.
        assert_eq!(after, 2 * (HEADER_LEN as u64 + 1));
    }

    // ── writer_len_tracking ───────────────────────────────────────────────────

    #[test]
    fn writer_len_tracking() {
        let mut w = FrameBuffer::new();
        assert_eq!(w.len(), 0);
        w.write(EntryId(1), b"ab");
        assert_eq!(w.len(), HEADER_LEN + 2);
        w.write(EntryId(2), b"cdef");
        assert_eq!(w.len(), 2 * HEADER_LEN + 6);
        w.clear();
        assert_eq!(w.len(), 0);
    }
}
