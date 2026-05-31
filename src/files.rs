use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::{SegmentId, StoreCfg};

const SEGMENT_MAGIC: [u8; 8] = *b"\xffWDSEGM\x01";
const MANIFEST_MAGIC: [u8; 8] = *b"\xffWDMNFT\x01";
pub const MAGIC_LEN: usize = 8;

const MANIFEST_FILE_NAME: &str = "MANIFEST";

// ── Manifest ──────────────────────────────────────────────────────────────────

pub fn manifest_exists(cfg: &StoreCfg) -> bool {
    manifest_path(cfg).exists()
}

/// Create a new manifest file. Fails if one already exists.
pub fn create_manifest(cfg: &StoreCfg) -> Result<(File, u64), std::io::Error> {
    let path = manifest_path(cfg);
    let mut file = File::create_new(&path)?;
    file.write_all(&MANIFEST_MAGIC)?;
    file.sync_all()?;
    synchronize_dir(cfg)?;
    Ok((file, MAGIC_LEN as u64))
}

/// Open an existing manifest file for append, positioned after magic.
#[cfg(test)]
pub fn open_manifest(cfg: &StoreCfg) -> Result<(File, u64), std::io::Error> {
    use std::fs::OpenOptions;
    let path = manifest_path(cfg);
    let mut file = OpenOptions::new().read(true).append(true).open(&path)?;
    check_magic(&mut file, &MANIFEST_MAGIC, &path)?;
    Ok((file, MAGIC_LEN as u64))
}

/// Open an existing manifest file for random-access read+write (no O_APPEND).
/// Use this when writing via `write_all_at` with a tracked offset.
pub fn open_manifest_rw(cfg: &StoreCfg) -> Result<(File, u64), std::io::Error> {
    use std::fs::OpenOptions;
    let path = manifest_path(cfg);
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    check_magic(&mut file, &MANIFEST_MAGIC, &path)?;
    Ok((file, MAGIC_LEN as u64))
}

/// Open an existing manifest file for reading from the start of frames.
pub fn open_manifest_read(cfg: &StoreCfg) -> Result<(File, u64), std::io::Error> {
    let path = manifest_path(cfg);
    let mut file = File::open(&path)?;
    check_magic(&mut file, &MANIFEST_MAGIC, &path)?;
    Ok((file, MAGIC_LEN as u64))
}

// ── Segments ──────────────────────────────────────────────────────────────────

/// Create a new segment file. Fails if one already exists.
pub fn create_segment(cfg: &StoreCfg, id: SegmentId) -> Result<(File, u64), std::io::Error> {
    let path = segment_path(cfg, id);
    let mut file = File::create_new(&path)?;
    file.write_all(&SEGMENT_MAGIC)?;
    file.sync_all()?;
    Ok((file, MAGIC_LEN as u64))
}

/// Open an existing segment file for reading, returning the file and offset of first frame.
pub fn open_segment(cfg: &StoreCfg, id: SegmentId) -> Result<(File, u64), std::io::Error> {
    let path = segment_path(cfg, id);
    let mut file = File::open(&path)?;
    check_magic(&mut file, &SEGMENT_MAGIC, &path)?;
    Ok((file, MAGIC_LEN as u64))
}

/// Open an existing segment file for read+write, returning the file and offset of first frame.
pub fn open_segment_rw(cfg: &StoreCfg, id: SegmentId) -> Result<(File, u64), std::io::Error> {
    use std::fs::OpenOptions;
    let path = segment_path(cfg, id);
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    check_magic(&mut file, &SEGMENT_MAGIC, &path)?;
    Ok((file, MAGIC_LEN as u64))
}

pub fn segment_size(cfg: &StoreCfg, id: SegmentId) -> Result<u64, std::io::Error> {
    Ok(fs::metadata(segment_path(cfg, id))?.len())
}

pub fn delete_segment(cfg: &StoreCfg, id: SegmentId) -> Result<(), std::io::Error> {
    match fs::remove_file(segment_path(cfg, id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn collect_segment_ids(cfg: &StoreCfg) -> Result<Vec<SegmentId>, std::io::Error> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(&cfg.base_dir)? {
        let path = entry?.path();
        if let Some(id) = parse_segment_path(&path) {
            ids.push(id);
        }
    }
    ids.sort();
    Ok(ids)
}

pub fn synchronize_dir(cfg: &StoreCfg) -> Result<(), std::io::Error> {
    File::open(&cfg.base_dir)?.sync_all()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn manifest_path(cfg: &StoreCfg) -> PathBuf {
    cfg.base_dir.join(MANIFEST_FILE_NAME)
}

fn segment_path(cfg: &StoreCfg, id: SegmentId) -> PathBuf {
    cfg.base_dir.join(format!("{:08x}.seg", id.0))
}

fn check_magic(file: &mut File, expected: &[u8; 8], path: &Path) -> Result<(), std::io::Error> {
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).map_err(|_| bad_magic(path))?;
    if &magic != expected {
        return Err(bad_magic(path));
    }
    Ok(())
}

fn bad_magic(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("invalid magic in {}", path.display()),
    )
}

fn parse_segment_path(path: &Path) -> Option<SegmentId> {
    if path.extension()?.to_str()? != "seg" {
        return None;
    }
    let name = path.file_stem()?.to_str()?;
    let id = u32::from_str_radix(name, 16).ok()?;
    Some(SegmentId(id))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn cfg(dir: &Path) -> StoreCfg {
        StoreCfg { base_dir: dir.to_path_buf(), segment_rollover_trigger_bytes: 64 * 1024 * 1024 }
    }

    #[test]
    fn manifest_create_and_open() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        assert!(!manifest_exists(&cfg));
        create_manifest(&cfg).unwrap();
        assert!(manifest_exists(&cfg));
        open_manifest(&cfg).unwrap();
        open_manifest_read(&cfg).unwrap();
    }

    #[test]
    fn manifest_create_fails_if_exists() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        create_manifest(&cfg).unwrap();
        assert!(create_manifest(&cfg).is_err());
    }

    #[test]
    fn manifest_bad_magic() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        fs::write(dir.path().join("MANIFEST"), b"garbage!").unwrap();
        assert!(open_manifest(&cfg).is_err());
    }

    #[test]
    fn segment_create_and_open() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        let id = SegmentId(1);
        create_segment(&cfg, id).unwrap();
        open_segment(&cfg, id).unwrap();
        open_segment_rw(&cfg, id).unwrap();
    }

    #[test]
    fn segment_create_fails_if_exists() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        create_segment(&cfg, SegmentId(1)).unwrap();
        assert!(create_segment(&cfg, SegmentId(1)).is_err());
    }

    #[test]
    fn segment_bad_magic() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        fs::write(dir.path().join("00000001.seg"), b"garbage!").unwrap();
        assert!(open_segment(&cfg, SegmentId(1)).is_err());
    }

    #[test]
    fn delete_segment_idempotent() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        create_segment(&cfg, SegmentId(5)).unwrap();
        delete_segment(&cfg, SegmentId(5)).unwrap();
        delete_segment(&cfg, SegmentId(5)).unwrap(); // not found is ok
    }

    #[test]
    fn collect_segment_ids_sorted() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        create_segment(&cfg, SegmentId(3)).unwrap();
        create_segment(&cfg, SegmentId(1)).unwrap();
        create_segment(&cfg, SegmentId(2)).unwrap();
        assert_eq!(
            collect_segment_ids(&cfg).unwrap(),
            vec![SegmentId(1), SegmentId(2), SegmentId(3)]
        );
    }

    #[test]
    fn collect_segment_ids_ignores_other_files() {
        let dir = tempdir().unwrap();
        let cfg = cfg(dir.path());
        create_manifest(&cfg).unwrap();
        create_segment(&cfg, SegmentId(1)).unwrap();
        assert_eq!(collect_segment_ids(&cfg).unwrap(), vec![SegmentId(1)]);
    }
}
