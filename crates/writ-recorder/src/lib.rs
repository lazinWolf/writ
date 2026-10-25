//! Flight recorder: an append-only JSONL log in which every entry carries the
//! SHA-256 of the previous entry.
//!
//! The chain is tamper-*evident* only against parties who cannot rewrite the
//! whole file. Anyone with write access can recompute the chain, so
//! non-repudiation needs external anchoring (plan-v2.md §4.6, D7), which this
//! build does not do yet.
//!
//! Several processes may append to the same file: each append takes an
//! exclusive file lock, reads the chain head, and writes one line.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    #[error("flight recorder I/O error on {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("flight recorder {path} is corrupt at line {line}: {reason}")]
    Corrupt { path: PathBuf, line: u64, reason: String },
    #[error("flight recorder {path} is corrupt: last entry does not parse ({reason}); refusing to extend it")]
    CorruptHead { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts: String,
    pub session: String,
    pub kind: String,
    pub data: Value,
    pub prev: String,
    pub hash: String,
}

/// The hashed portion of an entry: everything except `hash` itself.
#[derive(Serialize)]
struct Body<'a> {
    seq: u64,
    ts: &'a str,
    session: &'a str,
    kind: &'a str,
    data: &'a Value,
    prev: &'a str,
}

impl Entry {
    fn compute_hash(&self) -> String {
        let body = Body {
            seq: self.seq,
            ts: &self.ts,
            session: &self.session,
            kind: &self.kind,
            data: &self.data,
            prev: &self.prev,
        };
        // serde_json writes struct fields in declaration order and object keys
        // in sorted order (no `preserve_order` feature), so this is canonical.
        let bytes = serde_json::to_vec(&body).expect("entry body serializes");
        hex(&Sha256::digest(&bytes))
    }
}

pub struct Recorder {
    path: PathBuf,
    file: File,
}

impl Recorder {
    /// Opens (creating if needed) the log at `path`, and its parent directory.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RecorderError> {
        let path = path.into();
        let io_err = |source| RecorderError::Io {
            path: path.clone(),
            source,
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(io_err)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(io_err)?;
        Ok(Recorder { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one entry and returns it. Fails if the existing chain head is
    /// unreadable, so a damaged log is never silently extended.
    pub fn append(&mut self, session: &str, kind: &str, data: Value) -> Result<Entry, RecorderError> {
        let path = self.path.clone();
        let io_err = |source| RecorderError::Io {
            path: path.clone(),
            source,
        };

        self.file.lock().map_err(io_err)?;
        let result = (|| {
            let (seq, prev) = match read_last_line(&mut self.file).map_err(io_err)? {
                None => (0, GENESIS_HASH.to_string()),
                Some(line) => {
                    let head: Entry = serde_json::from_str(&line).map_err(|e| RecorderError::CorruptHead {
                        path: path.clone(),
                        reason: e.to_string(),
                    })?;
                    (head.seq + 1, head.hash)
                }
            };
            let mut entry = Entry {
                seq,
                ts: humantime::format_rfc3339_millis(SystemTime::now()).to_string(),
                session: session.to_string(),
                kind: kind.to_string(),
                data,
                prev,
                hash: String::new(),
            };
            entry.hash = entry.compute_hash();

            let mut line = serde_json::to_vec(&entry).expect("entry serializes");
            line.push(b'\n');
            self.file.write_all(&line).map_err(io_err)?;
            self.file.flush().map_err(io_err)?;
            Ok(entry)
        })();
        // Unlock even when the append failed; closing the file would also release it.
        let _ = self.file.unlock();
        result
    }
}

/// Reads every entry without checking the chain.
pub fn read_entries(path: impl AsRef<Path>) -> Result<Vec<Entry>, RecorderError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| RecorderError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut entries = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|source| RecorderError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let entry = serde_json::from_str(&line).map_err(|e| RecorderError::Corrupt {
            path: path.to_path_buf(),
            line: i as u64 + 1,
            reason: e.to_string(),
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Checks sequence numbers, back-links, and hashes for every entry.
/// Returns the number of entries verified.
pub fn verify(path: impl AsRef<Path>) -> Result<u64, RecorderError> {
    let path = path.as_ref();
    let corrupt = |line: u64, reason: String| RecorderError::Corrupt {
        path: path.to_path_buf(),
        line,
        reason,
    };

    let mut prev = GENESIS_HASH.to_string();
    let entries = read_entries(path)?;
    for (i, entry) in entries.iter().enumerate() {
        let line = i as u64 + 1;
        if entry.seq != i as u64 {
            return Err(corrupt(line, format!("expected seq {i}, found {}", entry.seq)));
        }
        if entry.prev != prev {
            return Err(corrupt(
                line,
                "prev does not match the previous entry's hash".to_string(),
            ));
        }
        if entry.compute_hash() != entry.hash {
            return Err(corrupt(line, "hash does not match entry contents".to_string()));
        }
        prev = entry.hash.clone();
    }
    Ok(entries.len() as u64)
}

/// `$WRIT_LOG`, else `$XDG_STATE_HOME/writ/flight.jsonl`, else
/// `~/.local/state/writ/flight.jsonl`, else `./writ-flight.jsonl`.
pub fn default_log_path() -> PathBuf {
    let non_empty = |key| std::env::var_os(key).filter(|v| !v.is_empty());
    if let Some(path) = non_empty("WRIT_LOG") {
        return PathBuf::from(path);
    }
    if let Some(state) = non_empty("XDG_STATE_HOME") {
        return PathBuf::from(state).join("writ/flight.jsonl");
    }
    if let Some(home) = non_empty("HOME") {
        return PathBuf::from(home).join(".local/state/writ/flight.jsonl");
    }
    PathBuf::from("writ-flight.jsonl")
}

/// Returns the last non-empty line, reading backwards from the end so appends
/// stay O(entry size), not O(file size).
fn read_last_line(file: &mut File) -> io::Result<Option<String>> {
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }

    const CHUNK: u64 = 8192;
    let mut tail: Vec<u8> = Vec::new();
    let mut pos = len;
    let start = loop {
        let read_from = pos.saturating_sub(CHUNK);
        let mut chunk = vec![0; (pos - read_from) as usize];
        file.seek(SeekFrom::Start(read_from))?;
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&tail);
        tail = chunk;
        pos = read_from;

        let content_end = tail.iter().rposition(|&b| b != b'\n').map_or(0, |i| i + 1);
        if let Some(nl) = tail[..content_end].iter().rposition(|&b| b == b'\n') {
            break nl + 1;
        }
        if pos == 0 {
            break 0;
        }
    };
    let content_end = tail.iter().rposition(|&b| b != b'\n').map_or(0, |i| i + 1);
    if content_end <= start {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&tail[start..content_end]).into_owned()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of arbitrary bytes, hex-encoded (e.g. for recording a policy hash).
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn appends_form_a_verifiable_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/flight.jsonl");
        let mut rec = Recorder::open(&path).unwrap();
        let a = rec.append("s1", "session_start", json!({"cmd": ["x"]})).unwrap();
        let b = rec.append("s1", "tool_call", json!({"tool": "t"})).unwrap();
        assert_eq!(a.prev, GENESIS_HASH);
        assert_eq!(b.prev, a.hash);
        assert_eq!(b.seq, 1);
        assert_eq!(verify(&path).unwrap(), 2);
    }

    #[test]
    fn separate_recorders_share_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flight.jsonl");
        let mut r1 = Recorder::open(&path).unwrap();
        let mut r2 = Recorder::open(&path).unwrap();
        for i in 0..5 {
            r1.append("s1", "e", json!({ "i": i })).unwrap();
            r2.append("s2", "e", json!({ "i": i })).unwrap();
        }
        assert_eq!(verify(&path).unwrap(), 10);
    }

    #[test]
    fn concurrent_appends_from_threads_keep_the_chain_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flight.jsonl");
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut rec = Recorder::open(&path).unwrap();
                    for i in 0..25 {
                        rec.append(&format!("s{t}"), "e", json!({ "i": i })).unwrap();
                    }
                })
            })
            .collect();
        handles.into_iter().for_each(|h| h.join().unwrap());
        assert_eq!(verify(&path).unwrap(), 100);
    }

    #[test]
    fn large_entries_span_read_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flight.jsonl");
        let mut rec = Recorder::open(&path).unwrap();
        let big = "x".repeat(20_000);
        rec.append("s", "e", json!({ "big": big })).unwrap();
        rec.append("s", "e", json!({ "big": big })).unwrap();
        rec.append("s", "e", json!({})).unwrap();
        assert_eq!(verify(&path).unwrap(), 3);
    }

    #[test]
    fn detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flight.jsonl");
        let mut rec = Recorder::open(&path).unwrap();
        rec.append("s", "tool_call", json!({"tool": "stripe.refund", "amount": 240}))
            .unwrap();
        rec.append("s", "tool_call", json!({"tool": "other"})).unwrap();

        let original = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, original.replace("240", "24")).unwrap();
        let err = verify(&path).unwrap_err().to_string();
        assert!(err.contains("line 1") && err.contains("hash"), "{err}");

        // Deleting the first entry breaks seq and back-links.
        let second = original.lines().nth(1).unwrap();
        std::fs::write(&path, format!("{second}\n")).unwrap();
        assert!(verify(&path).is_err());
    }

    #[test]
    fn refuses_to_extend_a_corrupt_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flight.jsonl");
        std::fs::write(&path, "{\"truncated\": \n").unwrap();
        let mut rec = Recorder::open(&path).unwrap();
        let err = rec.append("s", "e", json!({})).unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
    }
}
