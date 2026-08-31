//! Durable storage for audit evidence.
//!
//! # Why
//!
//! A hash chain held only in memory proves nothing after a restart. Worse than losing it:
//! restarting would begin a *new* chain at sequence 0, so the log would contain two
//! independently-valid chains and no way to tell a legitimate restart from an attacker who
//! truncated the old one and started fresh. Recovery — resuming the existing chain — is the
//! property that matters, not merely writing bytes somewhere.
//!
//! # What
//!
//! [`AuditSink`] is the persistence seam. [`FileAuditSink`] is an append-only JSONL
//! implementation that fsyncs each record before reporting success, and can rebuild the
//! chain head on startup so a restarted process continues where it left off.
//!
//! # Assumptions
//!
//! [`FileAuditSink`] is **single-writer**. Two processes appending to one file would
//! interleave records and produce duplicate sequence numbers. A multi-replica deployment
//! needs a store with an atomic sequence allocator — a Postgres table with
//! `UNIQUE (tenant_id, sequence)` is the intended production implementation, and the trait
//! exists so it drops in without touching the chain logic.
//!
//! # Failure mode
//!
//! An append that cannot be durably written returns `Err`, and [`crate::AuditChain::append`]
//! propagates it. The caller — the decision pipeline — treats a failed audit write as a
//! failed decision. A system that keeps enforcing while silently losing its evidence is
//! worse than one that stops.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vigil_common::{ContentHash, Result, VigilError};

use crate::{AuditEntry, Checkpoint};

/// Where committed audit records are persisted.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Durably append one entry. Must not return `Ok` until the record survives a crash.
    fn append(&self, entry: &AuditEntry) -> Result<()>;

    /// Durably record a signed checkpoint.
    fn append_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()>;

    /// Load everything previously written, for recovery and for verification.
    fn load(&self) -> Result<(Vec<AuditEntry>, Vec<Checkpoint>)>;
}

/// The state a restarted chain resumes from.
#[derive(Debug, Clone)]
pub struct RecoveredState {
    pub next_sequence: u64,
    pub head: Option<ContentHash>,
    pub entries_recovered: u64,
    pub checkpoints_recovered: u64,
}

/// An append-only, fsync-on-write file sink.
#[derive(Debug)]
pub struct FileAuditSink {
    entries_path: PathBuf,
    checkpoints_path: PathBuf,
    /// Serializes writers within this process. Cross-process safety is not provided; see the
    /// module docs.
    writer: Mutex<()>,
    /// Whether to fsync each record. Disabling trades durability for throughput and is only
    /// appropriate where the evidence is replicated some other way.
    fsync: bool,
}

impl FileAuditSink {
    /// Open (or create) a sink rooted at `directory`.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        Ok(Self {
            entries_path: directory.join("entries.jsonl"),
            checkpoints_path: directory.join("checkpoints.jsonl"),
            writer: Mutex::new(()),
            fsync: true,
        })
    }

    /// Disable per-record fsync.
    ///
    /// Only for tests and for deployments where durability is provided by replication. The
    /// method is named to make its appearance in a diff obvious.
    pub fn without_durability_guarantee(mut self) -> Self {
        self.fsync = false;
        self
    }

    fn append_line(&self, path: &Path, line: &str) -> Result<()> {
        let _guard = self.writer.lock().map_err(|_| {
            VigilError::AuditIntegrity(
                "audit sink lock poisoned; refusing to write an unordered record".to_string(),
            )
        })?;

        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        // One record per line, written in a single call so a crash cannot interleave two
        // records within a line.
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        if self.fsync {
            // Without this, `append` returns success for a record still sitting in the page
            // cache — which a power loss discards, leaving a gap the verifier reports but
            // nobody caused.
            file.sync_all()?;
        }
        Ok(())
    }

    /// Rebuild the chain state a restarted process should resume from.
    ///
    /// This is what stops a restart from forking a second chain at sequence 0.
    pub fn recover(&self) -> Result<RecoveredState> {
        let (entries, checkpoints) = self.load()?;
        let last = entries.last();
        Ok(RecoveredState {
            next_sequence: last.map(|e| e.sequence + 1).unwrap_or(0),
            head: last.map(|e| e.chain_hash.clone()),
            entries_recovered: entries.len() as u64,
            checkpoints_recovered: checkpoints.len() as u64,
        })
    }

    fn read_lines<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path)?;
        let mut out = Vec::new();
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // A record that will not parse is corruption, not something to skip past: the
            // chain's whole value is that gaps are detectable, so a silent skip would defeat
            // the mechanism.
            let value = serde_json::from_str(&line).map_err(|e| {
                VigilError::AuditIntegrity(format!(
                    "{}: record {} is unreadable: {e}",
                    path.display(),
                    index + 1
                ))
            })?;
            out.push(value);
        }
        Ok(out)
    }
}

impl AuditSink for FileAuditSink {
    fn append(&self, entry: &AuditEntry) -> Result<()> {
        let line = serde_json::to_string(entry)?;
        self.append_line(&self.entries_path, &line)
    }

    fn append_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()> {
        let line = serde_json::to_string(checkpoint)?;
        self.append_line(&self.checkpoints_path, &line)
    }

    fn load(&self) -> Result<(Vec<AuditEntry>, Vec<Checkpoint>)> {
        Ok((
            Self::read_lines(&self.entries_path)?,
            Self::read_lines(&self.checkpoints_path)?,
        ))
    }
}

/// A sink that discards everything. The default when no durable store is configured.
///
/// Named so its presence in a production configuration is self-evidently wrong.
#[derive(Debug, Default)]
pub struct NonDurableSink;

impl AuditSink for NonDurableSink {
    fn append(&self, _entry: &AuditEntry) -> Result<()> {
        Ok(())
    }
    fn append_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<()> {
        Ok(())
    }
    fn load(&self) -> Result<(Vec<AuditEntry>, Vec<Checkpoint>)> {
        Ok((Vec::new(), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vigil-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn an_empty_sink_recovers_to_the_start_of_a_chain() {
        let sink = FileAuditSink::open(tempdir("empty")).unwrap();
        let state = sink.recover().unwrap();
        assert_eq!(state.next_sequence, 0);
        assert!(state.head.is_none());
    }

    #[test]
    fn a_corrupt_record_is_reported_rather_than_skipped() {
        // Skipping an unreadable line would hide exactly the gap the chain exists to expose.
        let dir = tempdir("corrupt");
        let sink = FileAuditSink::open(&dir).unwrap();
        std::fs::write(dir.join("entries.jsonl"), "{not json}\n").unwrap();

        let err = sink.load().unwrap_err();
        assert!(matches!(err, VigilError::AuditIntegrity(_)), "{err}");
    }

    #[test]
    fn the_non_durable_sink_loads_nothing_it_was_given() {
        let sink = NonDurableSink;
        assert!(sink.load().unwrap().0.is_empty());
    }
}
