//! The file a log line is written to.
//!
//! A sink is a file that is appended to, rolled over on a schedule or by size,
//! and pruned down to a bounded number of copies — so a long running container
//! cannot fill the disk with its own logs. The line goes through a writer that
//! holds the file's lock, so a line is whole when it lands.

use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing_subscriber::fmt::MakeWriter;

use super::Rotation;

/// A shared, self-rotating log file. Cloning is cheap: every clone writes to the
/// same file, which is what [`MakeWriter`] needs for each `tracing` event.
#[derive(Clone)]
pub struct FileSink {
    state: Arc<Mutex<SinkState>>,
}

struct SinkState {
    /// Path of the active file; rotated copies live next to it.
    path: PathBuf,
    file: Option<File>,
    rotation: Rotation,
    /// Bucket the active file belongs to.
    stamp: Option<String>,
    /// Bytes in the active file so far.
    written: u64,
    /// Rotate once the active file would exceed this (0 = time based only).
    max_bytes: u64,
    /// Rotated copies to keep (0 = keep all).
    max_files: usize,
    /// Whether the last failure was already reported on stderr.
    reported: bool,
}

impl FileSink {
    pub(super) fn new(
        dir: &Path,
        name: &str,
        rotation: Rotation,
        max_size_mb: u64,
        max_files: usize,
    ) -> io::Result<Self> {
        fs::create_dir_all(dir)?;

        let path = dir.join(name);
        let file = open_append(&path)?;
        // The file is opened in append mode, so carry on counting where the
        // previous run stopped.
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);

        Ok(Self {
            state: Arc::new(Mutex::new(SinkState {
                path,
                file: Some(file),
                rotation,
                stamp: rotation.stamp(),
                written,
                max_bytes: max_size_mb.saturating_mul(1024 * 1024),
                max_files,
                reported: false,
            })),
        })
    }

    /// Path of the active file.
    pub fn path(&self) -> PathBuf {
        self.lock().path.clone()
    }

    /// Append one line, adding a trailing newline when missing.
    pub fn write_line(&self, line: &str) {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        if !line.ends_with('\n') {
            buf.push(b'\n');
        }

        let _ = self.lock().append(&buf);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SinkState> {
        // A panic somewhere else must not take logging down with it.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl SinkState {
    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.rotate_if_needed(buf.len());

        let result = match self.file.as_mut() {
            Some(file) => file.write_all(buf).and_then(|()| file.flush()),
            None => Err(io::Error::other("log file is not open")),
        };

        match result {
            Ok(()) => {
                self.written += buf.len() as u64;
                self.reported = false;
                Ok(())
            }
            Err(err) => {
                // Report once and stay quiet afterwards: a full disk must not
                // turn every log line into another stderr message.
                if !self.reported {
                    eprintln!("nexapipe: failed to write {}: {}", self.path.display(), err);
                    self.reported = true;
                }
                // The file may have been removed or replaced behind our back
                // (host side rotation, `docker compose down`, ...): reopen it.
                self.file = open_append(&self.path).ok();
                Err(err)
            }
        }
    }

    fn rotate_if_needed(&mut self, incoming: usize) {
        let by_size = self.max_bytes > 0
            && self.written > 0
            && self.written.saturating_add(incoming as u64) > self.max_bytes;
        let by_time = self
            .rotation
            .stamp()
            .is_some_and(|stamp| self.stamp.as_deref() != Some(stamp.as_str()));

        if by_size || by_time {
            self.rotate();
        }
    }

    /// Rename the active file to `<stem>.<stamp>.<ext>` and start a fresh one.
    ///
    /// Failures are reported on stderr and never propagate: dropping a log line
    /// because rotation failed would be worse than a mixed up file.
    fn rotate(&mut self) {
        let stamp = self
            .rotation
            .stamp()
            .unwrap_or_else(|| Local::now().format("%Y-%m-%d-%H%M%S").to_string());
        let rotated = rotated_path(&self.path, &stamp);

        // Windows refuses to rename a file that is still open.
        drop(self.file.take());
        let renamed = fs::rename(&self.path, &rotated);
        self.file = open_append(&self.path).ok();

        match renamed {
            Ok(()) => {
                self.written = 0;
                self.stamp = self.rotation.stamp();
                prune_rotated_files(&self.path, self.max_files);
            }
            Err(err) => {
                if !self.reported {
                    eprintln!(
                        "nexapipe: failed to rotate {}: {}",
                        self.path.display(),
                        err
                    );
                    self.reported = true;
                }
                // Do not retry the same rotation on every following line.
                self.max_bytes = 0;
                self.stamp = self.rotation.stamp();
            }
        }
    }
}

/// Writer handed to `tracing` for every event; writes into the shared [`FileSink`].
pub struct SinkWriter {
    sink: FileSink,
}

impl Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.sink.lock().append(buf) {
            Ok(()) => Ok(buf.len()),
            // `tracing` swallows writer errors, so reporting the failure instead
            // of pretending the write succeeded is what keeps it visible.
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.sink.lock().file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> MakeWriter<'a> for FileSink {
    type Writer = SinkWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SinkWriter { sink: self.clone() }
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// `<dir>/<stem>.<stamp>.<ext>`, with a counter appended when that name is taken.
fn rotated_path(active: &Path, stamp: &str) -> PathBuf {
    let dir = active.parent().unwrap_or_else(|| Path::new("."));
    let stem = active
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("nexapipe");
    let ext = active.extension().and_then(|ext| ext.to_str());

    let named = |suffix: &str| match ext {
        Some(ext) => dir.join(format!("{}.{}.{}", stem, suffix, ext)),
        None => dir.join(format!("{}.{}", stem, suffix)),
    };

    let mut candidate = named(stamp);
    let mut counter = 1;
    while candidate.exists() {
        candidate = named(&format!("{}-{}", stamp, counter));
        counter += 1;
    }
    candidate
}

/// Keep at most `keep` rotated files for `active`, deleting the oldest first.
fn prune_rotated_files(active: &Path, keep: usize) {
    if keep == 0 {
        return;
    }

    let Some(active_name) = active.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let Some(dir) = active.parent() else {
        return;
    };
    let prefix = format!(
        "{}.",
        active
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(active_name)
    );
    let suffix = active
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext));

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    let mut rotated: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        // Only ever touch files this sink created: `<stem>.<stamp>.<ext>`.
        if name == active_name || !name.starts_with(&prefix) {
            continue;
        }
        if let Some(suffix) = &suffix
            && !name.ends_with(suffix.as_str())
        {
            continue;
        }

        let modified = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        rotated.push((modified, path));
    }

    if rotated.len() <= keep {
        return;
    }

    rotated.sort_by_key(|(modified, _)| *modified);
    for (_, path) in rotated.iter().take(rotated.len() - keep) {
        let _ = fs::remove_file(path);
    }
}

/// Byte level size budget, which the public API only exposes in MiB.
#[cfg(test)]
pub(super) fn sink_with(dir: &Path, name: &str, max_bytes: u64, max_files: usize) -> FileSink {
    let path = dir.join(name);
    let file = open_append(&path).unwrap();

    FileSink {
        state: Arc::new(Mutex::new(SinkState {
            path,
            file: Some(file),
            rotation: Rotation::Never,
            stamp: None,
            written: 0,
            max_bytes,
            max_files,
            reported: false,
        })),
    }
}
