//! The logs, and the timings of the start-up.
//!
//! The log page reads the newest log file from where it left off, so that
//! "clear" sticks: the lines before the cursor are never offered again, even
//! though the file itself keeps growing.

use crate::commands::{APP_START, LOG_CURSOR, STARTUP_ERROR};
use crate::error::{codes, AppError};
use crate::log_dir;
use crate::service::IpcClient;

use serde::Serialize;

/// The failure `start_proxy` recorded after it had already returned, if any.
///
/// Infallible: "there is no recorded failure" and "the failure could not be read" are the same
/// answer to the caller. That is also why this deliberately does *not* clear the value — the
/// frontend polls it, and clearing it would make the message flash for one poll interval.
#[tauri::command]
pub(crate) async fn get_startup_error() -> Option<AppError> {
    if let Some(error) = STARTUP_ERROR.read().await.clone() {
        return Some(error);
    }

    // A service-mode start fails in the other process, where this one cannot see it — and its
    // log is written under LocalSystem's profile, which nobody can read. So ask: the service
    // records the same failure with the same code, and an unreachable service or an older build
    // that does not know the question is simply "no failure on file".
    match IpcClient::get_startup_error().await {
        Ok(Some(error)) => Some(error),
        Ok(None) | Err(_) => None,
    }
}

/// The result of `get_logs`.
///
/// `fresh` marks a full tail read (the first poll, a day roll-over, or anything else that
/// invalidates the incremental cursor); the frontend must *replace* its view with `lines`.
/// `fresh: false` lines are an append-only continuation of what was delivered before.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogPage {
    lines: Vec<String>,
    fresh: bool,
}

/// Picks the most recently modified `nexa.log` file in `dir` (daily rolling: `nexa.log.YYYY-MM-DD`).
pub(crate) fn newest_log_file(
    dir: &std::path::Path,
) -> Result<Option<std::path::PathBuf>, AppError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AppError::cause(codes::LOGS_DIR_UNREADABLE, error)),
    };

    Ok(entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("nexa.log"))
                    .unwrap_or(false)
        })
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()))
}

/// Splits `content` into the lines that are guaranteed complete.
///
/// A log file is read while the writer is still appending, so the tail may end mid-line; a
/// fragment without a trailing newline is held back and the returned byte length tells the
/// caller where the complete portion ends, so the next poll re-reads it instead of losing it.
/// Returns `(lines, consumed_bytes)`.
pub(crate) fn complete_lines(content: &str) -> (Vec<&str>, usize) {
    match content.rfind('\n') {
        Some(pos) => (content[..pos].lines().collect(), pos + 1),
        None => (Vec::new(), 0),
    }
}

/// Reads the log file for the frontend log page.
///
/// Pass `append: true` to get only the lines written since the previous call (incremental);
/// the default is a fresh tail read. Incremental reads are what keep the page in sync with a
/// file that outgrew the tail window — a file with more than `limit` lines never changes the
/// *length* of the tail, so counting lines to detect new ones never fires. They are also what
/// makes `clear_logs` stick.
///
/// The lines themselves are raw log output and stay untranslated; only failures to read them are
/// reported as codes.
#[tauri::command]
pub(crate) async fn get_logs(
    limit: Option<usize>,
    append: Option<bool>,
) -> Result<LogPage, AppError> {
    use std::io::{Read, Seek};

    let limit = limit.unwrap_or(200);
    let append = append.unwrap_or(false);
    let dir = log_dir();

    let Some(path) = newest_log_file(&dir)? else {
        *LOG_CURSOR.write().await = None;
        return Ok(LogPage {
            lines: vec![],
            fresh: true,
        });
    };

    let mut file =
        std::fs::File::open(&path).map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut cursor = LOG_CURSOR.write().await;
    let incremental = append
        && cursor
            .as_ref()
            .is_some_and(|c| c.path == path && c.offset <= file_len);

    let (lines, fresh) = if incremental {
        // Continue exactly where the previous read stopped.
        let offset = cursor.as_ref().expect("checked above").offset;
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        // A partially written last line stays in the file for the next poll.
        let (lines, consumed) = complete_lines(&content);
        *cursor = Some(LogCursor {
            path,
            offset: offset + consumed as u64,
        });
        (
            lines.into_iter().map(String::from).collect::<Vec<_>>(),
            false,
        )
    } else {
        // Only read the tail so that large files are not loaded in full. When the window starts
        // mid-line, drop the partial first line instead of showing it as garbled output.
        const MAX_TAIL: u64 = 512 * 1024;
        let tail_offset = file_len.saturating_sub(MAX_TAIL);
        if tail_offset > 0 {
            file.seek(std::io::SeekFrom::Start(tail_offset))
                .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        }
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        if tail_offset > 0 {
            if let Some(pos) = content.find('\n') {
                content.drain(..=pos);
            } else {
                content.clear();
            }
        }
        let all: Vec<&str> = content.lines().collect();
        let start = all.len().saturating_sub(limit);
        let lines = all[start..].iter().map(|l| l.to_string()).collect();
        *cursor = Some(LogCursor {
            path,
            offset: file_len,
        });
        (lines, true)
    };

    Ok(LogPage { lines, fresh })
}

/// Marks every line currently in the newest log file as already seen.
///
/// The frontend clears its view and calls this; the next incremental poll returns only lines
/// written *after* the clear, so old entries never reappear. The file itself is deliberately not
/// truncated: the rolling writer in whichever process owns it (often the service) keeps its
/// handle open, and cutting a file out from under an appender corrupts the stream.
#[tauri::command]
pub(crate) async fn clear_logs() -> Result<(), AppError> {
    let newest = newest_log_file(&log_dir())?;
    *LOG_CURSOR.write().await = newest.and_then(|path| {
        std::fs::File::open(&path)
            .ok()
            .and_then(|f| f.metadata().ok())
            .map(|m| LogCursor {
                path,
                offset: m.len(),
            })
    });
    Ok(())
}

/// Writes the renderer's start-up timings to the log.
///
/// The window is created hidden and shown by the frontend, so "the application takes a while
/// to appear" is a question about code this process cannot see. This is what makes it
/// answerable: the renderer's own series, in the same file as the backend's, measured from the
/// document navigation — and, alongside it, how long this process had been running when the
/// report arrived. The difference is the part neither clock covers.
///
/// Bounded on the way in, because a log line is somewhere a caller can write. The caller here
/// is the renderer, which can reach any other command just as easily, so a mark is treated as
/// untrusted text: control characters dropped, label and count capped. Nothing about this can
/// fail a start-up, so it returns nothing.
#[tauri::command]
pub(crate) async fn log_startup_timing(marks: Vec<(String, f64)>) {
    /// Beyond this a label is prose, not a label.
    const MAX_LABEL_CHARS: usize = 64;
    /// Generous for every mark the start-up path records, and small enough that a series is
    /// one line of log rather than a wall of them.
    const MAX_MARKS: usize = 64;

    let rendered: Vec<String> = marks
        .iter()
        .take(MAX_MARKS)
        .map(|(label, ms)| {
            let label: String = label
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_LABEL_CHARS)
                .collect();
            format!("{label}={ms:.0}ms")
        })
        .collect();

    tracing::info!(
        "[startup] frontend, from the document navigation: {}",
        rendered.join(", ")
    );
    tracing::info!(
        "[startup] process start to this report: {}ms",
        APP_START.elapsed().as_millis()
    );
}

/// How far the log page has read into the newest log file.
///
/// `get_logs` in incremental mode returns only the bytes after this offset, which is what makes
/// "clear" stick: the lines before the offset are never offered to the frontend again, even
/// though the file itself keeps growing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogCursor {
    path: std::path::PathBuf,
    offset: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_lines_hold_back_a_trailing_fragment() {
        let (lines, consumed) = complete_lines("one\ntwo\nthree");

        assert_eq!(lines, vec!["one", "two"]);
        assert_eq!(
            consumed, 8,
            "only the bytes up to and including the last newline"
        );
    }

    #[test]
    fn complete_lines_accept_a_fully_terminated_buffer() {
        let (lines, consumed) = complete_lines("one\ntwo\n");

        assert_eq!(lines, vec!["one", "two"]);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn complete_lines_return_nothing_without_a_newline() {
        let (lines, consumed) = complete_lines("half a line");

        assert!(lines.is_empty());
        assert_eq!(consumed, 0);
    }
}
