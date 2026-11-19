//! The QR code: printed on the terminal, or written to a file.

use crate::{Cli, QrFormat};

/// Prints (and, with `--out`, writes) a QR code of `text` in whatever format
/// was asked for.
///
/// `header` is the line above the code, when the code is one part of a longer
/// report; `file_title` is the comment a text file carries, because a file
/// found later has nothing else to say what it is.
pub(super) fn render_qr(
    text: &str,
    cli: &Cli,
    header: Option<&str>,
    file_title: &str,
) -> anyhow::Result<()> {
    if cli.qr_format != QrFormat::None {
        if let Some(header) = header {
            println!("{header}");
        }
        let qr = match cli.qr_format {
            QrFormat::Unicode => nexapipe::qr::render_unicode(text, cli.qr_invert)?,
            QrFormat::Plain => nexapipe::qr::render_plain(text, cli.qr_invert)?,
            QrFormat::Ascii => nexapipe::qr::render_ascii(text, cli.qr_invert)?,
            QrFormat::Svg => nexapipe::qr::render_svg(text, cli.qr_invert)?,
            QrFormat::None => unreachable!("filtered above"),
        };
        print!("{qr}");
        println!();
    }

    if let Some(path) = &cli.qr_out {
        write_qr_file(path, text, cli.qr_invert, file_title)?;
    }
    Ok(())
}

/// A QR code of the text given, and nothing else: `nexapipe qr <TEXT>`.
pub(crate) fn print_qr(text: &str, cli: &Cli) -> anyhow::Result<()> {
    let text = text.trim();
    if text.is_empty() {
        anyhow::bail!("there is no text to draw: pass the text the code should carry");
    }
    render_qr(text, cli, None, "NexaPipe QR code")
}

/// Writes the QR code to `path`. The extension picks the format: `.svg` is a
/// standalone document, anything else is ASCII text with the text on top.
///
/// The file carries a credential whenever the code does — a TOTP secret, an
/// enrollment token — so it is written private: a QR code left at the default
/// mode is a credential anybody with access to the machine can read back.
fn write_qr_file(path: &str, text: &str, invert: bool, title: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let is_svg = path.to_ascii_lowercase().ends_with(".svg");
    let content = if is_svg {
        nexapipe::qr::render_svg(text, invert)?
    } else {
        format!(
            "# {title}\n# {text}\n{}",
            nexapipe::qr::render_ascii(text, invert)?
        )
    };

    // Opened with the mode in the same call that creates it, rather than
    // written and then made private. `fs::write` truncates whatever is already
    // at the path and follows a symlink to reach it, so a `--out` naming a
    // file another account got there first could aim the write at something the
    // operator owns; and between the create and the chmod the file is readable
    // by anyone watching. `create_new` refuses to open a path that already
    // exists, which closes both, and the mode is applied by the same open.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::AlreadyExists {
            " (refusing to overwrite a file that is already there)"
        } else {
            ""
        };
        anyhow::anyhow!("failed to write the QR code to {path}: {e}{hint}")
    })?;
    file.write_all(content.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write the QR code to {path}: {e}"))?;

    println!();
    println!(
        "Wrote the QR code to {path} ({})",
        if is_svg { "SVG" } else { "ASCII" }
    );
    Ok(())
}
