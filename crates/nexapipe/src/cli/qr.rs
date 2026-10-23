//! The QR code: printed on the terminal, or written to a file.

use crate::{Cli, QrFormat};

/// Prints (and, with `--qr-out`, writes) a QR code of `link` in whatever format
/// was asked for.
pub(super) fn render_qr(link: &str, cli: &Cli, header: &str) -> anyhow::Result<()> {
    if cli.qr_format != QrFormat::None {
        println!("{header}");
        let qr = match cli.qr_format {
            QrFormat::Unicode => nexapipe::qr::render_unicode(link, cli.qr_invert)?,
            QrFormat::Plain => nexapipe::qr::render_plain(link, cli.qr_invert)?,
            QrFormat::Ascii => nexapipe::qr::render_ascii(link, cli.qr_invert)?,
            QrFormat::Svg => nexapipe::qr::render_svg(link, cli.qr_invert)?,
            QrFormat::None => unreachable!("filtered above"),
        };
        print!("{qr}");
        println!();
    }

    if let Some(path) = &cli.qr_out {
        write_qr_file(path, link, cli.qr_invert)?;
    }
    Ok(())
}

/// Writes the QR code to `path`. The extension picks the format: `.svg` is a
/// standalone document, anything else is ASCII text with the URI on top.
///
/// The file carries the TOTP secret in the clear, so it is written private: a
/// QR code left at the default mode is a credential anybody with access to the
/// machine can read back.
fn write_qr_file(path: &str, link: &str, invert: bool) -> anyhow::Result<()> {
    use std::io::Write;

    let is_svg = path.to_ascii_lowercase().ends_with(".svg");
    let content = if is_svg {
        nexapipe::qr::render_svg(link, invert)?
    } else {
        format!(
            "# NexaPipe 2FA enrollment\n# {link}\n{}",
            nexapipe::qr::render_ascii(link, invert)?
        )
    };

    // Opened with the mode in the same call that creates it, rather than
    // written and then made private. `fs::write` truncates whatever is already
    // at the path and follows a symlink to reach it, so a `--qr-out` naming a
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
