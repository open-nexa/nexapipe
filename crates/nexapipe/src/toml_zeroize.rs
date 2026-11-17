//! Zeroing the TOML a config is written from.
//!
//! A config file can carry the 2FA seeds in the clear, and every writer that
//! touches it puts those bytes somewhere in the heap on the way to the file
//! again. The typed values are wiped when they go out of scope; the
//! intermediate copies are not, unless something wipes them.
//!
//! One shape of intermediate copy turns up on the write path:
//! `toml_edit::DocumentMut`, which it parses the file into before changing one
//! section and writing the file back. [`zeroize_document`] takes the strings
//! out of such a document and zeroes them.
//!
//! What none of them can reach is the raw text `toml_edit` keeps for every
//! value it parsed. For `secret = "ABC123"` that text is `"ABC123"`, the
//! source with its quotes, so the heap holds the secret twice: the decoded
//! value and the text it was decoded from. It lives in a private `RawString`
//! behind `Formatted::repr`, which exposes only `&str` and has no `&mut` path
//! to the bytes, so the only way at it is `unsafe` or a fork of the crate.
//! One copy of every string on the write path is therefore left behind, and
//! saying so plainly beats describing the write path as clean.
//!
//! The read path has no such copy to wipe. It used to parse the file into a
//! `toml::Value` tree first — a copy of the document in plain strings, the
//! seeds included — and that tree is gone: the parse goes straight into the
//! typed model, where every credential is a [`SecretString`] that wipes
//! itself. The two `toml::Value`s that [`Config`](crate::config::Config)
//! holds outside the tree — `default_backend` and `acme` — come from the same
//! document, but they hold no credentials (`build_routes` refuses a
//! `default_backend` outright and `acme` is ignored and reported), and they
//! live as long as the config does, which is the life of the process.

use toml_edit::{DocumentMut, Formatted, Item, Table, Value};
use zeroize::Zeroize;

/// Zeroes every string a document holds.
///
/// `toml_edit` keeps each value in a `Formatted<String>` whose fields are
/// private, so the only way at the bytes is to take the value out of the item
/// and zero it there.
///
/// That is one of the two copies a string on the write path has. The other is
/// the raw text the value was parsed from, which lives in a private
/// `RawString` behind `Formatted::repr` — `&str` is all that is exposed of it,
/// and there is no `&mut` path to the bytes. The raw text is a copy of the
/// secret as well, and it is left behind: reaching it would take `unsafe` or
/// a fork of the library.
pub fn zeroize_document(document: &mut DocumentMut) {
    zeroize_table(document.as_table_mut());
}

fn zeroize_table(table: &mut Table) {
    for (_, item) in table.iter_mut() {
        zeroize_item(item);
    }
}

fn zeroize_item(item: &mut Item) {
    match item {
        Item::None => {}
        Item::Value(value) => zeroize_edit_value(value),
        Item::Table(table) => zeroize_table(table),
        Item::ArrayOfTables(tables) => {
            for table in tables.iter_mut() {
                zeroize_table(table);
            }
        }
    }
}

fn zeroize_edit_value(value: &mut Value) {
    match value {
        Value::String(_) => {
            // Taken out of the item rather than borrowed from it:
            // `Formatted` gives its value away only by being consumed, and
            // the placeholder it leaves behind is what keeps the document
            // walkable.
            let placeholder = Value::String(Formatted::new(String::new()));
            let owned = std::mem::replace(value, placeholder);
            if let Value::String(formatted) = owned {
                let mut text = formatted.into_value();
                text.zeroize();
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                zeroize_edit_value(item);
            }
        }
        Value::InlineTable(table) => {
            for (_, value) in table.iter_mut() {
                zeroize_edit_value(value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document's strings are wiped in place: the values are taken out of
    /// the items they sit in, and the document stays walkable afterwards.
    #[test]
    fn a_wiped_document_has_no_string_left_in_it() {
        let mut document: DocumentMut = r#"
[auth.clients.one]
secret = "ABC123"
"#
        .parse()
        .expect("parses");

        zeroize_document(&mut document);

        let text = document.to_string();
        assert!(
            !text.contains("ABC123"),
            "the seed is still in the document: {text}"
        );
    }
}
