//! Zeroing the TOML a config is read into and written from.
//!
//! A config file can carry the 2FA seeds in the clear, and every parser that
//! touches it puts those bytes somewhere in the heap on the way to the typed
//! values the server runs on. The typed values are wiped when they go out of
//! scope; the intermediate copies are not, unless something wipes them.
//!
//! Two shapes of intermediate copy turn up in this crate:
//!
//! - `toml::Value`, which owns a `String` for every string in the document.
//!   [`ZeroizedValue`] wipes such a tree when it goes out of scope, so a copy
//!   dropped on an error path is wiped on the way out like any other.
//! - `toml_edit::DocumentMut`, which the write path parses the file into
//!   before changing one section and writing the file back.
//!   [`zeroize_document`] takes the strings out of such a document and zeroes
//!   them.
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
//! Two things are left alone on purpose:
//!
//! - The keys of a table. A key names a thing — a client, a device, a route
//!   — and the credentials in a config are values, not names.
//! - The two `toml::Value`s that [`ProxyConfig`](crate::config::ProxyConfig)
//!   holds outside the tree: `default_backend` and `acme`. They come from the
//!   same document, but they hold no credentials — `build_routes` refuses a
//!   `default_backend` outright and `acme` is ignored and reported — and they
//!   live as long as the config does, which is the life of the process.

use toml_edit::{DocumentMut, Formatted, Item, Table, Value};
use zeroize::Zeroize;

/// Zeroes every string a `toml::Value` holds, in place.
///
/// The numbers, the booleans and the datetimes are left alone: they are not
/// credentials, and the tree is walked once on the way out.
pub fn zeroize_value(value: &mut toml::Value) {
    match value {
        toml::Value::String(text) => text.zeroize(),
        toml::Value::Array(items) => items.iter_mut().for_each(zeroize_value),
        toml::Value::Table(table) => table.iter_mut().for_each(|(_, value)| zeroize_value(value)),
        _ => {}
    }
}

/// A `toml::Value` that zeroes its strings when it goes out of scope.
///
/// The tree a config file is parsed into is a copy of the file in plain
/// strings, the 2FA seeds included, and it is dropped on every way out of the
/// function that made it — the error paths as much as the successful one. A
/// guard wipes it on the way instead of leaving it to the allocator.
pub struct ZeroizedValue(toml::Value);

impl ZeroizedValue {
    /// Wraps a value so that its strings are zeroed when it is dropped.
    pub fn new(value: toml::Value) -> Self {
        Self(value)
    }

    /// The table the value holds, if it is one.
    ///
    /// Used to take a section out of the tree by value: a section that is
    /// moved out is a section the tree no longer holds a copy of.
    pub fn table_mut(&mut self) -> Option<&mut toml::map::Map<String, toml::Value>> {
        self.0.as_table_mut()
    }
}

impl Drop for ZeroizedValue {
    fn drop(&mut self) {
        zeroize_value(&mut self.0);
    }
}

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

    /// A wiped string is empty: `zeroize` writes zeroes over the bytes and
    /// then clears the length, so what the secret was is neither readable nor
    /// left in the buffer.
    #[test]
    fn a_wiped_string_is_empty() {
        let mut value: toml::Value = toml::from_str("secret = \"ABC123\"").expect("parses");
        zeroize_value(&mut value);

        assert_eq!(
            value["secret"].as_str(),
            Some(""),
            "the secret was not zeroed"
        );
    }

    /// The strings nested in tables and arrays are wiped too: a seed does not
    /// stop being a seed because it sits one level down.
    #[test]
    fn a_wiped_tree_wipes_what_is_nested_in_it() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [auth.clients.one]
            secret = "ONESEED"

            [[routes]]
            hosts = ["SECOND"]
            "#,
        )
        .expect("parses");
        zeroize_value(&mut value);

        assert_eq!(
            value["auth"]["clients"]["one"]["secret"].as_str(),
            Some(""),
            "the seed was not zeroed"
        );
        assert_eq!(
            value["routes"][0]["hosts"][0].as_str(),
            Some(""),
            "the nested string was not zeroed"
        );
    }

    /// A section taken out of the tree is not in the tree any more.
    ///
    /// It leaves by value, so the tree holds no second copy of it: a clone
    /// would be one more copy of the seeds in the heap. The section the caller
    /// gets is its own to zero.
    ///
    /// The wipe of the tree itself is a property of the guard rather than
    /// something this test can watch: `Drop` runs when the tree goes out of
    /// scope, and there is no way to look at a value after that.
    #[test]
    fn a_section_taken_out_of_the_tree_is_not_in_the_tree() {
        let mut tree = ZeroizedValue::new(toml::from_str("secret = \"ABC123\"").expect("parses"));
        let mut section = tree
            .table_mut()
            .and_then(|table| table.remove("secret"))
            .expect("the secret is there");
        // The section is taken out by value, so the tree no longer holds it.
        assert!(
            tree.table_mut().is_some_and(|table| table.is_empty()),
            "the tree still holds the secret"
        );
        assert_eq!(section.as_str(), Some("ABC123"));

        // The caller owns what it took out, and wipes it like the tree does.
        zeroize_value(&mut section);
        assert_eq!(section.as_str(), Some(""));
    }

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
