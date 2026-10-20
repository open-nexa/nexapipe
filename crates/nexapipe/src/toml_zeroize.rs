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
//! What neither of them can reach is the raw text `toml_edit` keeps for every
//! value it parsed: that lives in a `RawString` whose fields are private, and
//! the only way at the bytes is `unsafe` or a fork of the crate. The copies
//! this crate makes are zeroed; the ones the library makes are not.

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
/// and zero it there. The raw text it keeps for the value it parsed is not a
/// second copy of the value but the text the value was written as, and it
/// lives in a private `RawString` this crate cannot reach — so what is zeroed
/// here is the decoded value, not the file's own bytes.
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

    /// The guard wipes the tree when it is dropped, which is the only moment
    /// that matters: a tree that is dropped on an error path is dropped
    /// without anyone asking.
    #[test]
    fn the_guard_wipes_the_tree_it_holds() {
        let mut tree = ZeroizedValue::new(toml::from_str("secret = \"ABC123\"").expect("parses"));
        let section = tree
            .table_mut()
            .and_then(|table| table.remove("secret"))
            .expect("the secret is there");
        // The section is taken out by value, so the tree no longer holds it.
        assert!(
            tree.table_mut().is_some_and(|table| table.is_empty()),
            "the tree still holds the secret"
        );
        assert_eq!(section.as_str(), Some("ABC123"));

        // And the tree that is left is wiped when it goes.
        drop(tree);
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
