//! Diff engine -- Rust port of diff.c
//!
//! Compares two streams of LDAP entries and generates modification operations.

use std::io::{Read, Seek};

use crate::data::{Entry, LdapMod, ModOp, ModifyRecord, RenameRecord};
use crate::error::Result;
use crate::parse::LdapviParser;
use crate::parseldif::LdifParser;

// ===========================================================================
// Traits
// ===========================================================================

/// Trait for reading LDAP entries from a stream.
/// Implemented by both LdifParser and LdapviParser.
pub trait EntryParser {
    fn read_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, Entry, u64)>>;
    fn peek_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, u64)>>;
    fn skip_entry(&mut self, offset: Option<u64>) -> Result<Option<String>>;
    fn read_rename(&mut self, offset: Option<u64>) -> Result<RenameRecord>;
    fn read_delete(&mut self, offset: Option<u64>) -> Result<String>;
    fn read_modify(&mut self, offset: Option<u64>) -> Result<ModifyRecord>;
    fn parser_tell(&mut self) -> Result<u64>;
    fn parser_seek(&mut self, pos: u64) -> Result<()>;
    fn parser_read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

/// Handler trait for processing diff operations.
/// Methods return 0 on success, -1 on failure.
pub trait DiffHandler {
    fn handle_add(&mut self, n: i32, dn: &str, mods: &[LdapMod]) -> i32;
    fn handle_delete(&mut self, n: i32, dn: &str) -> i32;
    fn handle_change(&mut self, n: i32, old_dn: &str, new_dn: &str, mods: &[LdapMod]) -> i32;
    fn handle_rename(&mut self, n: i32, old_dn: &str, entry: &Entry) -> i32;
    fn handle_rename0(&mut self, n: i32, old_dn: &str, new_dn: &str, deleteoldrdn: bool) -> i32;
}

// ===========================================================================
// EntryParser implementations
// ===========================================================================

impl<R: Read + Seek> EntryParser for LdifParser<R> {
    fn read_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, Entry, u64)>> {
        LdifParser::read_entry(self, offset)
    }
    fn peek_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, u64)>> {
        LdifParser::peek_entry(self, offset)
    }
    fn skip_entry(&mut self, offset: Option<u64>) -> Result<Option<String>> {
        LdifParser::skip_entry(self, offset)
    }
    fn read_rename(&mut self, offset: Option<u64>) -> Result<RenameRecord> {
        LdifParser::read_rename(self, offset)
    }
    fn read_delete(&mut self, offset: Option<u64>) -> Result<String> {
        LdifParser::read_delete(self, offset)
    }
    fn read_modify(&mut self, offset: Option<u64>) -> Result<ModifyRecord> {
        LdifParser::read_modify(self, offset)
    }
    fn parser_tell(&mut self) -> Result<u64> {
        self.stream_position()
    }
    fn parser_seek(&mut self, pos: u64) -> Result<()> {
        self.seek_to(pos)
    }
    fn parser_read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_raw(buf)
    }
}

impl<R: Read + Seek> EntryParser for LdapviParser<R> {
    fn read_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, Entry, u64)>> {
        LdapviParser::read_entry(self, offset)
    }
    fn peek_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, u64)>> {
        LdapviParser::peek_entry(self, offset)
    }
    fn skip_entry(&mut self, offset: Option<u64>) -> Result<Option<String>> {
        LdapviParser::skip_entry(self, offset)
    }
    fn read_rename(&mut self, offset: Option<u64>) -> Result<RenameRecord> {
        LdapviParser::read_rename(self, offset)
    }
    fn read_delete(&mut self, offset: Option<u64>) -> Result<String> {
        LdapviParser::read_delete(self, offset)
    }
    fn read_modify(&mut self, offset: Option<u64>) -> Result<ModifyRecord> {
        LdapviParser::read_modify(self, offset)
    }
    fn parser_tell(&mut self) -> Result<u64> {
        self.stream_position()
    }
    fn parser_seek(&mut self, pos: u64) -> Result<()> {
        self.seek_to(pos)
    }
    fn parser_read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_raw(buf)
    }
}

// ===========================================================================
// FrobMode -- for frob_ava / frob_rdn
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrobMode {
    /// Check if value IS present (0 if yes, -1 if no).
    Check,
    /// Check if value is NOT present (0 if absent, -1 if present).
    CheckNone,
    /// Remove the value.
    Remove,
    /// Add the value (if not already present).
    Add,
}

// ===========================================================================
// Utility functions
// ===========================================================================

/// Invert an offset to mark it as "seen" (self-inverse: −2 − x).
pub fn long_array_invert(offsets: &mut [i64], i: usize) {
    offsets[i] = -2 - offsets[i];
}

/// Compare N bytes from stream S at position P and stream T at position Q.
///
/// This is a performance optimization in the diff loop: before fully parsing
/// two entries, we first do a raw byte comparison to quickly skip entries
/// that are unchanged.
///
/// Returns 0 if the segments are equal, 1 if different, -1 if either
/// stream terminates early.  Restores both streams to their original
/// positions regardless of outcome.
pub fn fastcmp(s: &mut dyn EntryParser, t: &mut dyn EntryParser, p: u64, q: u64, n: usize) -> i32 {
    let p_save = match s.parser_tell() {
        Ok(pos) => pos,
        Err(_) => return -1,
    };
    let q_save = match t.parser_tell() {
        Ok(pos) => pos,
        Err(_) => return -1,
    };

    let result = (|| -> i32 {
        if s.parser_seek(p).is_err() {
            return -1;
        }
        if t.parser_seek(q).is_err() {
            return -1;
        }

        let mut buf_s = vec![0u8; n];
        let mut buf_t = vec![0u8; n];

        let ns = read_exact_raw(s, &mut buf_s);
        let nt = read_exact_raw(t, &mut buf_t);

        if ns != n || nt != n {
            return -1;
        }
        if buf_s == buf_t {
            0
        } else {
            1
        }
    })();

    let _ = s.parser_seek(p_save);
    let _ = t.parser_seek(q_save);
    result
}

/// Read exactly `len` bytes from a parser, returning number of bytes read.
fn read_exact_raw(p: &mut dyn EntryParser, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        match p.parser_read_raw(&mut buf[filled..]) {
            Ok(0) => return filled,
            Ok(n) => filled += n,
            Err(_) => return filled,
        }
    }
    filled
}

// ---------------------------------------------------------------------------
// RDN parsing helpers
// ---------------------------------------------------------------------------

/// Extract the first RDN from a DN.
fn first_rdn(dn: &str) -> &str {
    let bytes = dn.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else if bytes[i] == b',' {
            return &dn[..i];
        } else {
            i += 1;
        }
    }
    dn
}

/// Parse an RDN into its AVA (attribute-value assertion) components.
/// "cn=test+sn=foo" → [("cn", "test"), ("sn", "foo")]
fn parse_rdn_avas(rdn: &str) -> Vec<(String, Vec<u8>)> {
    let mut avas = Vec::new();
    let bytes = rdn.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else if bytes[i] == b'+' {
            push_ava(&rdn[start..i], &mut avas);
            start = i + 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    push_ava(&rdn[start..], &mut avas);
    avas
}

fn push_ava(s: &str, avas: &mut Vec<(String, Vec<u8>)>) {
    if let Some(eq_pos) = s.find('=') {
        let ad = s[..eq_pos].trim();
        let value = &s[eq_pos + 1..];
        avas.push((ad.to_string(), value.as_bytes().to_vec()));
    }
}

// ---------------------------------------------------------------------------
// frob_ava / frob_rdn / validate_rename
// ---------------------------------------------------------------------------

/// Manipulate an entry's attribute AD with value DATA according to `mode`:
///
///  - `Check`:     return 0 if the value IS present, -1 if not.
///  - `CheckNone`: return 0 if the value is NOT present, -1 if it is.
///  - `Remove`:    remove the value (always returns 0).
///  - `Add`:       add the value unless already present (always returns 0).
pub fn frob_ava(entry: &mut Entry, mode: FrobMode, ad: &str, data: &[u8]) -> i32 {
    match mode {
        FrobMode::Check => match entry.get_attribute(ad) {
            None => -1,
            Some(a) => {
                if a.find_value(data).is_some() {
                    0
                } else {
                    -1
                }
            }
        },
        FrobMode::CheckNone => match entry.get_attribute(ad) {
            None => 0,
            Some(a) => {
                if a.find_value(data).is_some() {
                    -1
                } else {
                    0
                }
            }
        },
        FrobMode::Remove => {
            if let Some(a) = entry.find_attribute(ad, false) {
                a.remove_value(data);
            }
            0
        }
        FrobMode::Add => {
            let a = entry.find_attribute(ad, true).unwrap();
            if a.find_value(data).is_none() {
                a.append_value(data);
            }
            0
        }
    }
}

/// Call frob_ava for every AVA in DN's first RDN.
/// Returns -1 if frob_ava ever does so, 0 otherwise.
pub fn frob_rdn(entry: &mut Entry, dn: &str, mode: FrobMode) -> i32 {
    let rdn = first_rdn(dn);
    let avas = parse_rdn_avas(rdn);
    for (ad, value) in &avas {
        if frob_ava(entry, mode, ad, value) == -1 {
            return -1;
        }
    }
    0
}

/// Validate a rename by checking all of the following conditions:
///   - Neither DN is empty, so RDN-frobbing code can rely on valid DNs.
///   - The attribute values in clean's RDN are contained in clean.
///   - The attribute values in data's RDN are contained in data.
///   - The attribute values in clean's RDN are either ALL contained in
///     data or NONE of them are (determines `deleteoldrdn`).
///
/// On success, sets `deleteoldrdn` and returns 0.
/// On failure returns -1.
pub fn validate_rename(clean: &mut Entry, data: &mut Entry, deleteoldrdn: &mut bool) -> i32 {
    if clean.dn.is_empty() {
        return -1;
    }
    if data.dn.is_empty() {
        return -1;
    }
    let clean_dn = clean.dn.clone();
    let data_dn = data.dn.clone();
    if frob_rdn(clean, &clean_dn, FrobMode::Check) == -1 {
        return -1;
    }
    if frob_rdn(data, &data_dn, FrobMode::Check) == -1 {
        return -1;
    }
    // Check if old RDN values are still in data
    if frob_rdn(data, &clean_dn, FrobMode::Check) != -1 {
        *deleteoldrdn = false;
        return 0;
    }
    if frob_rdn(data, &clean_dn, FrobMode::CheckNone) != -1 {
        *deleteoldrdn = true;
        return 0;
    }
    -1
}

/// Modify a clean entry to reflect a rename.
fn rename_entry(entry: &mut Entry, new_dn: &str, deleteoldrdn: bool) {
    let old_dn = entry.dn.clone();
    if deleteoldrdn {
        frob_rdn(entry, &old_dn, FrobMode::Remove);
    }
    frob_rdn(entry, new_dn, FrobMode::Add);
    entry.dn = new_dn.to_string();
}

// ===========================================================================
// Entry comparison
// ===========================================================================

/// Compare two entries and return the modifications needed to transform
/// `clean` into `data`. Returns empty vec if entries are identical.
fn compare_entries(clean: &Entry, data: &Entry) -> Vec<LdapMod> {
    let mut clean_attrs: Vec<&crate::data::Attribute> = clean.attributes.iter().collect();
    let mut data_attrs: Vec<&crate::data::Attribute> = data.attributes.iter().collect();
    clean_attrs.sort_by(|a, b| a.ad.cmp(&b.ad));
    data_attrs.sort_by(|a, b| a.ad.cmp(&b.ad));

    let mut mods = Vec::new();
    let mut i = 0;
    let mut j = 0;

    while i < clean_attrs.len() && j < data_attrs.len() {
        match clean_attrs[i].ad.cmp(&data_attrs[j].ad) {
            std::cmp::Ordering::Less => {
                // In clean only → DELETE
                mods.push(LdapMod {
                    op: ModOp::Delete,
                    attr: clean_attrs[i].ad.clone(),
                    values: clean_attrs[i].values.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Equal => {
                // In both → compare values
                if clean_attrs[i].values != data_attrs[j].values {
                    mods.push(LdapMod {
                        op: ModOp::Replace,
                        attr: data_attrs[j].ad.clone(),
                        values: data_attrs[j].values.clone(),
                    });
                }
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Greater => {
                // In data only → ADD
                mods.push(LdapMod {
                    op: ModOp::Add,
                    attr: data_attrs[j].ad.clone(),
                    values: data_attrs[j].values.clone(),
                });
                j += 1;
            }
        }
    }
    while i < clean_attrs.len() {
        mods.push(LdapMod {
            op: ModOp::Delete,
            attr: clean_attrs[i].ad.clone(),
            values: clean_attrs[i].values.clone(),
        });
        i += 1;
    }
    while j < data_attrs.len() {
        mods.push(LdapMod {
            op: ModOp::Add,
            attr: data_attrs[j].ad.clone(),
            values: data_attrs[j].values.clone(),
        });
        j += 1;
    }
    mods
}

/// Convert entry attributes to LdapMods with Add op.
fn entry_to_add_mods(entry: &Entry) -> Vec<LdapMod> {
    entry
        .attributes
        .iter()
        .map(|a| LdapMod {
            op: ModOp::Add,
            attr: a.ad.clone(),
            values: a.values.clone(),
        })
        .collect()
}

/// Convert entry attributes to LdapMods with Replace op.
fn entry_to_replace_mods(entry: &Entry) -> Vec<LdapMod> {
    entry
        .attributes
        .iter()
        .map(|a| LdapMod {
            op: ModOp::Replace,
            attr: a.ad.clone(),
            values: a.values.clone(),
        })
        .collect()
}

// ===========================================================================
// Core diff functions
// ===========================================================================

/// Handle a changerecord of type `key` from `data_parser` at `datapos`.
/// Returns 0 on success, -1 on syntax error, -2 on handler error.
pub fn process_immediate(
    data_parser: &mut dyn EntryParser,
    handler: &mut dyn DiffHandler,
    datapos: u64,
    key: &str,
) -> i32 {
    match key {
        "add" => {
            let entry = match data_parser.read_entry(Some(datapos)) {
                Ok(Some((_, e, _))) => e,
                _ => return -1,
            };
            let mods = entry_to_add_mods(&entry);
            if handler.handle_add(-1, &entry.dn, &mods) == -1 {
                return -2;
            }
        }
        "replace" => {
            let entry = match data_parser.read_entry(Some(datapos)) {
                Ok(Some((_, e, _))) => e,
                _ => return -1,
            };
            let mods = entry_to_replace_mods(&entry);
            let dn = entry.dn.clone();
            if handler.handle_change(-1, &dn, &dn, &mods) == -1 {
                return -2;
            }
        }
        "rename" => {
            let rr = match data_parser.read_rename(Some(datapos)) {
                Ok(rr) => rr,
                Err(_) => return -1,
            };
            let rc = handler.handle_rename0(-1, &rr.old_dn, &rr.new_dn, rr.delete_old_rdn);
            if rc != 0 {
                return -2;
            }
        }
        "delete" => {
            let dn = match data_parser.read_delete(Some(datapos)) {
                Ok(dn) => dn,
                Err(_) => return -1,
            };
            let rc = handler.handle_delete(-1, &dn);
            if rc != 0 {
                return -2;
            }
        }
        "modify" => {
            let mr = match data_parser.read_modify(Some(datapos)) {
                Ok(mr) => mr,
                Err(_) => return -1,
            };
            if handler.handle_change(-1, &mr.dn, &mr.dn, &mr.mods) == -1 {
                return -2;
            }
        }
        _ => {
            eprintln!("Error: Invalid key: `{}'.", key);
            return -1;
        }
    }
    0
}

/// Process the next data entry: compare with clean copy or dispatch changerecord.
/// Returns 0 on success, -1 on syntax error, -2 on handler error.
fn process_next_entry(
    clean_parser: &mut dyn EntryParser,
    data_parser: &mut dyn EntryParser,
    handler: &mut dyn DiffHandler,
    offsets: &mut [i64],
    key: &str,
    datapos: u64,
) -> i32 {
    // Try to parse key as number
    let n: usize = match key.parse() {
        Ok(n) => n,
        Err(_) => {
            return process_immediate(data_parser, handler, datapos, key);
        }
    };

    // Validate key range
    if n >= offsets.len() {
        eprintln!("Error: Invalid key: `{}'.", key);
        return -1;
    }
    let pos = offsets[n];
    if pos < 0 {
        eprintln!("Error: Duplicate entry {}.", n);
        return -1;
    }

    // Find precise position of clean entry
    let clean_entry_pos = match clean_parser.read_entry(Some(pos as u64)) {
        Ok(Some((_, _, p))) => p,
        _ => panic!("Failed to read clean entry at offset {}", pos),
    };
    // Seek clean back so we can re-read
    let _ = clean_parser.parser_seek(pos as u64);

    // Fast comparison optimization
    if n + 1 < offsets.len() {
        let next = offsets[n + 1];
        if next >= 0 {
            let len = (next - clean_entry_pos as i64 + 1) as usize;
            if fastcmp(clean_parser, data_parser, clean_entry_pos, datapos, len) == 0 {
                let advance = (next - clean_entry_pos as i64) as u64;
                let new_datapos = datapos + advance;
                long_array_invert(offsets, n);
                let _ = data_parser.parser_seek(new_datapos);
                return 0;
            }
        }
    }

    // Read both entries
    let entry = match data_parser.read_entry(Some(datapos)) {
        Ok(Some((_, e, _))) => e,
        Ok(None) => return -1,
        Err(_) => return -1,
    };
    let mut cleanentry = match clean_parser.read_entry(Some(pos as u64)) {
        Ok(Some((_, e, _))) => e,
        _ => panic!("Failed to re-read clean entry"),
    };

    // Compare and update
    let is_rename = cleanentry.dn != entry.dn;
    if is_rename {
        let mut deleteoldrdn = false;
        if validate_rename(&mut cleanentry, &mut entry.clone(), &mut deleteoldrdn) != 0 {
            return -1;
        }
        if handler.handle_rename(n as i32, &cleanentry.dn, &entry) == -1 {
            return -2;
        }
        rename_entry(&mut cleanentry, &entry.dn, deleteoldrdn);
    }

    let mods = compare_entries(&cleanentry, &entry);
    if !mods.is_empty() {
        if handler.handle_change(n as i32, &cleanentry.dn, &entry.dn, &mods) == -1 {
            return -2;
        }
    }

    // Mark as seen
    long_array_invert(offsets, n);
    0
}

/// Process deletions: handle entries in clean that are not in data.
/// Returns 0 on success, -2 on handler error.
fn process_deletions(
    clean_parser: &mut dyn EntryParser,
    handler: &mut dyn DiffHandler,
    offsets: &mut [i64],
) -> i32 {
    for n in 0..offsets.len() {
        let pos = offsets[n];
        if pos < 0 {
            continue; // already seen
        }
        let cleanentry = match clean_parser.read_entry(Some(pos as u64)) {
            Ok(Some((_, e, _))) => e,
            _ => panic!("Failed to read clean entry for deletion"),
        };
        match handler.handle_delete(n as i32, &cleanentry.dn) {
            -1 => return -2,
            _ => {
                long_array_invert(offsets, n);
            }
        }
    }
    0
}

/// The compare_streams loop is the heart of ldapvi.
///
/// Read two ldapvi data files in streams CLEAN and DATA and compare them.
///
/// File CLEAN must contain numbered entries with consecutive keys starting at
/// zero.  For each of these entries, `offsets` must contain a position
/// in the file, such that the entry can be read by seeking to that position
/// and calling read_entry().
///
/// File DATA, a modified copy of CLEAN, may contain entries in any order,
/// which must be numbered or labeled "add", "rename", "delete", or "modify".
/// If a key is a number, the corresponding entry in CLEAN must exist; it is
/// read and compared to the modified copy.
///
/// For each new entry (labeled with "add"), call
///   handler.handle_add(dn, mods)
///
/// For each entry present in CLEAN but not DATA, call
///   handler.handle_delete(dn)
/// (This step can be repeated in the case of non-leaf entries.)
///
/// For each entry present in both files where the DNs disagree, call
///   handler.handle_rename(old_dn, entry)
/// If there are additional attribute changes after accounting for the
/// RDN change, also call
///   handler.handle_change(renamed_entry, new_entry, mods)
/// where the renamed entry accounts for attribute modifications due to
/// the RDN change (new RDN values added, old ones removed).
///
/// Returns 0 on success, -1 on parse error, -2 on handler error.
///
/// After successful completion, offsets are restored to their original values.
/// On handler error, offsets are left in their inverted state for error
/// recovery (identifying which entries have already been processed).
pub fn compare_streams(
    clean_parser: &mut dyn EntryParser,
    data_parser: &mut dyn EntryParser,
    handler: &mut dyn DiffHandler,
    offsets: &mut [i64],
) -> i32 {
    let mut rc = 0i32;

    loop {
        let peek = match data_parser.peek_entry(None) {
            Ok(Some((key, datapos))) => Some((key, datapos)),
            Ok(None) => None,
            Err(_) => {
                rc = -1;
                break;
            }
        };

        let (key, datapos) = match peek {
            Some(kd) => kd,
            None => break,
        };

        rc = process_next_entry(clean_parser, data_parser, handler, offsets, &key, datapos);
        if rc != 0 {
            break;
        }
    }

    if rc == 0 {
        rc = process_deletions(clean_parser, handler, offsets);
    }

    // On handler error, keep state for recovery
    if rc == -2 {
        return rc;
    }

    // Unmark offsets (restore inverted ones)
    for n in 0..offsets.len() {
        if offsets[n] < 0 {
            long_array_invert(offsets, n);
        }
    }
    rc
}

// ===========================================================================
// Tests -- ported from test_diff.c (44 tests)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // -- Mock handler infrastructure --

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CallType {
        Change,
        Rename,
        Add,
        Delete,
        Rename0,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct MockCall {
        call_type: CallType,
        n: i32,
        dn: String,
        dn2: Option<String>,
        deleteoldrdn: bool,
        num_mods: usize,
    }

    struct MockHandler {
        calls: Vec<MockCall>,
        fail_on_call: i32, // -1 = never fail
    }

    impl MockHandler {
        fn new() -> Self {
            MockHandler {
                calls: Vec::new(),
                fail_on_call: -1,
            }
        }
    }

    impl DiffHandler for MockHandler {
        fn handle_add(&mut self, n: i32, dn: &str, mods: &[LdapMod]) -> i32 {
            let idx = self.calls.len() as i32;
            self.calls.push(MockCall {
                call_type: CallType::Add,
                n,
                dn: dn.to_string(),
                dn2: None,
                deleteoldrdn: false,
                num_mods: mods.len(),
            });
            if idx == self.fail_on_call {
                -1
            } else {
                0
            }
        }

        fn handle_delete(&mut self, n: i32, dn: &str) -> i32 {
            let idx = self.calls.len() as i32;
            self.calls.push(MockCall {
                call_type: CallType::Delete,
                n,
                dn: dn.to_string(),
                dn2: None,
                deleteoldrdn: false,
                num_mods: 0,
            });
            if idx == self.fail_on_call {
                -1
            } else {
                0
            }
        }

        fn handle_change(&mut self, n: i32, old_dn: &str, new_dn: &str, mods: &[LdapMod]) -> i32 {
            let idx = self.calls.len() as i32;
            self.calls.push(MockCall {
                call_type: CallType::Change,
                n,
                dn: old_dn.to_string(),
                dn2: Some(new_dn.to_string()),
                deleteoldrdn: false,
                num_mods: mods.len(),
            });
            if idx == self.fail_on_call {
                -1
            } else {
                0
            }
        }

        fn handle_rename(&mut self, n: i32, old_dn: &str, entry: &Entry) -> i32 {
            let idx = self.calls.len() as i32;
            self.calls.push(MockCall {
                call_type: CallType::Rename,
                n,
                dn: old_dn.to_string(),
                dn2: Some(entry.dn.clone()),
                deleteoldrdn: false,
                num_mods: 0,
            });
            if idx == self.fail_on_call {
                -1
            } else {
                0
            }
        }

        fn handle_rename0(
            &mut self,
            n: i32,
            old_dn: &str,
            new_dn: &str,
            deleteoldrdn: bool,
        ) -> i32 {
            let idx = self.calls.len() as i32;
            self.calls.push(MockCall {
                call_type: CallType::Rename0,
                n,
                dn: old_dn.to_string(),
                dn2: Some(new_dn.to_string()),
                deleteoldrdn,
                num_mods: 0,
            });
            if idx == self.fail_on_call {
                -1
            } else {
                0
            }
        }
    }

    // -- Test helpers --

    fn make_entry(dn: &str) -> Entry {
        Entry::new(dn.to_string())
    }

    fn add_attr_value(entry: &mut Entry, ad: &str, val: &str) {
        let attr = entry.find_attribute(ad, true).unwrap();
        attr.append_value(val.as_bytes());
    }

    /// Build a clean file and offsets array from LDIF string.
    fn make_clean_file(ldif: &str) -> (Vec<u8>, Vec<i64>) {
        let data = ldif.as_bytes().to_vec();
        let mut parser = LdifParser::new(Cursor::new(data.clone()));
        let mut offsets: Vec<i64> = Vec::new();

        loop {
            match parser.read_entry(None) {
                Ok(Some((key, _entry, pos))) => {
                    if let Ok(n) = key.parse::<usize>() {
                        while offsets.len() <= n {
                            offsets.push(0i64);
                        }
                        offsets[n] = pos as i64;
                    }
                }
                _ => break,
            }
        }

        (data, offsets)
    }

    // ── Group 1: long_array_invert ────────────────────────────────

    #[test]
    fn test_long_array_invert_basic() {
        let mut a = vec![100i64];
        long_array_invert(&mut a, 0);
        assert_eq!(a[0], -102);
    }

    #[test]
    fn test_long_array_invert_double() {
        let mut a = vec![42i64];
        long_array_invert(&mut a, 0);
        long_array_invert(&mut a, 0);
        assert_eq!(a[0], 42);
    }

    #[test]
    fn test_long_array_invert_zero() {
        let mut a = vec![0i64];
        long_array_invert(&mut a, 0);
        assert_eq!(a[0], -2);
    }

    // ── Group 2: fastcmp ──────────────────────────────────────────

    fn make_parser(data: &[u8]) -> LdifParser<Cursor<Vec<u8>>> {
        LdifParser::new(Cursor::new(data.to_vec()))
    }

    #[test]
    fn test_fastcmp_equal() {
        let mut s = make_parser(b"hello world");
        let mut t = make_parser(b"hello world");
        assert_eq!(fastcmp(&mut s, &mut t, 0, 0, 11), 0);
    }

    #[test]
    fn test_fastcmp_different() {
        let mut s = make_parser(b"hello world");
        let mut t = make_parser(b"hello earth");
        assert_eq!(fastcmp(&mut s, &mut t, 0, 0, 11), 1);
    }

    #[test]
    fn test_fastcmp_short_read() {
        let mut s = make_parser(b"hi");
        let mut t = make_parser(b"hello world");
        assert_eq!(fastcmp(&mut s, &mut t, 0, 0, 11), -1);
    }

    #[test]
    fn test_fastcmp_offset() {
        let mut s = make_parser(b"XXXXXhello");
        let mut t = make_parser(b"YYhello");
        assert_eq!(fastcmp(&mut s, &mut t, 5, 2, 5), 0);
    }

    #[test]
    fn test_fastcmp_restores_position() {
        let mut s = make_parser(b"hello world");
        let mut t = make_parser(b"hello world");
        s.parser_seek(3).unwrap();
        t.parser_seek(7).unwrap();
        fastcmp(&mut s, &mut t, 0, 0, 5);
        assert_eq!(s.parser_tell().unwrap(), 3);
        assert_eq!(t.parser_tell().unwrap(), 7);
    }

    // ── Group 3: frob_ava ─────────────────────────────────────────

    #[test]
    fn test_frob_ava_check_found() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "test");
        assert_eq!(frob_ava(&mut e, FrobMode::Check, "cn", b"test"), 0);
    }

    #[test]
    fn test_frob_ava_check_not_found() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "test");
        assert_eq!(frob_ava(&mut e, FrobMode::Check, "cn", b"other"), -1);
    }

    #[test]
    fn test_frob_ava_check_no_attr() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        assert_eq!(frob_ava(&mut e, FrobMode::Check, "cn", b"test"), -1);
    }

    #[test]
    fn test_frob_ava_check_none_absent() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "test");
        // CHECK_NONE: value is NOT absent (it's present) -> returns -1
        assert_eq!(frob_ava(&mut e, FrobMode::CheckNone, "cn", b"test"), -1);
    }

    #[test]
    fn test_frob_ava_check_none_present() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "test");
        // CHECK_NONE: value IS absent (different value) -> returns 0
        assert_eq!(frob_ava(&mut e, FrobMode::CheckNone, "cn", b"other"), 0);
    }

    #[test]
    fn test_frob_ava_add() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        frob_ava(&mut e, FrobMode::Add, "cn", b"test");
        let a = e.get_attribute("cn").unwrap();
        assert_eq!(a.find_value(b"test"), Some(0));
    }

    #[test]
    fn test_frob_ava_add_idempotent() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "test");
        frob_ava(&mut e, FrobMode::Add, "cn", b"test");
        let a = e.get_attribute("cn").unwrap();
        assert_eq!(a.values.len(), 1);
    }

    #[test]
    fn test_frob_ava_remove() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "test");
        frob_ava(&mut e, FrobMode::Remove, "cn", b"test");
        let a = e.get_attribute("cn").unwrap();
        assert_eq!(a.values.len(), 0);
    }

    // ── Group 4: frob_rdn ─────────────────────────────────────────

    #[test]
    fn test_frob_rdn_check_match() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "test");
        assert_eq!(
            frob_rdn(&mut e, "cn=test,dc=example,dc=com", FrobMode::Check),
            0
        );
    }

    #[test]
    fn test_frob_rdn_check_nomatch() {
        let mut e = make_entry("cn=test,dc=example,dc=com");
        add_attr_value(&mut e, "cn", "other");
        assert_eq!(
            frob_rdn(&mut e, "cn=test,dc=example,dc=com", FrobMode::Check),
            -1
        );
    }

    #[test]
    fn test_frob_rdn_add() {
        let mut e = make_entry("cn=new,dc=example,dc=com");
        frob_rdn(&mut e, "cn=new,dc=example,dc=com", FrobMode::Add);
        let a = e.get_attribute("cn").unwrap();
        assert_eq!(a.find_value(b"new"), Some(0));
    }

    // ── Group 5: validate_rename ──────────────────────────────────

    #[test]
    fn test_validate_rename_deleteoldrdn_1() {
        let mut clean = make_entry("cn=old,dc=example,dc=com");
        add_attr_value(&mut clean, "cn", "old");
        let mut data = make_entry("cn=new,dc=example,dc=com");
        add_attr_value(&mut data, "cn", "new");

        let mut deleteoldrdn = false;
        assert_eq!(validate_rename(&mut clean, &mut data, &mut deleteoldrdn), 0);
        assert!(deleteoldrdn);
    }

    #[test]
    fn test_validate_rename_deleteoldrdn_0() {
        let mut clean = make_entry("cn=old,dc=example,dc=com");
        add_attr_value(&mut clean, "cn", "old");
        let mut data = make_entry("cn=new,dc=example,dc=com");
        add_attr_value(&mut data, "cn", "new");
        add_attr_value(&mut data, "cn", "old");

        let mut deleteoldrdn = true;
        assert_eq!(validate_rename(&mut clean, &mut data, &mut deleteoldrdn), 0);
        assert!(!deleteoldrdn);
    }

    #[test]
    fn test_validate_rename_empty_clean_dn() {
        let mut clean = make_entry("");
        let mut data = make_entry("cn=new,dc=example,dc=com");
        add_attr_value(&mut data, "cn", "new");
        let mut deleteoldrdn = false;
        assert_eq!(
            validate_rename(&mut clean, &mut data, &mut deleteoldrdn),
            -1
        );
    }

    #[test]
    fn test_validate_rename_empty_data_dn() {
        let mut clean = make_entry("cn=old,dc=example,dc=com");
        add_attr_value(&mut clean, "cn", "old");
        let mut data = make_entry("");
        let mut deleteoldrdn = false;
        assert_eq!(
            validate_rename(&mut clean, &mut data, &mut deleteoldrdn),
            -1
        );
    }

    #[test]
    fn test_validate_rename_old_rdn_missing() {
        let mut clean = make_entry("cn=old,dc=example,dc=com");
        // no cn attr in clean
        let mut data = make_entry("cn=new,dc=example,dc=com");
        add_attr_value(&mut data, "cn", "new");
        let mut deleteoldrdn = false;
        assert_eq!(
            validate_rename(&mut clean, &mut data, &mut deleteoldrdn),
            -1
        );
    }

    // ── Group 6: compare_streams ──────────────────────────────────

    #[test]
    fn test_compare_streams_unchanged() {
        let ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                     ldapvi-key: 0\n\
                     cn: foo\n\
                     \n";

        let (clean_data, mut offsets) = make_clean_file(ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 0);
    }

    #[test]
    fn test_compare_streams_unchanged_multi() {
        let ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                     ldapvi-key: 0\n\
                     cn: foo\n\
                     \n\
                     \ndn: cn=bar,dc=example,dc=com\n\
                     ldapvi-key: 1\n\
                     cn: bar\n\
                     \n";

        let (clean_data, mut offsets) = make_clean_file(ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 0);
    }

    #[test]
    fn test_compare_streams_modify_attr() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           sn: old\n\
                           \n";
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          sn: new\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Change);
        assert_eq!(m.calls[0].dn, "cn=foo,dc=example,dc=com");
        assert!(m.calls[0].num_mods > 0);
    }

    #[test]
    fn test_compare_streams_add_attr() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           \n";
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          mail: foo@example.com\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Change);
    }

    #[test]
    fn test_compare_streams_remove_attr() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           sn: bar\n\
                           \n";
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Change);
    }

    #[test]
    fn test_compare_streams_delete_entry() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           \n";
        let data_ldif = "";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Delete);
        assert_eq!(m.calls[0].dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn test_compare_streams_delete_one_of_two() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           \n\
                           \ndn: cn=bar,dc=example,dc=com\n\
                           ldapvi-key: 1\n\
                           cn: bar\n\
                           \n";
        let data_ldif = "\ndn: cn=bar,dc=example,dc=com\n\
                          ldapvi-key: 1\n\
                          cn: bar\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        let found_delete = m
            .calls
            .iter()
            .any(|c| c.call_type == CallType::Delete && c.dn == "cn=foo,dc=example,dc=com");
        assert!(found_delete);
    }

    #[test]
    fn test_compare_streams_add_new_entry() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           \n";
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          \n\
                          \ndn: cn=new,dc=example,dc=com\n\
                          ldapvi-key: add\n\
                          cn: new\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        let found_add = m
            .calls
            .iter()
            .any(|c| c.call_type == CallType::Add && c.dn == "cn=new,dc=example,dc=com");
        assert!(found_add);
    }

    #[test]
    fn test_compare_streams_rename() {
        let clean_ldif = "\ndn: cn=old,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: old\n\
                           \n";
        let data_ldif = "\ndn: cn=new,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: new\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, 0);
        let found_rename = m
            .calls
            .iter()
            .any(|c| c.call_type == CallType::Rename && c.dn == "cn=old,dc=example,dc=com");
        assert!(found_rename);
    }

    #[test]
    fn test_compare_streams_offsets_restored() {
        let ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                     ldapvi-key: 0\n\
                     cn: foo\n\
                     \n";

        let (clean_data, mut offsets) = make_clean_file(ldif);
        let orig = offsets[0];
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(offsets[0], orig);
    }

    // ── Group 7: process_immediate ────────────────────────────────

    #[test]
    fn test_process_immediate_add() {
        let ldif = "\ndn: cn=new,dc=example,dc=com\n\
                     ldapvi-key: add\n\
                     cn: new\n\
                     \n";

        let mut parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let (_, datapos) = parser.peek_entry(None).unwrap().unwrap();
        let mut m = MockHandler::new();

        let rc = process_immediate(&mut parser, &mut m, datapos, "add");
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Add);
        assert_eq!(m.calls[0].dn, "cn=new,dc=example,dc=com");
    }

    #[test]
    fn test_process_immediate_delete() {
        let ldif = "\ndn: cn=old,dc=example,dc=com\n\
                     changetype: delete\n\
                     \n";

        let mut parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let (_, datapos) = parser.peek_entry(None).unwrap().unwrap();
        let mut m = MockHandler::new();

        let rc = process_immediate(&mut parser, &mut m, datapos, "delete");
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Delete);
        assert_eq!(m.calls[0].dn, "cn=old,dc=example,dc=com");
    }

    #[test]
    fn test_process_immediate_modify() {
        let ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                     changetype: modify\n\
                     replace: sn\n\
                     sn: newval\n\
                     -\n\
                     \n";

        let mut parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let (_, datapos) = parser.peek_entry(None).unwrap().unwrap();
        let mut m = MockHandler::new();

        let rc = process_immediate(&mut parser, &mut m, datapos, "modify");
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Change);
    }

    #[test]
    fn test_process_immediate_invalid_key() {
        let ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                     ldapvi-key: bogus\n\
                     cn: foo\n\
                     \n";

        let mut parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let (_, datapos) = parser.peek_entry(None).unwrap().unwrap();
        let mut m = MockHandler::new();

        let rc = process_immediate(&mut parser, &mut m, datapos, "bogus");
        assert_eq!(rc, -1);
        assert_eq!(m.calls.len(), 0);
    }

    #[test]
    fn test_process_immediate_replace() {
        let ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                     ldapvi-key: replace\n\
                     cn: foo\n\
                     sn: bar\n\
                     \n";

        let mut parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let (_, datapos) = parser.peek_entry(None).unwrap().unwrap();
        let mut m = MockHandler::new();

        let rc = process_immediate(&mut parser, &mut m, datapos, "replace");
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Change);
    }

    #[test]
    fn test_process_immediate_rename() {
        let ldif = "\ndn: cn=old,dc=example,dc=com\n\
                     changetype: modrdn\n\
                     newrdn: cn=new\n\
                     deleteoldrdn: 1\n\
                     \n";

        let mut parser = LdifParser::new(Cursor::new(ldif.as_bytes().to_vec()));
        let (_, datapos) = parser.peek_entry(None).unwrap().unwrap();
        let mut m = MockHandler::new();

        let rc = process_immediate(&mut parser, &mut m, datapos, "rename");
        assert_eq!(rc, 0);
        assert_eq!(m.calls.len(), 1);
        assert_eq!(m.calls[0].call_type, CallType::Rename0);
    }

    // ── Group 8: handler failure ──────────────────────────────────

    #[test]
    fn test_compare_streams_handler_add_fails() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           \n";
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          \n\
                          \ndn: cn=new,dc=example,dc=com\n\
                          ldapvi-key: add\n\
                          cn: new\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();
        m.fail_on_call = 0;

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, -2);
    }

    #[test]
    fn test_compare_streams_handler_change_fails() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           sn: old\n\
                           \n";
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          sn: new\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();
        m.fail_on_call = 0;

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, -2);
    }

    // ── Group 9: error conditions ─────────────────────────────────

    #[test]
    fn test_compare_streams_invalid_numeric_key() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           \n";
        // data references key 5, which doesn't exist
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 5\n\
                          cn: foo\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, -1);
    }

    #[test]
    fn test_compare_streams_duplicate_key() {
        let clean_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                           ldapvi-key: 0\n\
                           cn: foo\n\
                           \n";
        // data uses key 0 twice
        let data_ldif = "\ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          \n\
                          \ndn: cn=foo,dc=example,dc=com\n\
                          ldapvi-key: 0\n\
                          cn: foo\n\
                          \n";

        let (clean_data, mut offsets) = make_clean_file(clean_ldif);
        let mut clean_parser = LdifParser::new(Cursor::new(clean_data));
        let mut data_parser = LdifParser::new(Cursor::new(data_ldif.as_bytes().to_vec()));
        let mut m = MockHandler::new();

        let rc = compare_streams(&mut clean_parser, &mut data_parser, &mut m, &mut offsets);
        assert_eq!(rc, -1);
    }
}
