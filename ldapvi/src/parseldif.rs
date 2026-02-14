//! LDIF parser -- Rust port of parseldif.c
//!
//! Reads RFC 2849 LDIF records (with ldapvi extensions) from any
//! `Read + Seek` source.

use std::io::{Read, Seek, SeekFrom};

use crate::base64::read_base64;
use crate::data::{Entry, LdapMod, ModOp, ModifyRecord, RenameRecord};
use crate::error::{LdapviError, Result};

// ---------------------------------------------------------------------------
// CharReader -- single-byte buffered reader with pushback
// ---------------------------------------------------------------------------

struct CharReader<R> {
    inner: R,
    pushback: Option<u8>,
}

impl<R: Read + Seek> CharReader<R> {
    fn new(inner: R) -> Self {
        CharReader {
            inner,
            pushback: None,
        }
    }

    /// Read one byte.  Returns `None` at EOF.
    fn getc(&mut self) -> Result<Option<u8>> {
        if let Some(c) = self.pushback.take() {
            return Ok(Some(c));
        }
        let mut buf = [0u8; 1];
        match self.inner.read(&mut buf) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(buf[0])),
            Err(e) => Err(LdapviError::Io(e)),
        }
    }

    /// Push one byte back (at most one outstanding).
    fn ungetc(&mut self, c: u8) {
        debug_assert!(self.pushback.is_none(), "double pushback");
        self.pushback = Some(c);
    }

    /// Current stream position (accounts for pushback).
    fn tell(&mut self) -> Result<u64> {
        let pos = self.inner.stream_position()?;
        if self.pushback.is_some() {
            Ok(pos - 1)
        } else {
            Ok(pos)
        }
    }

    fn seek(&mut self, pos: u64) -> Result<()> {
        self.pushback = None;
        self.inner.seek(SeekFrom::Start(pos))?;
        Ok(())
    }

    /// Read raw bytes from the underlying stream (clears pushback).
    fn read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.pushback = None;
        self.inner.read(buf)
    }

    /// True when the underlying stream is at EOF *and* no pushback byte.
    fn at_eof(&mut self) -> Result<bool> {
        if self.pushback.is_some() {
            return Ok(false);
        }
        let mut buf = [0u8; 1];
        match self.inner.read(&mut buf) {
            Ok(0) => Ok(true),
            Ok(_) => {
                self.pushback = Some(buf[0]);
                Ok(false)
            }
            Err(e) => Err(LdapviError::Io(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal line-reading result types
// ---------------------------------------------------------------------------

/// Result of `read_ad`.
enum AdResult {
    /// Attribute name read successfully (colon seen).
    Ok,
    /// The line was just "-".
    Dash,
}

/// Result of `read_line1`.
enum LineResult {
    /// Got an attribute-value pair (name and value populated).
    AttrValue,
    /// Empty line or EOF (name is empty).
    Empty,
    /// The line was "-".
    Dash,
}

// ---------------------------------------------------------------------------
// LdifParser
// ---------------------------------------------------------------------------

pub struct LdifParser<R> {
    cr: CharReader<R>,
}

impl<R: Read + Seek> LdifParser<R> {
    pub fn new(reader: R) -> Self {
        LdifParser {
            cr: CharReader::new(reader),
        }
    }

    // -- low-level helpers --------------------------------------------------

    fn parse_err(&self, msg: &str) -> LdapviError {
        LdapviError::Parse {
            position: 0,
            message: msg.to_string(),
        }
    }

    /// Read attribute descriptor up to (and including) the colon.
    /// On success the colon has been consumed and `lhs` contains the name.
    fn read_ad(&mut self, lhs: &mut String) -> Result<AdResult> {
        loop {
            match self.cr.getc()? {
                Some(b':') => return Ok(AdResult::Ok),
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(b'\r') => {
                    match self.cr.getc()? {
                        Some(b'\n') => {}
                        _ => return Err(self.parse_err("Unexpected EOL.")),
                    }
                    // fall through to newline handling
                    if !lhs.is_empty() {
                        match self.cr.getc()? {
                            Some(b' ') => continue, // folded line
                            Some(c) => {
                                self.cr.ungetc(c);
                                if lhs.len() == 1 && lhs.as_bytes()[0] == b'-' {
                                    return Ok(AdResult::Dash);
                                }
                            }
                            None => {
                                if lhs.len() == 1 && lhs.as_bytes()[0] == b'-' {
                                    return Ok(AdResult::Dash);
                                }
                            }
                        }
                    }
                    return Err(self.parse_err("Unexpected EOL."));
                }
                Some(b'\n') => {
                    if !lhs.is_empty() {
                        match self.cr.getc()? {
                            Some(b' ') => continue, // folded line
                            Some(c) => {
                                self.cr.ungetc(c);
                                if lhs.len() == 1 && lhs.as_bytes()[0] == b'-' {
                                    return Ok(AdResult::Dash);
                                }
                            }
                            None => {
                                if lhs.len() == 1 && lhs.as_bytes()[0] == b'-' {
                                    return Ok(AdResult::Dash);
                                }
                            }
                        }
                    }
                    return Err(self.parse_err("Unexpected EOL."));
                }
                Some(0) => return Err(self.parse_err("Null byte not allowed.")),
                Some(c) => lhs.push(c as char),
            }
        }
    }

    /// After the colon, determine the encoding marker.
    /// Returns: 0 = plain, b':' = base64, b'<' = URL, b'\n' = empty value.
    fn read_encoding(&mut self) -> Result<u8> {
        loop {
            match self.cr.getc()? {
                Some(b' ') => continue,
                Some(b':') => return Ok(b':'),
                Some(b'<') => return Ok(b'<'),
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(b'\r') => {
                    match self.cr.getc()? {
                        Some(b'\n') => {}
                        _ => return Err(self.parse_err("Unexpected EOL.")),
                    }
                    match self.cr.getc()? {
                        Some(b' ') => continue, // folded
                        Some(c) => {
                            self.cr.ungetc(c);
                            return Ok(b'\n');
                        }
                        None => return Ok(b'\n'),
                    }
                }
                Some(b'\n') => {
                    match self.cr.getc()? {
                        Some(b' ') => continue, // folded
                        Some(c) => {
                            self.cr.ungetc(c);
                            return Ok(b'\n');
                        }
                        None => return Ok(b'\n'),
                    }
                }
                Some(0) => return Err(self.parse_err("Null byte not allowed.")),
                Some(c) => {
                    self.cr.ungetc(c);
                    return Ok(0);
                }
            }
        }
    }

    /// Read a SAFE-STRING value (plain text until end of line, with folding).
    fn read_safe(&mut self, data: &mut Vec<u8>) -> Result<()> {
        loop {
            match self.cr.getc()? {
                Some(b'\r') => {
                    match self.cr.getc()? {
                        Some(b'\n') => {}
                        _ => return Err(self.parse_err("Unexpected EOL.")),
                    }
                    match self.cr.getc()? {
                        Some(b' ') => continue,
                        Some(c) => {
                            self.cr.ungetc(c);
                            return Ok(());
                        }
                        None => return Ok(()),
                    }
                }
                Some(b'\n') => match self.cr.getc()? {
                    Some(b' ') => continue,
                    Some(c) => {
                        self.cr.ungetc(c);
                        return Ok(());
                    }
                    None => return Ok(()),
                },
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(c) => data.push(c),
            }
        }
    }

    /// Skip a comment line (everything until EOL, with folding).
    fn skip_comment(&mut self) -> Result<()> {
        loop {
            match self.cr.getc()? {
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(b'\r') => {
                    match self.cr.getc()? {
                        Some(b'\n') => {}
                        _ => return Err(self.parse_err("Unexpected EOL.")),
                    }
                    match self.cr.getc()? {
                        Some(b' ') => continue,
                        Some(c) => {
                            self.cr.ungetc(c);
                            return Ok(());
                        }
                        None => return Ok(()),
                    }
                }
                Some(b'\n') => match self.cr.getc()? {
                    Some(b' ') => continue,
                    Some(c) => {
                        self.cr.ungetc(c);
                        return Ok(());
                    }
                    None => return Ok(()),
                },
                Some(_) => {}
            }
        }
    }

    /// Read one LDIF line.  Returns `LineResult::AttrValue` when a full
    /// attribute:value pair was read, `LineResult::Empty` at EOF or blank
    /// line, `LineResult::Dash` when the line is just "-".
    fn read_line1(&mut self, name: &mut String, value: &mut Vec<u8>) -> Result<LineResult> {
        name.clear();
        value.clear();

        // Skip comment lines at the start
        loop {
            match self.cr.getc()? {
                None => return Ok(LineResult::Empty), // EOF
                Some(b'\n') => return Ok(LineResult::Empty),
                Some(b'\r') => match self.cr.getc()? {
                    Some(b'\n') => return Ok(LineResult::Empty),
                    _ => return Err(self.parse_err("Unexpected EOL.")),
                },
                Some(b'#') => {
                    self.skip_comment()?;
                    continue;
                }
                Some(c) => {
                    self.cr.ungetc(c);
                    break;
                }
            }
        }

        // Read attribute descriptor
        match self.read_ad(name)? {
            AdResult::Dash => return Ok(LineResult::Dash),
            AdResult::Ok => {}
        }

        // Determine encoding
        let encoding = self.read_encoding()?;

        match encoding {
            0 => {
                // Plain value
                self.read_safe(value)?;
            }
            b'\n' => {
                // Empty value -- already consumed EOL
            }
            b':' => {
                // Base64
                self.read_safe(value)?;
                let s = String::from_utf8_lossy(value).to_string();
                match read_base64(&s) {
                    Some(decoded) => {
                        *value = decoded;
                    }
                    None => {
                        return Err(self.parse_err("Invalid Base64 string."));
                    }
                }
            }
            b'<' => {
                // URL
                self.read_safe(value)?;
                let url = String::from_utf8_lossy(value).to_string();
                if !url.starts_with("file://") {
                    return Err(self.parse_err("Unknown URL scheme."));
                }
                // File reading would go here; for now just error on non-file
                let path = &url[7..];
                let contents =
                    std::fs::read(path).map_err(|e| self.parse_err(&format!("open: {}", e)))?;
                *value = contents;
            }
            _ => unreachable!(),
        }

        Ok(LineResult::AttrValue)
    }

    /// Like `read_line1` but treats "-" as a parse error.
    fn read_line(&mut self, name: &mut String, value: &mut Vec<u8>) -> Result<LineResult> {
        match self.read_line1(name, value)? {
            LineResult::Dash => Err(self.parse_err("Unexpected EOL.")),
            other => Ok(other),
        }
    }

    /// Validate that a DN string is plausible (must contain '=').
    fn validate_dn(dn: &str) -> bool {
        dn.contains('=')
    }

    /// Read the first two lines of any record at position `offset`.
    ///
    /// Returns `(key, dn, pos)` where `pos` is the exact starting position,
    /// or `Ok(None)` at EOF.
    ///
    /// The key is derived from the second line:
    ///   - `"delete"` for `changetype: delete`
    ///   - `"modify"` for `changetype: modify`
    ///   - `"rename"` for `changetype: moddn` and `changetype: modrdn`
    ///   - `"add"`    for `changetype: add`
    ///   - the value of `ldapvi-key: ...` (must be the second line)
    ///   - `"add"` (implicit) if the second line is an ordinary attribute
    ///
    /// Note: unlike the ldapvi-format parser, LDIF peek must read TWO lines
    /// (dn + changetype/ldapvi-key) because the key comes from the second
    /// line, not the first.
    fn read_header(&mut self, offset: Option<u64>) -> Result<Option<(String, String, u64)>> {
        let mut name = String::new();
        let mut value_buf: Vec<u8> = Vec::new();

        if let Some(off) = offset {
            self.cr.seek(off)?;
        }

        let mut pos: u64;

        // Skip blank lines, version line
        loop {
            pos = self.cr.tell()?;
            match self.read_line(&mut name, &mut value_buf)? {
                LineResult::Empty => {
                    if self.cr.at_eof()? {
                        return Ok(None); // EOF
                    }
                    // blank line -- try again
                }
                LineResult::AttrValue => {
                    if name == "version" {
                        let val = String::from_utf8_lossy(&value_buf).to_string();
                        if val != "1" {
                            return Err(self.parse_err("Invalid file format."));
                        }
                        name.clear();
                        continue;
                    }
                    break; // got a real line
                }
                LineResult::Dash => unreachable!(), // read_line rejects dash
            }
        }

        // `name` should be "dn"
        let dn_str = String::from_utf8_lossy(&value_buf).to_string();
        if !Self::validate_dn(&dn_str) {
            return Err(self.parse_err("Invalid distinguished name string."));
        }
        let dn = dn_str;

        // Save position after dn line (before reading second line)
        let pos2 = self.cr.tell()?;

        // Read second line to determine key
        match self.read_line(&mut name, &mut value_buf)? {
            LineResult::AttrValue => {}
            LineResult::Empty => {
                // No second line -- implicit "add" with empty body
                // Seek back so attrval_body sees empty
                return Ok(Some(("add".to_string(), dn, pos)));
            }
            LineResult::Dash => unreachable!(),
        }

        let value_str = String::from_utf8_lossy(&value_buf).to_string();

        let key = if name == "ldapvi-key" {
            value_str
        } else if name == "changetype" {
            match value_str.as_str() {
                "modrdn" | "moddn" => "rename".to_string(),
                "delete" | "modify" | "add" => value_str,
                _ => {
                    return Err(self.parse_err("invalid changetype."));
                }
            }
        } else if name == "control" {
            return Err(self.parse_err("Sorry, 'control:' not supported."));
        } else {
            // Not a special second line -- implicit "add".
            // Seek back so the line is re-read by attrval_body.
            self.cr.seek(pos2)?;
            "add".to_string()
        };

        Ok(Some((key, dn, pos)))
    }

    /// Read the body of an attrval-record (attribute:value lines until blank/EOF).
    fn read_attrval_body(&mut self, entry: &mut Entry) -> Result<()> {
        let mut name = String::new();
        let mut value_buf: Vec<u8> = Vec::new();
        loop {
            match self.read_line(&mut name, &mut value_buf)? {
                LineResult::Empty => break,
                LineResult::AttrValue => {
                    let attr = entry.find_attribute(&name, true).unwrap();
                    attr.append_value(&value_buf);
                }
                LineResult::Dash => unreachable!(),
            }
        }
        Ok(())
    }

    /// Read a rename body: newrdn, deleteoldrdn, optional newsuperior.
    fn read_rename_body(&mut self, old_dn: &str) -> Result<(String, bool)> {
        let mut name = String::new();
        let mut value_buf: Vec<u8> = Vec::new();

        // Read newrdn
        match self.read_line(&mut name, &mut value_buf)? {
            LineResult::Empty | LineResult::Dash => {
                return Err(self.parse_err("Expected 'newrdn'."));
            }
            LineResult::AttrValue => {}
        }
        if name != "newrdn" {
            return Err(self.parse_err("Expected 'newrdn'."));
        }
        let newrdn = String::from_utf8_lossy(&value_buf).to_string();
        let newrdn_len = newrdn.len();

        // Read deleteoldrdn
        match self.read_line(&mut name, &mut value_buf)? {
            LineResult::Empty | LineResult::Dash => {
                return Err(self.parse_err("Expected 'deleteoldrdn'."));
            }
            LineResult::AttrValue => {}
        }
        if name != "deleteoldrdn" {
            return Err(self.parse_err("Expected 'deleteoldrdn'."));
        }
        let val = String::from_utf8_lossy(&value_buf).to_string();
        let delete_old_rdn = match val.as_str() {
            "0" => false,
            "1" => true,
            _ => {
                return Err(self.parse_err("Expected '0' or '1' for 'deleteoldrdn'."));
            }
        };

        // Read next line -- could be newsuperior or blank/EOF
        match self.read_line(&mut name, &mut value_buf)? {
            LineResult::Empty => {
                // No newsuperior.  Compute new DN from old.
                let comma = old_dn.find(',');
                match comma {
                    None => {
                        // Root entry -- just return newrdn
                        return Ok((newrdn, delete_old_rdn));
                    }
                    Some(idx) => {
                        let suffix = &old_dn[idx..];
                        let new_dn = format!("{}{}", newrdn, suffix);
                        return Ok((new_dn, delete_old_rdn));
                    }
                }
            }
            LineResult::AttrValue => {}
            LineResult::Dash => {
                return Err(self.parse_err("Unexpected EOL."));
            }
        }
        if name != "newsuperior" {
            return Err(self.parse_err("Garbage at end of moddn record."));
        }
        let newsuperior = String::from_utf8_lossy(&value_buf).to_string();
        if newsuperior.is_empty() {
            return Ok((newrdn, delete_old_rdn));
        }
        let new_dn = format!("{},{}", &newrdn[..newrdn_len], newsuperior);
        Ok((new_dn, delete_old_rdn))
    }

    /// Verify that the next line is empty (for delete records).
    fn read_nothing(&mut self) -> Result<()> {
        let mut name = String::new();
        let mut value_buf: Vec<u8> = Vec::new();
        match self.read_line(&mut name, &mut value_buf)? {
            LineResult::Empty => Ok(()),
            LineResult::AttrValue => Err(self.parse_err("Garbage at end of record.")),
            LineResult::Dash => unreachable!(),
        }
    }

    /// Parse an operation name ("add", "delete", "replace") into ModOp.
    fn parse_mod_op(action: &str) -> Result<ModOp> {
        match action {
            "add" => Ok(ModOp::Add),
            "delete" => Ok(ModOp::Delete),
            "replace" => Ok(ModOp::Replace),
            _ => Err(LdapviError::Parse {
                position: 0,
                message: "Invalid change marker.".to_string(),
            }),
        }
    }

    /// Read the body of a modify record.
    fn read_modify_body(&mut self) -> Result<Vec<LdapMod>> {
        let mut mods = Vec::new();
        let mut name = String::new();
        let mut value_buf: Vec<u8> = Vec::new();

        loop {
            // Read the operation line (e.g., "add: mail") or empty line
            match self.read_line(&mut name, &mut value_buf)? {
                LineResult::Empty => break,
                LineResult::AttrValue => {}
                LineResult::Dash => unreachable!(),
            }

            let op = Self::parse_mod_op(&name)?;
            let attr = String::from_utf8_lossy(&value_buf).to_string();

            let mut values: Vec<Vec<u8>> = Vec::new();

            // Read value lines until "-"
            loop {
                match self.read_line1(&mut name, &mut value_buf)? {
                    LineResult::AttrValue => {
                        if name != attr {
                            return Err(self.parse_err("Attribute name mismatch in change-modify."));
                        }
                        values.push(value_buf.clone());
                    }
                    LineResult::Dash => break,
                    LineResult::Empty => {
                        return Err(self.parse_err("Unexpected end of modify operation."));
                    }
                }
            }

            mods.push(LdapMod { op, attr, values });
        }

        Ok(mods)
    }

    // -- public API ---------------------------------------------------------

    /// Read a full attrval-record.  Returns `(key, entry, pos)`.
    /// `Ok(None)` at EOF.
    pub fn read_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, Entry, u64)>> {
        match self.read_header(offset)? {
            None => Ok(None),
            Some((key, dn, pos)) => {
                let mut entry = Entry::new(dn);
                self.read_attrval_body(&mut entry)?;
                Ok(Some((key, entry, pos)))
            }
        }
    }

    /// Peek at the next record's key without consuming the body.
    pub fn peek_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, u64)>> {
        match self.read_header(offset)? {
            None => Ok(None),
            Some((key, _dn, pos)) => Ok(Some((key, pos))),
        }
    }

    /// Skip an entry, returning its key.
    pub fn skip_entry(&mut self, offset: Option<u64>) -> Result<Option<String>> {
        match self.read_header(offset)? {
            None => Ok(None),
            Some((key, _dn, _pos)) => {
                let mut name = String::new();
                let mut value_buf: Vec<u8> = Vec::new();
                loop {
                    match self.read_line1(&mut name, &mut value_buf)? {
                        LineResult::Empty => break,
                        LineResult::AttrValue | LineResult::Dash => continue,
                    }
                }
                Ok(Some(key))
            }
        }
    }

    /// Read a rename (modrdn/moddn) record.
    pub fn read_rename(&mut self, offset: Option<u64>) -> Result<RenameRecord> {
        let (_key, dn, _pos) = self
            .read_header(offset)?
            .ok_or_else(|| self.parse_err("Unexpected EOF."))?;
        let (new_dn, delete_old_rdn) = self.read_rename_body(&dn)?;
        Ok(RenameRecord {
            old_dn: dn,
            new_dn,
            delete_old_rdn,
        })
    }

    /// Read a delete record.
    pub fn read_delete(&mut self, offset: Option<u64>) -> Result<String> {
        let (_key, dn, _pos) = self
            .read_header(offset)?
            .ok_or_else(|| self.parse_err("Unexpected EOF."))?;
        self.read_nothing()?;
        Ok(dn)
    }

    /// Read a modify record.
    pub fn read_modify(&mut self, offset: Option<u64>) -> Result<ModifyRecord> {
        let (_key, dn, _pos) = self
            .read_header(offset)?
            .ok_or_else(|| self.parse_err("Unexpected EOF."))?;
        let mods = self.read_modify_body()?;
        Ok(ModifyRecord { dn, mods })
    }

    /// Get current stream position.
    pub fn stream_position(&mut self) -> Result<u64> {
        self.cr.tell()
    }

    /// Seek to a position.
    pub fn seek_to(&mut self, pos: u64) -> Result<()> {
        self.cr.seek(pos)
    }

    /// Read raw bytes from the underlying stream (for fastcmp).
    pub fn read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cr.read_raw(buf)
    }
}

// ===========================================================================
// Tests -- direct port of all 63 tests from test_parseldif.c
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Attribute;
    use std::io::Cursor;

    fn p(data: &[u8]) -> LdifParser<Cursor<&[u8]>> {
        LdifParser::new(Cursor::new(data))
    }

    // Helper: find attribute by name
    fn find_attr<'a>(entry: &'a Entry, name: &str) -> Option<&'a Attribute> {
        entry.get_attribute(name)
    }

    // ── Group 1: EOF and empty input ────────────────────────────────────

    #[test]
    fn eof_returns_none() {
        let mut parser = p(b"");
        assert!(parser.read_entry(None).unwrap().is_none());
    }

    #[test]
    fn blank_lines_then_eof() {
        let mut parser = p(b"\n\n\n");
        assert!(parser.read_entry(None).unwrap().is_none());
    }

    #[test]
    fn peek_eof_returns_none() {
        let mut parser = p(b"");
        assert!(parser.peek_entry(None).unwrap().is_none());
    }

    #[test]
    fn skip_eof_returns_none() {
        let mut parser = p(b"");
        assert!(parser.skip_entry(None).unwrap().is_none());
    }

    // ── Group 2: Simple attrval-record (implicit "add") ─────────────────

    #[test]
    fn read_simple_entry() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              sn: bar\n\
              \n");
        let (key, entry, pos) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
        assert_eq!(entry.attributes.len(), 2);

        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values.len(), 1);
        assert_eq!(a.values[0].len(), 3);
        assert_eq!(&a.values[0], b"foo");

        let a = find_attr(&entry, "sn").unwrap();
        assert_eq!(&a.values[0], b"bar");

        assert_eq!(pos, 0);
    }

    #[test]
    fn read_entry_multi_valued_attribute() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              cn: bar\n\
              \n");
        let (key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");

        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values.len(), 2);
        assert_eq!(&a.values[0], b"foo");
        assert_eq!(&a.values[1], b"bar");
    }

    #[test]
    fn read_entry_empty_value() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              description:\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();

        let a = find_attr(&entry, "description").unwrap();
        assert_eq!(a.values.len(), 1);
        assert_eq!(a.values[0].len(), 0);
    }

    #[test]
    fn read_entry_at_offset() {
        let mut parser = p(b"XXXXX\
              dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              \n");
        let (key, _entry, pos) = parser.read_entry(Some(5)).unwrap().unwrap();
        assert_eq!(key, "add");
        assert_eq!(pos, 5);
    }

    #[test]
    fn read_entry_sequential() {
        let mut parser = p(b"dn: cn=a,dc=example,dc=com\n\
              cn: a\n\
              \n\
              dn: cn=b,dc=example,dc=com\n\
              cn: b\n\
              \n");
        let (_k1, e1, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(e1.dn, "cn=a,dc=example,dc=com");

        let (_k2, e2, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(e2.dn, "cn=b,dc=example,dc=com");
    }

    #[test]
    fn entry_eof_terminates_record() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n");
        let (key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        assert!(find_attr(&entry, "cn").is_some());
    }

    // ── Group 3: version line ───────────────────────────────────────────

    #[test]
    fn version_line_skipped() {
        let mut parser = p(b"version: 1\n\
              dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              \n");
        let (key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn invalid_version_number() {
        let mut parser = p(b"version: 2\n\
              dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }

    // ── Group 4: Comments ───────────────────────────────────────────────

    #[test]
    fn comment_lines_skipped() {
        let mut parser = p(b"# This is a comment\n\
              dn: cn=foo,dc=example,dc=com\n\
              # Another comment\n\
              cn: foo\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert!(find_attr(&entry, "cn").is_some());
    }

    #[test]
    fn comment_with_folding() {
        let mut parser = p(b"# This is a long\n \
              comment that folds\n\
              dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              \n");
        let (key, _entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
    }

    // ── Group 5: Line folding ───────────────────────────────────────────

    #[test]
    fn dn_line_folding() {
        let mut parser = p(b"dn: cn=foo,dc=exam\n \
              ple,dc=com\n\
              cn: foo\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn value_line_folding() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              description: hello\n \
              world\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();

        let a = find_attr(&entry, "description").unwrap();
        assert_eq!(a.values[0].len(), 10);
        assert_eq!(&a.values[0], b"helloworld");
    }

    #[test]
    fn attribute_name_folding() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              descr\n \
              iption: hello\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();

        let a = find_attr(&entry, "description").unwrap();
        assert_eq!(&a.values[0], b"hello");
    }

    // ── Group 6: Base64 encoding ────────────────────────────────────────

    #[test]
    fn base64_value() {
        // aGVsbG8= is base64 for "hello"
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn:: aGVsbG8=\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();

        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 5);
        assert_eq!(&a.values[0], b"hello");
    }

    #[test]
    fn base64_invalid() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn:: !!!invalid!!!\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn base64_dn() {
        // Y249Zm9vLGRjPWV4YW1wbGUsZGM9Y29t is base64 for
        // "cn=foo,dc=example,dc=com"
        let mut parser = p(b"dn:: Y249Zm9vLGRjPWV4YW1wbGUsZGM9Y29t\n\
              cn: foo\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
    }

    // ── Group 7: ldapvi-key extension ───────────────────────────────────

    #[test]
    fn ldapvi_key_custom() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              ldapvi-key: 42\n\
              cn: foo\n\
              \n");
        let (key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "42");

        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(&a.values[0], b"foo");
    }

    // ── Group 8: changetype: add ────────────────────────────────────────

    #[test]
    fn changetype_add() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: add\n\
              cn: foo\n\
              \n");
        let (key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        assert!(find_attr(&entry, "cn").is_some());
    }

    // ── Group 9: changetype: delete ─────────────────────────────────────

    #[test]
    fn read_delete_basic() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: delete\n\
              \n");
        let dn = parser.read_delete(None).unwrap();
        assert_eq!(dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn read_delete_garbage_after() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: delete\n\
              cn: foo\n\
              \n");
        assert!(parser.read_delete(None).is_err());
    }

    #[test]
    fn peek_delete() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: delete\n\
              \n");
        let (key, _pos) = parser.peek_entry(None).unwrap().unwrap();
        assert_eq!(key, "delete");
    }

    #[test]
    fn skip_delete() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: delete\n\
              \n");
        let key = parser.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "delete");
    }

    // ── Group 10: changetype: modify ────────────────────────────────────

    #[test]
    fn read_modify_add_operation() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              add: mail\n\
              mail: foo@example.com\n\
              -\n\
              \n");
        let rec = parser.read_modify(None).unwrap();
        assert_eq!(rec.dn, "cn=foo,dc=example,dc=com");
        assert_eq!(rec.mods.len(), 1);
        assert_eq!(rec.mods[0].op, ModOp::Add);
        assert_eq!(rec.mods[0].attr, "mail");
        assert_eq!(rec.mods[0].values.len(), 1);
        assert_eq!(rec.mods[0].values[0].len(), 15);
        assert_eq!(&rec.mods[0].values[0], b"foo@example.com");
    }

    #[test]
    fn read_modify_delete_operation() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              delete: mail\n\
              -\n\
              \n");
        let rec = parser.read_modify(None).unwrap();
        assert_eq!(rec.mods.len(), 1);
        assert_eq!(rec.mods[0].op, ModOp::Delete);
        assert_eq!(rec.mods[0].attr, "mail");
        assert_eq!(rec.mods[0].values.len(), 0);
    }

    #[test]
    fn read_modify_replace_operation() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              replace: mail\n\
              mail: new@example.com\n\
              -\n\
              \n");
        let rec = parser.read_modify(None).unwrap();
        assert_eq!(rec.mods.len(), 1);
        assert_eq!(rec.mods[0].op, ModOp::Replace);
        assert_eq!(&rec.mods[0].values[0], b"new@example.com");
    }

    #[test]
    fn read_modify_multiple_operations() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              add: mail\n\
              mail: a@example.com\n\
              -\n\
              delete: phone\n\
              -\n\
              replace: sn\n\
              sn: Smith\n\
              -\n\
              \n");
        let rec = parser.read_modify(None).unwrap();
        assert_eq!(rec.mods.len(), 3);
        assert_eq!(rec.mods[0].op, ModOp::Add);
        assert_eq!(rec.mods[0].attr, "mail");
        assert_eq!(rec.mods[1].op, ModOp::Delete);
        assert_eq!(rec.mods[1].attr, "phone");
        assert_eq!(rec.mods[2].op, ModOp::Replace);
        assert_eq!(rec.mods[2].attr, "sn");
    }

    #[test]
    fn read_modify_add_multiple_values() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              add: mail\n\
              mail: a@example.com\n\
              mail: b@example.com\n\
              -\n\
              \n");
        let rec = parser.read_modify(None).unwrap();
        assert_eq!(rec.mods[0].values.len(), 2);
        assert_eq!(&rec.mods[0].values[0], b"a@example.com");
        assert_eq!(&rec.mods[0].values[1], b"b@example.com");
    }

    #[test]
    fn read_modify_attribute_name_mismatch() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              add: mail\n\
              phone: 12345\n\
              -\n\
              \n");
        assert!(parser.read_modify(None).is_err());
    }

    #[test]
    fn read_modify_invalid_change_marker() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              frobnicate: mail\n\
              -\n\
              \n");
        assert!(parser.read_modify(None).is_err());
    }

    #[test]
    fn peek_modify() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              add: mail\n\
              mail: foo@example.com\n\
              -\n\
              \n");
        let (key, _pos) = parser.peek_entry(None).unwrap().unwrap();
        assert_eq!(key, "modify");
    }

    // ── Group 11: changetype: modrdn / moddn (rename) ──────────────────

    #[test]
    fn read_rename_modrdn() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 1\n\
              \n");
        let rec = parser.read_rename(None).unwrap();
        assert_eq!(rec.old_dn, "cn=old,dc=example,dc=com");
        assert_eq!(rec.new_dn, "cn=new,dc=example,dc=com");
        assert_eq!(rec.delete_old_rdn, true);
    }

    #[test]
    fn read_rename_moddn() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: moddn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 0\n\
              \n");
        let rec = parser.read_rename(None).unwrap();
        assert_eq!(rec.new_dn, "cn=new,dc=example,dc=com");
        assert_eq!(rec.delete_old_rdn, false);
    }

    #[test]
    fn read_rename_with_newsuperior() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 1\n\
              newsuperior: dc=other,dc=com\n\
              \n");
        let rec = parser.read_rename(None).unwrap();
        assert_eq!(rec.new_dn, "cn=new,dc=other,dc=com");
    }

    #[test]
    fn read_rename_with_empty_newsuperior() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 1\n\
              newsuperior:\n\
              \n");
        let rec = parser.read_rename(None).unwrap();
        assert_eq!(rec.new_dn, "cn=new");
    }

    #[test]
    fn read_rename_without_newsuperior() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=moved\n\
              deleteoldrdn: 0\n\
              \n");
        let rec = parser.read_rename(None).unwrap();
        assert_eq!(rec.new_dn, "cn=moved,dc=example,dc=com");
    }

    #[test]
    fn read_rename_invalid_deleteoldrdn() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 2\n\
              \n");
        assert!(parser.read_rename(None).is_err());
    }

    #[test]
    fn read_rename_missing_newrdn() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              deleteoldrdn: 1\n\
              \n");
        assert!(parser.read_rename(None).is_err());
    }

    #[test]
    fn read_rename_missing_deleteoldrdn() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=new\n\
              \n");
        assert!(parser.read_rename(None).is_err());
    }

    #[test]
    fn read_rename_garbage_after() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 1\n\
              garbage: value\n\
              \n");
        assert!(parser.read_rename(None).is_err());
    }

    #[test]
    fn peek_rename_modrdn() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: modrdn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 1\n\
              \n");
        let (key, _pos) = parser.peek_entry(None).unwrap().unwrap();
        assert_eq!(key, "rename");
    }

    #[test]
    fn peek_rename_moddn() {
        let mut parser = p(b"dn: cn=old,dc=example,dc=com\n\
              changetype: moddn\n\
              newrdn: cn=new\n\
              deleteoldrdn: 1\n\
              \n");
        let (key, _pos) = parser.peek_entry(None).unwrap().unwrap();
        assert_eq!(key, "rename");
    }

    #[test]
    fn rename_root_entry_no_comma() {
        let mut parser = p(b"dn: dc=com\n\
              changetype: modrdn\n\
              newrdn: dc=org\n\
              deleteoldrdn: 0\n\
              \n");
        let rec = parser.read_rename(None).unwrap();
        assert_eq!(rec.new_dn, "dc=org");
    }

    // ── Group 12: Error conditions ──────────────────────────────────────

    #[test]
    fn invalid_dn() {
        let mut parser = p(b"dn: invalid\n\
              cn: foo\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn invalid_changetype() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: bogus\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn control_line_not_supported() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              control: 1.2.3.4 true\n\
              changetype: add\n\
              cn: foo\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn null_byte_in_attr_name() {
        let data: &[u8] = b"dn: cn=foo,dc=example,dc=com\nc\x00n: foo\n\n";
        let mut parser = LdifParser::new(Cursor::new(data));
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn unexpected_eof_in_attr_name() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn");
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn unexpected_eol_in_attr_name() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn unexpected_eof_in_value() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn: foo");
        assert!(parser.read_entry(None).is_err());
    }

    #[test]
    fn dash_line_in_non_modify_context() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              -\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }

    // ── Group 13: skip_entry ────────────────────────────────────────────

    #[test]
    fn skip_simple_entry() {
        let mut parser = p(b"dn: cn=a,dc=example,dc=com\n\
              cn: a\n\
              \n\
              dn: cn=b,dc=example,dc=com\n\
              cn: b\n\
              \n");
        let key = parser.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");

        let (_key2, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.dn, "cn=b,dc=example,dc=com");
    }

    #[test]
    fn skip_modify_entry() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              changetype: modify\n\
              add: mail\n\
              mail: foo@example.com\n\
              -\n\
              \n");
        let key = parser.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "modify");
    }

    // ── Group 14: pos output parameter ──────────────────────────────────

    #[test]
    fn pos_set_correctly() {
        let mut parser = p(b"\n\
              dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              \n");
        let (_key, _entry, pos) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(pos, 1);
    }

    #[test]
    fn pos_with_version() {
        let mut parser = p(b"version: 1\n\
              dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              \n");
        let (_key, _entry, pos) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(pos, 11);
    }

    // ── Group 15: Edge cases ────────────────────────────────────────────

    #[test]
    fn multiple_different_attributes() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              sn: bar\n\
              mail: foo@bar.com\n\
              description: test\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.attributes.len(), 4);
        assert!(find_attr(&entry, "cn").is_some());
        assert!(find_attr(&entry, "sn").is_some());
        assert!(find_attr(&entry, "mail").is_some());
        assert!(find_attr(&entry, "description").is_some());
    }

    #[test]
    fn peek_does_not_consume_body() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn: foo\n\
              sn: bar\n\
              \n");
        let (key, pos) = parser.peek_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");

        let (_key2, entry, _) = parser.read_entry(Some(pos)).unwrap().unwrap();
        assert_eq!(entry.attributes.len(), 2);
        assert!(find_attr(&entry, "cn").is_some());
        assert!(find_attr(&entry, "sn").is_some());
    }

    #[test]
    fn extra_spaces_after_colon() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn:    foo\n\
              \n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();

        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 3);
        assert_eq!(&a.values[0], b"foo");
    }

    #[test]
    fn crlf_line_endings() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\r\n\
              cn: foo\r\n\
              \r\n");
        let (_key, entry, _) = parser.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn file_url_unknown_scheme() {
        let mut parser = p(b"dn: cn=foo,dc=example,dc=com\n\
              cn:< http://example.com/foo\n\
              \n");
        assert!(parser.read_entry(None).is_err());
    }
}
