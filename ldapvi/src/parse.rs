//! ldapvi native format parser -- Rust port of parse.c
//!
//! Reads records in ldapvi format from any `Read + Seek` source.
//! Format: `key dn\nattr value\n` with backslash escaping by default.

use std::io::{Read, Seek, SeekFrom};

use crate::base64;
use crate::data::{Entry, LdapMod, ModOp, ModifyRecord, RenameRecord};
use crate::error::{LdapviError, Result};
use crate::port;

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

    fn ungetc(&mut self, c: u8) {
        debug_assert!(self.pushback.is_none(), "double pushback");
        self.pushback = Some(c);
    }

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

    fn read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.pushback = None;
        self.inner.read(buf)
    }

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

    /// Read exactly `n` bytes into `buf`. Error if not enough bytes.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        if let Some(pb) = self.pushback.take() {
            if !buf.is_empty() {
                buf[0] = pb;
                offset = 1;
            }
        }
        self.inner
            .read_exact(&mut buf[offset..])
            .map_err(LdapviError::Io)
    }
}

// ---------------------------------------------------------------------------
// Internal line-reading result
// ---------------------------------------------------------------------------

/// Result of `read_line1`.
enum LineResult {
    /// Attribute-value line (name may be empty for modify value lines).
    Line(String, Vec<u8>),
    /// Empty line (record separator).
    BlankLine,
    /// End of file.
    Eof,
}

// ---------------------------------------------------------------------------
// Crypt support (Unix only)
// ---------------------------------------------------------------------------

const SALT_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890./";

fn random_salt_bytes(n: usize) -> Vec<u8> {
    let mut salt = vec![0u8; n];
    #[cfg(target_family = "unix")]
    {
        use std::io::Read as _;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut salt);
        }
    }
    salt
}

#[cfg(unix)]
fn crypt_des(key: &str) -> Result<String> {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    #[link(name = "crypt")]
    extern "C" {
        fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
    }

    let raw = random_salt_bytes(2);
    let salt = format!(
        "{}{}",
        SALT_CHARS[(raw[0] & 63) as usize] as char,
        SALT_CHARS[(raw[1] & 63) as usize] as char
    );

    let c_key = CString::new(key).map_err(|_| LdapviError::Other("invalid key".into()))?;
    let c_salt = CString::new(salt).map_err(|_| LdapviError::Other("invalid salt".into()))?;

    unsafe {
        let result = crypt(c_key.as_ptr(), c_salt.as_ptr());
        if result.is_null() {
            return Err(LdapviError::Other(
                "crypt not available: crypt() returned null".into(),
            ));
        }
        Ok(CStr::from_ptr(result).to_string_lossy().into_owned())
    }
}

#[cfg(not(unix))]
fn crypt_des(_key: &str) -> Result<String> {
    Err(LdapviError::Other(
        "crypt not available on this platform".into(),
    ))
}

#[cfg(unix)]
fn crypt_md5(key: &str) -> Result<String> {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    #[link(name = "crypt")]
    extern "C" {
        fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
    }

    let raw = random_salt_bytes(8);
    let mut salt = String::from("$1$");
    for &b in &raw {
        salt.push(SALT_CHARS[(b & 63) as usize] as char);
    }

    let c_key = CString::new(key).map_err(|_| LdapviError::Other("invalid key".into()))?;
    let c_salt = CString::new(salt).map_err(|_| LdapviError::Other("invalid salt".into()))?;

    unsafe {
        let result = crypt(c_key.as_ptr(), c_salt.as_ptr());
        if result.is_null() {
            return Err(LdapviError::Other("MD5 crypt returned null".into()));
        }
        let s = CStr::from_ptr(result).to_string_lossy().into_owned();
        if s.len() < 25 {
            return Err(LdapviError::Other(
                "MD5 crypt not available: result too short".into(),
            ));
        }
        Ok(s)
    }
}

#[cfg(not(unix))]
fn crypt_md5(_key: &str) -> Result<String> {
    Err(LdapviError::Other(
        "crypt not available on this platform".into(),
    ))
}

// ---------------------------------------------------------------------------
// LdapviParser
// ---------------------------------------------------------------------------

pub struct LdapviParser<R> {
    cr: CharReader<R>,
}

impl<R: Read + Seek> LdapviParser<R> {
    pub fn new(reader: R) -> Self {
        LdapviParser {
            cr: CharReader::new(reader),
        }
    }

    /// Current stream position.
    pub fn stream_position(&mut self) -> Result<u64> {
        self.cr.tell()
    }

    fn parse_err(&self, msg: &str) -> LdapviError {
        LdapviError::Parse {
            position: 0,
            message: msg.to_string(),
        }
    }

    // -- low-level readers --------------------------------------------------

    /// Read the left-hand side of a line (everything up to the first space).
    /// Space is consumed but not included in the result.
    fn read_lhs(&mut self) -> Result<String> {
        let mut lhs = String::new();
        loop {
            match self.cr.getc()? {
                Some(b' ') => return Ok(lhs),
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(b'\n') => return Err(self.parse_err("Unexpected EOL.")),
                Some(0) => return Err(self.parse_err("Null byte not allowed.")),
                Some(c) => lhs.push(c as char),
            }
        }
    }

    /// Read a backslash-escaped value until newline.
    /// Backslash causes the next byte to be taken literally.
    fn read_backslashed(&mut self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        loop {
            match self.cr.getc()? {
                Some(b'\n') => return Ok(data),
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(b'\\') => match self.cr.getc()? {
                    None => return Err(self.parse_err("Unexpected EOF.")),
                    Some(c) => data.push(c),
                },
                Some(c) => data.push(c),
            }
        }
    }

    /// Read an LDIF-style value with line folding (newline + space = continuation).
    fn read_ldif_attrval(&mut self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        loop {
            match self.cr.getc()? {
                Some(b'\n') => {
                    match self.cr.getc()? {
                        Some(b' ') => continue, // folded line
                        Some(c) => {
                            self.cr.ungetc(c);
                            return Ok(data);
                        }
                        None => return Ok(data), // EOF after newline is OK
                    }
                }
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(c) => data.push(c),
            }
        }
    }

    /// Skip a comment line (with line folding support).
    fn skip_comment(&mut self) -> Result<()> {
        loop {
            match self.cr.getc()? {
                None => return Err(self.parse_err("Unexpected EOF.")),
                Some(b'\n') => {
                    match self.cr.getc()? {
                        Some(b' ') => continue, // folded comment
                        Some(c) => {
                            self.cr.ungetc(c);
                            return Ok(());
                        }
                        None => return Ok(()),
                    }
                }
                Some(_) => {} // skip
            }
        }
    }

    /// Read a line in ldapvi native format:
    ///
    /// ```text
    /// name (':' encoding)? ' ' value '\n'
    /// ```
    ///
    /// where encoding is one of: (empty) for LDIF-style, `:` for base64,
    /// `<` for file URL, `;` for backslash-escaped, `crypt`/`sha`/`ssha`/
    /// `md5`/`smd5`/`cryptmd5` for password hashing, or a decimal number
    /// for a fixed-length binary read.  Without a colon, values use
    /// backslash escaping by default.
    ///
    /// Returns `Line(name, value)` where name may be empty (for modify value
    /// lines starting with space), `BlankLine` for empty lines, or `Eof`.
    /// Comments (lines starting with `#`) are skipped.
    fn read_line1(&mut self) -> Result<LineResult> {
        // Skip comment lines, detect EOF / blank lines
        loop {
            match self.cr.getc()? {
                None => return Ok(LineResult::Eof),
                Some(b'\n') => return Ok(LineResult::BlankLine),
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

        // Read LHS (everything up to space)
        let lhs = self.read_lhs()?;

        // Parse name and encoding from LHS
        let (name, encoding) = if let Some(colon_pos) = lhs.find(':') {
            let name = lhs[..colon_pos].to_string();
            let enc = lhs[colon_pos + 1..].to_string();
            (name, Some(enc))
        } else {
            (lhs, None)
        };

        // Read value based on encoding
        let value = match encoding.as_deref() {
            None | Some(";") => {
                // Default: backslash-escaped value
                self.read_backslashed()?
            }
            Some("") => {
                // LDIF-style value (line folded, no decode)
                self.read_ldif_attrval()?
            }
            Some(":") => {
                // Base64: read LDIF-style, then decode
                let raw = self.read_ldif_attrval()?;
                let raw_str = String::from_utf8_lossy(&raw);
                base64::read_base64(&raw_str)
                    .ok_or_else(|| self.parse_err("Invalid Base64 string."))?
            }
            Some("<") => {
                // File URL
                let raw = self.read_ldif_attrval()?;
                let url = String::from_utf8_lossy(&raw);
                if !url.starts_with("file://") {
                    return Err(self.parse_err("Unknown URL scheme."));
                }
                let path = &url[7..];
                std::fs::read(path).map_err(LdapviError::Io)?
            }
            Some(enc) if enc.eq_ignore_ascii_case("crypt") => {
                let raw = self.read_ldif_attrval()?;
                let key = String::from_utf8_lossy(&raw);
                let hash = crypt_des(&key)?;
                format!("{{CRYPT}}{}", hash).into_bytes()
            }
            Some(enc) if enc.eq_ignore_ascii_case("cryptmd5") => {
                let raw = self.read_ldif_attrval()?;
                let key = String::from_utf8_lossy(&raw);
                let hash = crypt_md5(&key)?;
                format!("{{CRYPT}}{}", hash).into_bytes()
            }
            Some(enc) if enc.eq_ignore_ascii_case("sha") => {
                let raw = self.read_ldif_attrval()?;
                let key = String::from_utf8_lossy(&raw);
                let mut result = String::from("{SHA}");
                port::append_sha(&mut result, &key);
                result.into_bytes()
            }
            Some(enc) if enc.eq_ignore_ascii_case("ssha") => {
                let raw = self.read_ldif_attrval()?;
                let key = String::from_utf8_lossy(&raw);
                let mut result = String::from("{SSHA}");
                port::append_ssha(&mut result, &key);
                result.into_bytes()
            }
            Some(enc) if enc.eq_ignore_ascii_case("md5") => {
                let raw = self.read_ldif_attrval()?;
                let key = String::from_utf8_lossy(&raw);
                let mut result = String::from("{MD5}");
                port::append_md5(&mut result, &key);
                result.into_bytes()
            }
            Some(enc) if enc.eq_ignore_ascii_case("smd5") => {
                let raw = self.read_ldif_attrval()?;
                let key = String::from_utf8_lossy(&raw);
                let mut result = String::from("{SMD5}");
                port::append_smd5(&mut result, &key);
                result.into_bytes()
            }
            Some(enc) => {
                // Try numeric encoding (read exactly N bytes)
                match enc.parse::<usize>() {
                    Ok(n) => {
                        let mut buf = vec![0u8; n];
                        self.cr.read_exact(&mut buf)?;
                        buf
                    }
                    Err(_) => {
                        return Err(self.parse_err("Unknown value encoding."));
                    }
                }
            }
        };

        Ok(LineResult::Line(name, value))
    }

    /// Read a line, rejecting empty names on content lines.
    /// Returns `Ok(Some((name, value)))` for content, `Ok(None)` for EOF/blank.
    fn read_line(&mut self) -> Result<Option<(String, Vec<u8>)>> {
        match self.read_line1()? {
            LineResult::Eof | LineResult::BlankLine => Ok(None),
            LineResult::Line(name, value) => {
                if name.is_empty() {
                    return Err(self.parse_err("Space at beginning of line."));
                }
                Ok(Some((name, value)))
            }
        }
    }

    /// Read the header line of a record (key + DN), skipping blank lines and
    /// the "version ldapvi" line.
    /// Returns `Ok(Some((key, dn, pos)))` or `Ok(None)` at EOF.
    fn read_header(&mut self, offset: Option<u64>) -> Result<Option<(String, String, u64)>> {
        if let Some(off) = offset {
            self.cr.seek(off)?;
        }

        loop {
            let pos = self.cr.tell()?;
            match self.read_line()? {
                None => {
                    // Blank line or EOF. Check if EOF.
                    if self.cr.at_eof()? {
                        return Ok(None);
                    }
                    continue;
                }
                Some((key, value)) => {
                    if key == "version" {
                        let version = String::from_utf8_lossy(&value);
                        if version != "ldapvi" {
                            return Err(self.parse_err("Invalid file format."));
                        }
                        continue;
                    }
                    // Validate DN (must contain '=')
                    let dn = String::from_utf8_lossy(&value).into_owned();
                    if !dn.contains('=') {
                        return Err(self.parse_err("Invalid distinguished name string."));
                    }
                    return Ok(Some((key, dn, pos)));
                }
            }
        }
    }

    /// Read attribute-value body lines into an entry.
    fn read_attrval_body(&mut self, entry: &mut Entry) -> Result<()> {
        loop {
            match self.read_line()? {
                None => return Ok(()),
                Some((name, value)) => {
                    let attr = entry.find_attribute(&name, true).unwrap();
                    attr.values.push(value);
                }
            }
        }
    }

    /// Read the body of a rename record: `add|replace new_dn`.
    fn read_rename_body(&mut self) -> Result<(String, bool)> {
        match self.read_line()? {
            None => Err(self.parse_err("Rename record lacks dn line.")),
            Some((action, value)) => {
                let delete_old_rdn = if action == "replace" {
                    true
                } else if action == "add" {
                    false
                } else {
                    return Err(self.parse_err("Expected 'add' or 'replace' in rename record."));
                };
                let new_dn = String::from_utf8_lossy(&value).into_owned();

                // Expect end of record
                self.read_nothing()?;
                Ok((new_dn, delete_old_rdn))
            }
        }
    }

    /// Expect an empty line (or EOF) -- error if there's content.
    fn read_nothing(&mut self) -> Result<()> {
        match self.read_line()? {
            None => Ok(()),
            Some(_) => Err(self.parse_err("Garbage at end of record.")),
        }
    }

    /// Parse a modify body. Uses `read_line1` to allow empty-name value lines.
    ///
    /// Format:
    /// ```text
    /// add attr_name
    ///  value1
    ///  value2
    /// delete attr_name
    ///
    /// ```
    fn read_modify_body(&mut self) -> Result<Vec<LdapMod>> {
        let mut mods: Vec<LdapMod> = Vec::new();
        let mut current_mod: Option<LdapMod> = None;

        loop {
            match self.read_line1()? {
                LineResult::Line(name, value) => {
                    if !name.is_empty() {
                        // New mod operation: finalize previous
                        if let Some(m) = current_mod.take() {
                            mods.push(m);
                        }
                        let op = match name.as_str() {
                            "add" => ModOp::Add,
                            "delete" => ModOp::Delete,
                            "replace" => ModOp::Replace,
                            _ => return Err(self.parse_err("Invalid change marker.")),
                        };
                        let attr = String::from_utf8_lossy(&value).into_owned();
                        current_mod = Some(LdapMod {
                            op,
                            attr,
                            values: Vec::new(),
                        });
                    } else {
                        // Empty name: value for current mod
                        if let Some(ref mut m) = current_mod {
                            m.values.push(value);
                        }
                    }
                }
                LineResult::Eof | LineResult::BlankLine => {
                    if let Some(m) = current_mod.take() {
                        mods.push(m);
                    }
                    return Ok(mods);
                }
            }
        }
    }

    // -- public API ---------------------------------------------------------

    /// Read a full attrval-record.
    /// Returns `Ok(Some((key, entry, pos)))` or `Ok(None)` at EOF.
    pub fn read_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, Entry, u64)>> {
        let (key, dn, pos) = match self.read_header(offset)? {
            Some(h) => h,
            None => return Ok(None),
        };
        let mut entry = Entry::new(dn);
        self.read_attrval_body(&mut entry)?;
        Ok(Some((key, entry, pos)))
    }

    /// Peek at the next record's key without consuming the body.
    /// Returns `Ok(Some((key, pos)))` or `Ok(None)` at EOF.
    pub fn peek_entry(&mut self, offset: Option<u64>) -> Result<Option<(String, u64)>> {
        match self.read_header(offset)? {
            Some((key, _, pos)) => Ok(Some((key, pos))),
            None => Ok(None),
        }
    }

    /// Skip past an entry, returning its key.
    /// Returns `Ok(Some(key))` or `Ok(None)` at EOF.
    pub fn skip_entry(&mut self, offset: Option<u64>) -> Result<Option<String>> {
        let (key, _, _) = match self.read_header(offset)? {
            Some(h) => h,
            None => return Ok(None),
        };

        match key.as_str() {
            "modify" => {
                self.read_modify_body()?;
            }
            "rename" => {
                self.read_rename_body()?;
            }
            "delete" => {
                self.read_nothing()?;
            }
            _ => {
                let mut dummy = Entry::new(String::new());
                self.read_attrval_body(&mut dummy)?;
            }
        }

        Ok(Some(key))
    }

    /// Read a rename record.
    pub fn read_rename(&mut self, offset: Option<u64>) -> Result<RenameRecord> {
        let (_, old_dn, _) = self
            .read_header(offset)?
            .ok_or_else(|| self.parse_err("Unexpected EOF in rename."))?;
        let (new_dn, delete_old_rdn) = self.read_rename_body()?;
        Ok(RenameRecord {
            old_dn,
            new_dn,
            delete_old_rdn,
        })
    }

    /// Read a delete record.
    pub fn read_delete(&mut self, offset: Option<u64>) -> Result<String> {
        let (_, dn, _) = self
            .read_header(offset)?
            .ok_or_else(|| self.parse_err("Unexpected EOF in delete."))?;
        self.read_nothing()?;
        Ok(dn)
    }

    /// Read a modify record.
    pub fn read_modify(&mut self, offset: Option<u64>) -> Result<ModifyRecord> {
        let (_, dn, _) = self
            .read_header(offset)?
            .ok_or_else(|| self.parse_err("Unexpected EOF in modify."))?;
        let mods = self.read_modify_body()?;
        Ok(ModifyRecord { dn, mods })
    }

    /// Seek to a position.
    pub fn seek_to(&mut self, pos: u64) -> Result<()> {
        self.cr.seek(pos)
    }

    /// Read raw bytes from the underlying stream (for fastcmp).
    pub fn read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cr.read_raw(buf)
    }

    /// Read a profile record. Returns `Ok(None)` at EOF.
    pub fn read_profile(&mut self) -> Result<Option<Entry>> {
        loop {
            match self.read_line()? {
                None => {
                    if self.cr.at_eof()? {
                        return Ok(None);
                    }
                    continue;
                }
                Some((key, value)) => {
                    if key != "profile" {
                        return Err(LdapviError::Parse {
                            position: 0,
                            message: format!(
                                "Expected 'profile' in configuration, found '{}' instead",
                                key
                            ),
                        });
                    }
                    let name = String::from_utf8_lossy(&value).into_owned();
                    let mut entry = Entry::new(name);
                    self.read_attrval_body(&mut entry)?;
                    return Ok(Some(entry));
                }
            }
        }
    }
}

// ===========================================================================
// Tests -- ported from test_parse.c
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parser(data: &[u8]) -> LdapviParser<Cursor<&[u8]>> {
        LdapviParser::new(Cursor::new(data))
    }

    fn find_attr<'a>(entry: &'a Entry, name: &str) -> Option<&'a crate::data::Attribute> {
        entry.get_attribute(name)
    }

    // ── Group 1: EOF and empty input ──────────────────────────────

    #[test]
    fn eof_returns_null_key() {
        let mut p = parser(b"");
        let result = p.read_entry(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn blank_lines_then_eof() {
        let mut p = parser(b"\n\n\n");
        let result = p.read_entry(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn peek_eof_returns_null_key() {
        let mut p = parser(b"");
        let result = p.peek_entry(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn skip_eof_returns_null_key() {
        let mut p = parser(b"");
        let result = p.skip_entry(None).unwrap();
        assert!(result.is_none());
    }

    // ── Group 2: Simple entry read ────────────────────────────────

    #[test]
    fn read_simple_entry() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              sn bar\n\
              \n",
        );
        let (key, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
        assert_eq!(entry.attributes.len(), 2);

        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values.len(), 1);
        assert_eq!(a.values[0], b"foo");

        let a = find_attr(&entry, "sn").unwrap();
        assert_eq!(a.values.len(), 1);
        assert_eq!(a.values[0], b"bar");
    }

    #[test]
    fn read_entry_multi_valued() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              cn bar\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.attributes.len(), 1);
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values.len(), 2);
        assert_eq!(a.values[0], b"foo");
        assert_eq!(a.values[1], b"bar");
    }

    #[test]
    fn read_entry_empty_value() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn \n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values.len(), 1);
        assert_eq!(a.values[0].len(), 0);
    }

    #[test]
    fn read_entry_at_offset() {
        let input = b"add cn=skip,dc=com\n\
                      cn skip\n\
                      \n\
                      add cn=target,dc=example,dc=com\n\
                      cn target\n\
                      \n";
        let mut p = parser(input);
        // Read first entry
        let _ = p.read_entry(None).unwrap().unwrap();
        let pos = p.stream_position().unwrap();

        // Re-read from offset
        let (_, entry, _) = p.read_entry(Some(pos)).unwrap().unwrap();
        assert_eq!(entry.dn, "cn=target,dc=example,dc=com");
    }

    #[test]
    fn read_entry_sequential() {
        let mut p = parser(
            b"add cn=first,dc=example,dc=com\n\
              cn first\n\
              \n\
              add cn=second,dc=example,dc=com\n\
              cn second\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.dn, "cn=first,dc=example,dc=com");

        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.dn, "cn=second,dc=example,dc=com");
    }

    #[test]
    fn entry_eof_terminates_record() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo\n",
        );
        let (key, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0], b"foo");
    }

    // ── Group 3: Version line ─────────────────────────────────────

    #[test]
    fn version_line_skipped() {
        let mut p = parser(
            b"version ldapvi\n\
              add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        let (key, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn invalid_version() {
        let mut p = parser(
            b"version 1\n\
              add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        assert!(p.read_entry(None).is_err());
    }

    // ── Group 4: Comments ─────────────────────────────────────────

    #[test]
    fn comment_lines_skipped() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              # this is a comment\n\
              cn foo\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.attributes.len(), 1);
    }

    #[test]
    fn comment_with_folding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              # comment line\n \
              continued\n\
              cn foo\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(entry.attributes.len(), 1);
    }

    // ── Group 5: Backslash-escaped values ─────────────────────────

    #[test]
    fn backslash_plain_value() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo bar\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 7);
        assert_eq!(a.values[0], b"foo bar");
    }

    #[test]
    fn backslash_embedded_newline() {
        let mut p = parser(b"add cn=foo,dc=example,dc=com\ndescription one\\\ntwo\n\n");
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "description").unwrap();
        assert_eq!(a.values[0].len(), 7);
        assert_eq!(a.values[0], b"one\ntwo");
    }

    #[test]
    fn backslash_embedded_backslash() {
        let mut p = parser(b"add cn=foo,dc=example,dc=com\ncn foo\\\\bar\n\n");
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 7);
        assert_eq!(a.values[0], b"foo\\bar");
    }

    #[test]
    fn semicolon_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn:; foo\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 3);
        assert_eq!(a.values[0], b"foo");
    }

    // ── Group 6: Base64 encoding ──────────────────────────────────

    #[test]
    fn base64_value() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn:: Zm9v\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 3);
        assert_eq!(a.values[0], b"foo");
    }

    #[test]
    fn base64_invalid() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn:: !!!!\n\
              \n",
        );
        assert!(p.read_entry(None).is_err());
    }

    // ── Group 7: File URL encoding ────────────────────────────────

    #[test]
    fn file_url_read() {
        use std::io::Write;

        let dir = std::env::temp_dir();
        let path = dir.join("ldapvi_test_parse_file_url");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let input = format!(
            "add cn=foo,dc=example,dc=com\ncn:< file://{}\n\n",
            path.display()
        );
        let mut p = LdapviParser::new(Cursor::new(input.as_bytes()));
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 11);
        assert_eq!(a.values[0], b"hello world");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_url_unknown_scheme() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn:< http://example.com/data\n\
              \n",
        );
        assert!(p.read_entry(None).is_err());
    }

    // ── Group 8: Numeric binary encoding ──────────────────────────

    #[test]
    fn numeric_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn:3 foo\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 3);
        assert_eq!(a.values[0], b"foo");
    }

    #[test]
    fn numeric_encoding_zero() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn:0 \n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "cn").unwrap();
        assert_eq!(a.values[0].len(), 0);
    }

    // ── Group 9: Password hash encodings ──────────────────────────

    #[test]
    fn sha_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              userPassword:sha secret\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "userPassword").unwrap();
        assert!(a.values[0].len() >= 5);
        assert_eq!(&a.values[0][..5], b"{SHA}");
    }

    #[test]
    fn ssha_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              userPassword:ssha secret\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "userPassword").unwrap();
        assert!(a.values[0].len() >= 6);
        assert_eq!(&a.values[0][..6], b"{SSHA}");
    }

    #[test]
    fn md5_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              userPassword:md5 secret\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "userPassword").unwrap();
        assert!(a.values[0].len() >= 5);
        assert_eq!(&a.values[0][..5], b"{MD5}");
    }

    #[test]
    fn smd5_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              userPassword:smd5 secret\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "userPassword").unwrap();
        assert!(a.values[0].len() >= 6);
        assert_eq!(&a.values[0][..6], b"{SMD5}");
    }

    // ── Group 10: Crypt encodings ─────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn crypt_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              userPassword:crypt secret\n\
              \n",
        );
        let (_, entry, _) = p.read_entry(None).unwrap().unwrap();
        let a = find_attr(&entry, "userPassword").unwrap();
        assert!(a.values[0].len() >= 7);
        assert_eq!(&a.values[0][..7], b"{CRYPT}");
    }

    // ── Group 11: Key types ───────────────────────────────────────

    #[test]
    fn numeric_key() {
        let mut p = parser(
            b"42 cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        let (key, entry, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "42");
        assert_eq!(entry.dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn arbitrary_key() {
        let mut p = parser(
            b"mykey cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        let (key, _, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "mykey");
    }

    #[test]
    fn invalid_dn() {
        let mut p = parser(
            b"add notadn\n\
              cn foo\n\
              \n",
        );
        assert!(p.read_entry(None).is_err());
    }

    // ── Group 12: Delete record ───────────────────────────────────

    #[test]
    fn read_delete_basic() {
        let mut p = parser(b"delete cn=foo,dc=example,dc=com\n\n");
        let dn = p.read_delete(None).unwrap();
        assert_eq!(dn, "cn=foo,dc=example,dc=com");
    }

    #[test]
    fn read_delete_garbage_after() {
        let mut p = parser(
            b"delete cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        assert!(p.read_delete(None).is_err());
    }

    #[test]
    fn skip_delete() {
        let mut p = parser(b"delete cn=foo,dc=example,dc=com\n\n");
        let key = p.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "delete");
    }

    // ── Group 13: Modify record ───────────────────────────────────

    #[test]
    fn read_modify_add_operation() {
        let mut p = parser(
            b"modify cn=foo,dc=example,dc=com\n\
              add mail\n\
              \x20foo@example.com\n\
              \n",
        );
        let record = p.read_modify(None).unwrap();
        assert_eq!(record.dn, "cn=foo,dc=example,dc=com");
        assert_eq!(record.mods.len(), 1);
        assert_eq!(record.mods[0].op, ModOp::Add);
        assert_eq!(record.mods[0].attr, "mail");
        assert_eq!(record.mods[0].values.len(), 1);
        assert_eq!(record.mods[0].values[0], b"foo@example.com");
    }

    #[test]
    fn read_modify_delete_operation() {
        let mut p = parser(
            b"modify cn=foo,dc=example,dc=com\n\
              delete phone\n\
              \n",
        );
        let record = p.read_modify(None).unwrap();
        assert_eq!(record.mods.len(), 1);
        assert_eq!(record.mods[0].op, ModOp::Delete);
        assert_eq!(record.mods[0].attr, "phone");
        assert_eq!(record.mods[0].values.len(), 0);
    }

    #[test]
    fn read_modify_replace_operation() {
        let mut p = parser(
            b"modify cn=foo,dc=example,dc=com\n\
              replace sn\n\
              \x20Bar\n\
              \n",
        );
        let record = p.read_modify(None).unwrap();
        assert_eq!(record.mods.len(), 1);
        assert_eq!(record.mods[0].op, ModOp::Replace);
        assert_eq!(record.mods[0].attr, "sn");
        assert_eq!(record.mods[0].values.len(), 1);
        assert_eq!(record.mods[0].values[0], b"Bar");
    }

    #[test]
    fn read_modify_multiple_operations() {
        let mut p = parser(
            b"modify cn=foo,dc=example,dc=com\n\
              add mail\n\
              \x20foo@example.com\n\
              delete phone\n\
              \n",
        );
        let record = p.read_modify(None).unwrap();
        assert_eq!(record.mods.len(), 2);
        assert_eq!(record.mods[0].op, ModOp::Add);
        assert_eq!(record.mods[0].attr, "mail");
        assert_eq!(record.mods[1].op, ModOp::Delete);
        assert_eq!(record.mods[1].attr, "phone");
    }

    #[test]
    fn read_modify_multiple_values() {
        let mut p = parser(
            b"modify cn=foo,dc=example,dc=com\n\
              add mail\n\
              \x20foo@example.com\n\
              \x20bar@example.com\n\
              \n",
        );
        let record = p.read_modify(None).unwrap();
        assert_eq!(record.mods.len(), 1);
        assert_eq!(record.mods[0].values.len(), 2);
        assert_eq!(record.mods[0].values[0], b"foo@example.com");
        assert_eq!(record.mods[0].values[1], b"bar@example.com");
    }

    #[test]
    fn read_modify_invalid_marker() {
        let mut p = parser(
            b"modify cn=foo,dc=example,dc=com\n\
              bogus mail\n\
              \n",
        );
        assert!(p.read_modify(None).is_err());
    }

    // ── Group 14: Rename record ───────────────────────────────────

    #[test]
    fn read_rename_add() {
        let mut p = parser(
            b"rename cn=old,dc=example,dc=com\n\
              add cn=new,dc=example,dc=com\n\
              \n",
        );
        let r = p.read_rename(None).unwrap();
        assert_eq!(r.old_dn, "cn=old,dc=example,dc=com");
        assert_eq!(r.new_dn, "cn=new,dc=example,dc=com");
        assert!(!r.delete_old_rdn);
    }

    #[test]
    fn read_rename_replace() {
        let mut p = parser(
            b"rename cn=old,dc=example,dc=com\n\
              replace cn=new,dc=example,dc=com\n\
              \n",
        );
        let r = p.read_rename(None).unwrap();
        assert_eq!(r.old_dn, "cn=old,dc=example,dc=com");
        assert_eq!(r.new_dn, "cn=new,dc=example,dc=com");
        assert!(r.delete_old_rdn);
    }

    #[test]
    fn read_rename_missing_dn() {
        let mut p = parser(b"rename cn=old,dc=example,dc=com\n\n");
        assert!(p.read_rename(None).is_err());
    }

    #[test]
    fn read_rename_invalid_keyword() {
        let mut p = parser(
            b"rename cn=old,dc=example,dc=com\n\
              move cn=new,dc=example,dc=com\n\
              \n",
        );
        assert!(p.read_rename(None).is_err());
    }

    #[test]
    fn read_rename_garbage_after() {
        let mut p = parser(
            b"rename cn=old,dc=example,dc=com\n\
              add cn=new,dc=example,dc=com\n\
              extra stuff\n\
              \n",
        );
        assert!(p.read_rename(None).is_err());
    }

    // ── Group 15: skip_entry ──────────────────────────────────────

    #[test]
    fn skip_add_entry() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              sn bar\n\
              \n",
        );
        let key = p.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
    }

    #[test]
    fn skip_modify_entry() {
        let mut p = parser(
            b"modify cn=foo,dc=example,dc=com\n\
              add mail\n\
              \x20foo@example.com\n\
              \n",
        );
        let key = p.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "modify");
    }

    #[test]
    fn skip_rename_entry() {
        let mut p = parser(
            b"rename cn=old,dc=example,dc=com\n\
              add cn=new,dc=example,dc=com\n\
              \n",
        );
        let key = p.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "rename");
    }

    #[test]
    fn skip_delete_entry() {
        let mut p = parser(b"delete cn=foo,dc=example,dc=com\n\n");
        let key = p.skip_entry(None).unwrap().unwrap();
        assert_eq!(key, "delete");
    }

    // ── Group 16: peek_entry ──────────────────────────────────────

    #[test]
    fn peek_basic() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        let (key, _) = p.peek_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
    }

    #[test]
    fn peek_does_not_consume_body() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        let (key, _) = p.peek_entry(Some(0)).unwrap().unwrap();
        assert_eq!(key, "add");

        // Re-read from start should still work
        let (key, entry, _) = p.read_entry(Some(0)).unwrap().unwrap();
        assert_eq!(key, "add");
        assert_eq!(entry.attributes.len(), 1);
    }

    // ── Group 17: read_profile ────────────────────────────────────

    #[test]
    fn read_profile_basic() {
        let mut p = parser(
            b"profile myprofile\n\
              host ldap.example.com\n\
              base dc=example,dc=com\n\
              \n",
        );
        let entry = p.read_profile().unwrap().unwrap();
        assert_eq!(entry.dn, "myprofile");
        assert_eq!(entry.attributes.len(), 2);

        let a = find_attr(&entry, "host").unwrap();
        assert_eq!(a.values[0], b"ldap.example.com");

        let a = find_attr(&entry, "base").unwrap();
        assert_eq!(a.values[0], b"dc=example,dc=com");
    }

    #[test]
    fn read_profile_eof() {
        let mut p = parser(b"");
        let result = p.read_profile().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_profile_invalid_header() {
        let mut p = parser(
            b"notprofile myprofile\n\
              host ldap.example.com\n\
              \n",
        );
        assert!(p.read_profile().is_err());
    }

    // ── Group 18: Error conditions ────────────────────────────────

    #[test]
    fn unknown_encoding() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn:bogus val\n\
              \n",
        );
        assert!(p.read_entry(None).is_err());
    }

    #[test]
    fn null_byte_in_attr_name() {
        let data = b"add cn=foo,dc=example,dc=com\nc\x00n foo\n\n";
        let mut p = parser(data);
        assert!(p.read_entry(None).is_err());
    }

    #[test]
    fn unexpected_eof_in_attr_name() {
        let mut p = parser(b"add cn=foo,dc=example,dc=com\ncn");
        assert!(p.read_entry(None).is_err());
    }

    #[test]
    fn unexpected_eol_in_attr_name() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn\n\
              \n",
        );
        assert!(p.read_entry(None).is_err());
    }

    // ── Group 19: pos output ──────────────────────────────────────

    #[test]
    fn pos_set_correctly() {
        let mut p = parser(
            b"add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        let (_, _, pos) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(pos, 0);
    }

    #[test]
    fn pos_with_version() {
        let mut p = parser(
            b"version ldapvi\n\
              add cn=foo,dc=example,dc=com\n\
              cn foo\n\
              \n",
        );
        let (_, _, pos) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(pos, 15); // "version ldapvi\n" = 15 bytes
    }
}
