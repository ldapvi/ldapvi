//! Output formatting -- Rust port of print.c
//!
//! Prints entries and change records in both ldapvi and LDIF formats.

use std::io::{self, Write};

use crate::base64;
use crate::data::{Entry, LdapMod, ModOp};
use crate::schema::Entroid;

/// Controls how non-ASCII or binary values are detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryMode {
    /// Check for valid UTF-8 (default).
    Utf8,
    /// Only plain ASCII (bytes 32..=126 plus \n and \t) counts as readable.
    Ascii,
    /// Everything is considered readable (never base64-encode).
    Junk,
}

// ---------------------------------------------------------------------------
// String classification helpers
// ---------------------------------------------------------------------------

/// Check if `data` is valid UTF-8 with no null bytes.
/// Matches the C `utf8_string_p`.
fn utf8_string_p(data: &[u8]) -> bool {
    if data.contains(&0) {
        return false;
    }
    std::str::from_utf8(data).is_ok()
}

/// Check if all bytes are printable: >= 32 or \n or \t.
/// Matches the C `readable_string_p`.
fn readable_string_p(data: &[u8]) -> bool {
    for &c in data {
        // In C, char is signed: bytes >= 128 are negative and fail `c < 32`.
        if c >= 128 || (c < 32 && c != b'\n' && c != b'\t') {
            return false;
        }
    }
    true
}

/// Check if the value can be printed as an LDIF SAFE-STRING:
/// no leading space/colon/less-than, no null/CR/LF/non-ASCII bytes.
fn safe_string_p(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let c = data[0];
    if c == b' ' || c == b':' || c == b'<' {
        return false;
    }
    for &c in data {
        if c == 0 || c == b'\r' || c == b'\n' || c >= 0x80 {
            return false;
        }
    }
    true
}

/// Is the value "readable" according to the given mode?
fn is_readable(data: &[u8], mode: BinaryMode) -> bool {
    match mode {
        BinaryMode::Utf8 => utf8_string_p(data),
        BinaryMode::Ascii => readable_string_p(data),
        BinaryMode::Junk => true,
    }
}

// ---------------------------------------------------------------------------
// Low-level output helpers
// ---------------------------------------------------------------------------

/// Write `data` with backslash escaping: `\n` → `\\n`, `\\` → `\\\\`.
fn write_backslashed(w: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    for &c in data {
        if c == b'\n' || c == b'\\' {
            w.write_all(b"\\")?;
        }
        w.write_all(&[c])?;
    }
    Ok(())
}

/// Write an attribute value with appropriate encoding for ldapvi format.
///
/// `prefer_no_colon`: true for DN values printed after a keyword (uses space
/// prefix instead of colon prefix).
fn print_attrval(
    w: &mut dyn Write,
    data: &[u8],
    prefer_no_colon: bool,
    mode: BinaryMode,
) -> io::Result<()> {
    if !is_readable(data, mode) {
        w.write_all(b":: ")?;
        base64::print_base64(data, w)?;
    } else if prefer_no_colon {
        w.write_all(b" ")?;
        write_backslashed(w, data)?;
    } else if !safe_string_p(data) {
        w.write_all(b":; ")?;
        write_backslashed(w, data)?;
    } else {
        w.write_all(b": ")?;
        w.write_all(data)?;
    }
    Ok(())
}

/// Write an LDIF attribute line: `ad: value\n` or `ad:: base64\n`.
fn print_ldif_line(w: &mut dyn Write, ad: &str, data: &[u8]) -> io::Result<()> {
    w.write_all(ad.as_bytes())?;
    if safe_string_p(data) {
        w.write_all(b": ")?;
        w.write_all(data)?;
    } else {
        w.write_all(b":: ")?;
        base64::print_base64(data, w)?;
    }
    w.write_all(b"\n")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// DN splitting for modrdn
// ---------------------------------------------------------------------------

/// Split a DN into RDN components, handling backslash-escaped commas.
fn explode_dn(dn: &str) -> Vec<&str> {
    if dn.is_empty() {
        return vec![];
    }
    let mut parts = Vec::new();
    let mut start = 0;
    let bytes = dn.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2; // skip escaped char
        } else if bytes[i] == b',' {
            parts.push(&dn[start..i]);
            start = i + 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    parts.push(&dn[start..]);
    parts
}

/// Join RDN components back into a DN.
fn rdns_to_dn(rdns: &[&str]) -> String {
    rdns.join(",")
}

// ---------------------------------------------------------------------------
// ldapvi format printers
// ---------------------------------------------------------------------------

/// Print an entry in ldapvi format.
pub fn print_ldapvi_entry(
    w: &mut dyn Write,
    entry: &Entry,
    key: Option<&str>,
    mode: BinaryMode,
) -> io::Result<()> {
    w.write_all(b"\n")?;
    w.write_all(key.unwrap_or("entry").as_bytes())?;
    print_attrval(w, entry.dn.as_bytes(), true, mode)?;
    w.write_all(b"\n")?;

    for attr in &entry.attributes {
        for value in &attr.values {
            w.write_all(attr.ad.as_bytes())?;
            print_attrval(w, value, false, mode)?;
            w.write_all(b"\n")?;
        }
    }
    Ok(())
}

/// Print an entry in ldapvi format with schema annotations from an Entroid.
///
/// After the DN line, writes entroid.comment (structural class info, warnings).
/// For each attribute, calls entroid.remove_ad() — if false, writes a warning.
/// After all attributes, writes remaining MUST as "required attribute not shown"
/// and remaining MAY as commented-out placeholders.
pub fn print_ldapvi_entry_annotated(
    w: &mut dyn Write,
    entry: &Entry,
    key: Option<&str>,
    mode: BinaryMode,
    entroid: &mut Entroid,
) -> io::Result<()> {
    w.write_all(b"\n")?;
    w.write_all(key.unwrap_or("entry").as_bytes())?;
    print_attrval(w, entry.dn.as_bytes(), true, mode)?;
    w.write_all(b"\n")?;

    // Write entroid comment (structural class info, warnings)
    if !entroid.comment.is_empty() {
        w.write_all(entroid.comment.as_bytes())?;
    }
    if !entroid.error.is_empty() {
        w.write_all(entroid.error.as_bytes())?;
    }

    for attr in &entry.attributes {
        // Check if attribute is allowed by schema
        let allowed = entroid.remove_ad(&attr.ad);
        if !allowed {
            write!(w, "# WARNING: {} not allowed by schema\n", attr.ad)?;
        }
        for value in &attr.values {
            w.write_all(attr.ad.as_bytes())?;
            print_attrval(w, value, false, mode)?;
            w.write_all(b"\n")?;
        }
    }

    // Write remaining MUST attributes as warnings
    for at in &entroid.must {
        write!(w, "# required attribute not shown: {}\n", at.name())?;
    }

    // Write remaining MAY attributes as commented-out placeholders
    for at in &entroid.may {
        write!(w, "#{}: \n", at.name())?;
    }

    Ok(())
}

/// Print a single LDAPMod in ldapvi format.
fn print_ldapvi_ldapmod(w: &mut dyn Write, m: &LdapMod, mode: BinaryMode) -> io::Result<()> {
    let op_str = match m.op {
        ModOp::Add => "add",
        ModOp::Delete => "delete",
        ModOp::Replace => "replace",
    };
    w.write_all(op_str.as_bytes())?;
    print_attrval(w, m.attr.as_bytes(), false, mode)?;
    w.write_all(b"\n")?;

    for value in &m.values {
        print_attrval(w, value, false, mode)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

/// Print a modify record in ldapvi format.
pub fn print_ldapvi_modify(
    w: &mut dyn Write,
    dn: &str,
    mods: &[LdapMod],
    mode: BinaryMode,
) -> io::Result<()> {
    w.write_all(b"\nmodify")?;
    print_attrval(w, dn.as_bytes(), true, mode)?;
    w.write_all(b"\n")?;

    for m in mods {
        print_ldapvi_ldapmod(w, m, mode)?;
    }
    Ok(())
}

/// Print a rename record in ldapvi format.
pub fn print_ldapvi_rename(
    w: &mut dyn Write,
    old_dn: &str,
    new_dn: &str,
    delete_old_rdn: bool,
    mode: BinaryMode,
) -> io::Result<()> {
    w.write_all(b"\nrename")?;
    print_attrval(w, old_dn.as_bytes(), true, mode)?;
    if delete_old_rdn {
        w.write_all(b"\nreplace")?;
    } else {
        w.write_all(b"\nadd")?;
    }
    print_attrval(w, new_dn.as_bytes(), false, mode)?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Print a modrdn record in ldapvi format (constructs full new DN from old DN
/// and new RDN).
pub fn print_ldapvi_modrdn(
    w: &mut dyn Write,
    old_dn: &str,
    new_rdn: &str,
    delete_old_rdn: bool,
    mode: BinaryMode,
) -> io::Result<()> {
    let rdns = explode_dn(old_dn);
    let new_dn = if rdns.len() > 1 {
        let mut parts = vec![new_rdn];
        parts.extend_from_slice(&rdns[1..]);
        rdns_to_dn(&parts)
    } else {
        new_rdn.to_string()
    };

    print_ldapvi_rename(w, old_dn, &new_dn, delete_old_rdn, mode)
}

/// Print an add record in ldapvi format.
pub fn print_ldapvi_add(
    w: &mut dyn Write,
    dn: &str,
    mods: &[LdapMod],
    mode: BinaryMode,
) -> io::Result<()> {
    w.write_all(b"\nadd")?;
    print_attrval(w, dn.as_bytes(), true, mode)?;
    w.write_all(b"\n")?;

    for m in mods {
        for value in &m.values {
            w.write_all(m.attr.as_bytes())?;
            print_attrval(w, value, false, mode)?;
            w.write_all(b"\n")?;
        }
    }
    Ok(())
}

/// Print a delete record in ldapvi format.
pub fn print_ldapvi_delete(w: &mut dyn Write, dn: &str, mode: BinaryMode) -> io::Result<()> {
    w.write_all(b"\ndelete")?;
    print_attrval(w, dn.as_bytes(), true, mode)?;
    w.write_all(b"\n")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// LDIF format printers
// ---------------------------------------------------------------------------

/// Print an entry in LDIF format.
pub fn print_ldif_entry(w: &mut dyn Write, entry: &Entry, key: Option<&str>) -> io::Result<()> {
    w.write_all(b"\n")?;
    print_ldif_line(w, "dn", entry.dn.as_bytes())?;
    if let Some(k) = key {
        write!(w, "ldapvi-key: {}\n", k)?;
    }
    for attr in &entry.attributes {
        for value in &attr.values {
            print_ldif_line(w, &attr.ad, value)?;
        }
    }
    Ok(())
}

/// Print a modify record in LDIF format.
pub fn print_ldif_modify(w: &mut dyn Write, dn: &str, mods: &[LdapMod]) -> io::Result<()> {
    w.write_all(b"\n")?;
    print_ldif_line(w, "dn", dn.as_bytes())?;
    w.write_all(b"changetype: modify\n")?;

    for m in mods {
        let op_str = match m.op {
            ModOp::Add => "add",
            ModOp::Delete => "delete",
            ModOp::Replace => "replace",
        };
        write!(w, "{}: {}\n", op_str, m.attr)?;
        for value in &m.values {
            print_ldif_line(w, &m.attr, value)?;
        }
        w.write_all(b"-\n")?;
    }
    Ok(())
}

/// Print a rename record in LDIF format.
pub fn print_ldif_rename(
    w: &mut dyn Write,
    old_dn: &str,
    new_dn: &str,
    delete_old_rdn: bool,
) -> io::Result<()> {
    let rdns = explode_dn(new_dn);

    w.write_all(b"\n")?;
    print_ldif_line(w, "dn", old_dn.as_bytes())?;
    w.write_all(b"changetype: modrdn\n")?;

    if rdns.is_empty() {
        print_ldif_line(w, "newrdn", b"")?;
    } else {
        print_ldif_line(w, "newrdn", rdns[0].as_bytes())?;
    }

    write!(w, "deleteoldrdn: {}\n", if delete_old_rdn { 1 } else { 0 })?;

    if rdns.len() <= 1 {
        w.write_all(b"newsuperior:\n")?;
    } else {
        let sup = rdns_to_dn(&rdns[1..]);
        print_ldif_line(w, "newsuperior", sup.as_bytes())?;
    }
    Ok(())
}

/// Print a modrdn record in LDIF format (without newsuperior).
pub fn print_ldif_modrdn(
    w: &mut dyn Write,
    old_dn: &str,
    new_rdn: &str,
    delete_old_rdn: bool,
) -> io::Result<()> {
    w.write_all(b"\n")?;
    print_ldif_line(w, "dn", old_dn.as_bytes())?;
    w.write_all(b"changetype: modrdn\n")?;
    print_ldif_line(w, "newrdn", new_rdn.as_bytes())?;
    write!(w, "deleteoldrdn: {}\n", if delete_old_rdn { 1 } else { 0 })?;
    Ok(())
}

/// Print an add record in LDIF format.
pub fn print_ldif_add(w: &mut dyn Write, dn: &str, mods: &[LdapMod]) -> io::Result<()> {
    w.write_all(b"\n")?;
    print_ldif_line(w, "dn", dn.as_bytes())?;
    w.write_all(b"changetype: add\n")?;

    for m in mods {
        for value in &m.values {
            print_ldif_line(w, &m.attr, value)?;
        }
    }
    Ok(())
}

/// Print a delete record in LDIF format.
pub fn print_ldif_delete(w: &mut dyn Write, dn: &str) -> io::Result<()> {
    w.write_all(b"\n")?;
    print_ldif_line(w, "dn", dn.as_bytes())?;
    w.write_all(b"changetype: delete\n")?;
    Ok(())
}

// ===========================================================================
// Tests -- ported from test_print.c (26 tests in 14 groups)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(dn: &str) -> Entry {
        Entry::new(dn.to_string())
    }

    fn add_value(entry: &mut Entry, ad: &str, val: &[u8]) {
        let attr = entry.find_attribute(ad, true).unwrap();
        attr.values.push(val.to_vec());
    }

    fn make_mod(op: ModOp, attr: &str, values: Vec<Vec<u8>>) -> LdapMod {
        LdapMod {
            op,
            attr: attr.to_string(),
            values,
        }
    }

    fn capture<F: FnOnce(&mut Vec<u8>) -> io::Result<()>>(f: F) -> String {
        let mut buf = Vec::new();
        f(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    // ── Group 1: print_ldapvi_entry ───────────────────────────────

    #[test]
    fn ldapvi_entry_simple() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b"foo");
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Utf8));
        assert_eq!(out, "\nadd cn=foo,dc=example,dc=com\ncn: foo\n");
    }

    #[test]
    fn ldapvi_entry_multi_valued() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b"foo");
        add_value(&mut e, "cn", b"bar");
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Utf8));
        assert_eq!(out, "\nadd cn=foo,dc=example,dc=com\ncn: foo\ncn: bar\n");
    }

    #[test]
    fn ldapvi_entry_null_key() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b"foo");
        let out = capture(|w| print_ldapvi_entry(w, &e, None, BinaryMode::Utf8));
        assert!(out.starts_with("\nentry cn=foo,dc=example,dc=com\n"));
    }

    #[test]
    fn ldapvi_entry_binary_value() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", &[0x00, 0x01, 0x02]);
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Utf8));
        assert!(out.contains("cn:: "));
    }

    #[test]
    fn ldapvi_entry_newline_value() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "description", b"line1\nline2");
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Utf8));
        // newlines use :; encoding with backslash escaping
        assert!(out.contains("description:; line1\\"));
    }

    #[test]
    fn ldapvi_entry_space_prefix() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b" leading space");
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Utf8));
        assert!(out.contains("cn:;  leading space\n"));
    }

    // ── Group 2: print_ldapvi_modify ──────────────────────────────

    #[test]
    fn ldapvi_modify_add() {
        let mods = vec![make_mod(
            ModOp::Add,
            "mail",
            vec![b"foo@example.com".to_vec()],
        )];
        let out = capture(|w| {
            print_ldapvi_modify(w, "cn=foo,dc=example,dc=com", &mods, BinaryMode::Utf8)
        });
        assert_eq!(
            out,
            "\nmodify cn=foo,dc=example,dc=com\nadd: mail\n: foo@example.com\n"
        );
    }

    #[test]
    fn ldapvi_modify_multi_ops() {
        let mods = vec![
            make_mod(ModOp::Add, "mail", vec![b"foo@example.com".to_vec()]),
            make_mod(ModOp::Delete, "phone", vec![]),
        ];
        let out = capture(|w| {
            print_ldapvi_modify(w, "cn=foo,dc=example,dc=com", &mods, BinaryMode::Utf8)
        });
        assert!(out.contains("add: mail\n"));
        assert!(out.contains("delete: phone\n"));
    }

    // ── Group 3: print_ldapvi_rename ──────────────────────────────

    #[test]
    fn ldapvi_rename_add() {
        let out = capture(|w| {
            print_ldapvi_rename(
                w,
                "cn=old,dc=example,dc=com",
                "cn=new,dc=example,dc=com",
                false,
                BinaryMode::Utf8,
            )
        });
        assert_eq!(
            out,
            "\nrename cn=old,dc=example,dc=com\nadd: cn=new,dc=example,dc=com\n"
        );
    }

    #[test]
    fn ldapvi_rename_replace() {
        let out = capture(|w| {
            print_ldapvi_rename(
                w,
                "cn=old,dc=example,dc=com",
                "cn=new,dc=example,dc=com",
                true,
                BinaryMode::Utf8,
            )
        });
        assert_eq!(
            out,
            "\nrename cn=old,dc=example,dc=com\nreplace: cn=new,dc=example,dc=com\n"
        );
    }

    // ── Group 4: print_ldapvi_modrdn ──────────────────────────────

    #[test]
    fn ldapvi_modrdn() {
        let out = capture(|w| {
            print_ldapvi_modrdn(
                w,
                "cn=old,dc=example,dc=com",
                "cn=new",
                true,
                BinaryMode::Utf8,
            )
        });
        assert!(out.contains("\nrename cn=old,dc=example,dc=com\n"));
        assert!(out.contains("replace"));
        assert!(out.contains("cn=new,dc=example,dc=com"));
    }

    // ── Group 5: print_ldapvi_add ─────────────────────────────────

    #[test]
    fn ldapvi_add() {
        let mods = vec![make_mod(ModOp::Add, "cn", vec![b"foo".to_vec()])];
        let out =
            capture(|w| print_ldapvi_add(w, "cn=foo,dc=example,dc=com", &mods, BinaryMode::Utf8));
        assert_eq!(out, "\nadd cn=foo,dc=example,dc=com\ncn: foo\n");
    }

    // ── Group 6: print_ldapvi_delete ──────────────────────────────

    #[test]
    fn ldapvi_delete() {
        let out = capture(|w| print_ldapvi_delete(w, "cn=foo,dc=example,dc=com", BinaryMode::Utf8));
        assert_eq!(out, "\ndelete cn=foo,dc=example,dc=com\n");
    }

    // ── Group 7: print_ldif_entry ─────────────────────────────────

    #[test]
    fn ldif_entry_simple() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b"foo");
        let out = capture(|w| print_ldif_entry(w, &e, None));
        assert_eq!(out, "\ndn: cn=foo,dc=example,dc=com\ncn: foo\n");
    }

    #[test]
    fn ldif_entry_with_key() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b"foo");
        let out = capture(|w| print_ldif_entry(w, &e, Some("42")));
        assert!(out.contains("ldapvi-key: 42\n"));
    }

    #[test]
    fn ldif_entry_binary() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", &[0x00, 0x01, 0x02]);
        let out = capture(|w| print_ldif_entry(w, &e, None));
        assert!(out.contains("cn:: "));
    }

    // ── Group 8: print_ldif_modify ────────────────────────────────

    #[test]
    fn ldif_modify() {
        let mods = vec![make_mod(
            ModOp::Add,
            "mail",
            vec![b"foo@example.com".to_vec()],
        )];
        let out = capture(|w| print_ldif_modify(w, "cn=foo,dc=example,dc=com", &mods));
        assert!(out.contains("dn: cn=foo,dc=example,dc=com\n"));
        assert!(out.contains("changetype: modify\n"));
        assert!(out.contains("add: mail\n"));
        assert!(out.contains("mail: foo@example.com\n"));
        assert!(out.contains("-\n"));
    }

    // ── Group 9: print_ldif_rename ────────────────────────────────

    #[test]
    fn ldif_rename() {
        let out = capture(|w| {
            print_ldif_rename(
                w,
                "cn=old,dc=example,dc=com",
                "cn=new,dc=example,dc=com",
                true,
            )
        });
        assert!(out.contains("dn: cn=old,dc=example,dc=com\n"));
        assert!(out.contains("changetype: modrdn\n"));
        assert!(out.contains("newrdn: cn=new\n"));
        assert!(out.contains("deleteoldrdn: 1\n"));
        assert!(out.contains("newsuperior: dc=example,dc=com\n"));
    }

    // ── Group 10: print_ldif_modrdn ───────────────────────────────

    #[test]
    fn ldif_modrdn() {
        let out = capture(|w| print_ldif_modrdn(w, "cn=old,dc=example,dc=com", "cn=new", false));
        assert!(out.contains("dn: cn=old,dc=example,dc=com\n"));
        assert!(out.contains("changetype: modrdn\n"));
        assert!(out.contains("newrdn: cn=new\n"));
        assert!(out.contains("deleteoldrdn: 0\n"));
    }

    // ── Group 11: print_ldif_add ──────────────────────────────────

    #[test]
    fn ldif_add() {
        let mods = vec![make_mod(ModOp::Add, "cn", vec![b"foo".to_vec()])];
        let out = capture(|w| print_ldif_add(w, "cn=foo,dc=example,dc=com", &mods));
        assert!(out.contains("dn: cn=foo,dc=example,dc=com\n"));
        assert!(out.contains("changetype: add\n"));
        assert!(out.contains("cn: foo\n"));
    }

    // ── Group 12: print_ldif_delete ───────────────────────────────

    #[test]
    fn ldif_delete() {
        let out = capture(|w| print_ldif_delete(w, "cn=foo,dc=example,dc=com"));
        assert!(out.contains("dn: cn=foo,dc=example,dc=com\n"));
        assert!(out.contains("changetype: delete\n"));
    }

    // ── Group 13: print_binary_mode ───────────────────────────────

    #[test]
    fn print_mode_utf8() {
        // Valid UTF-8: U+00E9 (e-acute) = 0xC3 0xA9
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", &[0xc3, 0xa9]);
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Utf8));
        // Valid UTF-8 should NOT be base64
        assert!(!out.contains("cn:: "));
    }

    #[test]
    fn print_mode_ascii() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", &[0xc3, 0xa9]);
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Ascii));
        // Non-ASCII → not readable in ASCII mode → base64
        assert!(out.contains("cn:: "));
    }

    #[test]
    fn print_mode_junk() {
        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", &[0x00, 0x01, 0x02]);
        let out = capture(|w| print_ldapvi_entry(w, &e, Some("add"), BinaryMode::Junk));
        // JUNK mode: never base64
        assert!(!out.contains("cn:: "));
    }

    // ── Group 14: Round-trip tests ────────────────────────────────

    #[test]
    fn roundtrip_ldapvi() {
        use crate::parse::LdapviParser;
        use std::io::Cursor;

        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b"foo");
        add_value(&mut e, "sn", b"bar");

        let mut buf = Vec::new();
        print_ldapvi_entry(&mut buf, &e, Some("add"), BinaryMode::Utf8).unwrap();

        let mut p = LdapviParser::new(Cursor::new(buf.as_slice()));
        let (key, result, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "add");
        assert_eq!(result.dn, "cn=foo,dc=example,dc=com");
        assert!(result.get_attribute("cn").is_some());
        assert!(result.get_attribute("sn").is_some());
    }

    #[test]
    fn roundtrip_ldif() {
        use crate::parseldif::LdifParser;
        use std::io::Cursor;

        let mut e = make_entry("cn=foo,dc=example,dc=com");
        add_value(&mut e, "cn", b"foo");
        add_value(&mut e, "sn", b"bar");

        let mut buf = Vec::new();
        print_ldif_entry(&mut buf, &e, Some("42")).unwrap();

        let mut p = LdifParser::new(Cursor::new(buf.as_slice()));
        let (key, result, _) = p.read_entry(None).unwrap().unwrap();
        assert_eq!(key, "42");
        assert_eq!(result.dn, "cn=foo,dc=example,dc=com");
        assert!(result.get_attribute("cn").is_some());
        assert!(result.get_attribute("sn").is_some());
    }

    // ── Helpers: string classification ────────────────────────────

    #[test]
    fn test_utf8_string_p() {
        assert!(utf8_string_p(b"hello"));
        assert!(utf8_string_p(&[0xc3, 0xa9])); // é
        assert!(!utf8_string_p(&[0x00])); // null
        assert!(!utf8_string_p(&[0xff])); // invalid
    }

    #[test]
    fn test_readable_string_p() {
        assert!(readable_string_p(b"hello"));
        assert!(readable_string_p(b"hello\nworld"));
        assert!(readable_string_p(b"hello\tworld"));
        assert!(!readable_string_p(&[0x01])); // control char
        assert!(!readable_string_p(&[0x00])); // null
    }

    #[test]
    fn test_safe_string_p() {
        assert!(safe_string_p(b"hello"));
        assert!(safe_string_p(b""));
        assert!(!safe_string_p(b" leading"));
        assert!(!safe_string_p(b":colon"));
        assert!(!safe_string_p(b"<angle"));
        assert!(!safe_string_p(b"has\nnewline"));
        assert!(!safe_string_p(b"has\x00null"));
        assert!(!safe_string_p(&[0xc3, 0xa9])); // non-ASCII
    }

    #[test]
    fn test_explode_dn() {
        assert_eq!(
            explode_dn("cn=foo,dc=example,dc=com"),
            vec!["cn=foo", "dc=example", "dc=com"]
        );
        assert_eq!(explode_dn("cn=foo"), vec!["cn=foo"]);
        assert_eq!(
            explode_dn("cn=foo\\,bar,dc=com"),
            vec!["cn=foo\\,bar", "dc=com"]
        );
        let empty: Vec<&str> = vec![];
        assert_eq!(explode_dn(""), empty);
    }
}
