use std::collections::HashSet;
use std::io::{Seek, Write};

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};

use crate::arguments::Cmdline;
use ldapvi::data::{Attribute, Entry, LdapMod, ModOp};
use ldapvi::print::{self, BinaryMode};
use ldapvi::schema::{self, Schema};

pub fn do_connect(cmdline: &Cmdline) -> Result<LdapConn, String> {
    let url = match &cmdline.server {
        Some(s) => {
            if s.contains("://") {
                s.clone()
            } else {
                format!("ldap://{}", s)
            }
        }
        None => "ldap://localhost".to_string(),
    };

    let mut settings = LdapConnSettings::new();

    // -Z / --starttls: upgrade ldap:// to TLS via StartTLS extended op
    if cmdline.starttls {
        settings = settings.set_starttls(true);
    }

    // --tls mode
    match cmdline.tls.as_deref() {
        Some("never") | Some("allow") | Some("try") => {
            settings = settings.set_no_tls_verify(true);
        }
        Some("strict") => {
            // default: verify certificates
        }
        Some(other) => {
            return Err(format!(
                "invalid --tls mode: {} (expected never, allow, try, strict)",
                other
            ));
        }
        None => {}
    }

    let mut conn = LdapConn::with_settings(settings, &url)
        .map_err(|e| format!("connect to {}: {}", url, e))?;

    if let (Some(user), Some(password)) = (&cmdline.user, &cmdline.password) {
        let result = conn
            .simple_bind(user, password)
            .map_err(|e| format!("bind: {}", e))?;
        if result.rc != 0 {
            return Err(format!("bind failed: {} {}", result.rc, result.text));
        }
    }

    Ok(conn)
}

fn search_entry_to_entry(se: SearchEntry) -> Entry {
    let mut attributes = Vec::new();

    for (ad, values) in se.attrs {
        attributes.push(Attribute {
            ad,
            values: values.into_iter().map(|v| v.into_bytes()).collect(),
        });
    }

    for (ad, values) in se.bin_attrs {
        attributes.push(Attribute { ad, values });
    }

    // Sort attributes by name for deterministic output.
    // LDAP libraries return attributes in HashMap order which varies.
    attributes.sort_by(|a, b| a.ad.cmp(&b.ad));

    Entry {
        dn: se.dn,
        attributes,
    }
}

fn binary_mode(cmdline: &Cmdline) -> BinaryMode {
    match cmdline.encoding.as_deref() {
        Some("ascii") => BinaryMode::Ascii,
        Some("binary") => BinaryMode::Junk,
        _ => BinaryMode::Utf8,
    }
}

pub fn search_and_print(
    ldap: &mut LdapConn,
    cmdline: &Cmdline,
    out: &mut dyn Write,
) -> Result<(), String> {
    let attr_refs: Vec<&str> = cmdline.attrs.iter().map(|s| s.as_str()).collect();

    for base in &cmdline.basedns {
        let (entries, _result) = ldap
            .search(base, cmdline.scope, &cmdline.filter, &attr_refs)
            .map_err(|e| format!("search: {}", e))?
            .success()
            .map_err(|e| format!("search: {}", e))?;

        for raw_entry in entries {
            let se = SearchEntry::construct(raw_entry);
            let entry = search_entry_to_entry(se);

            if cmdline.ldif {
                print::print_ldif_entry(out, &entry, None).map_err(|e| format!("write: {}", e))?;
            } else {
                print::print_ldapvi_entry(out, &entry, None, binary_mode(cmdline))
                    .map_err(|e| format!("write: {}", e))?;
            }
        }
    }

    Ok(())
}

/// Search and write results to a file in ldapvi format, returning entry offsets.
pub fn search_to_file<W: Write + Seek>(
    ldap: &mut LdapConn,
    cmdline: &Cmdline,
    out: &mut W,
) -> Result<Vec<i64>, String> {
    let attr_refs: Vec<&str> = cmdline.attrs.iter().map(|s| s.as_str()).collect();
    let mode = binary_mode(cmdline);
    let mut offsets = Vec::new();

    // File header: Emacs coding cookie + vim modeline for UTF-8.
    // Note: vim's "encoding" is disallowed in modelines;
    // use "fileencoding" instead.
    if mode == BinaryMode::Utf8 && !cmdline.ldif {
        writeln!(out, "# -*- coding: utf-8 -*- vim:fileencoding=utf-8:")
            .map_err(|e| format!("write: {}", e))?;
    }
    if cmdline.ldif {
        writeln!(out, "version: 1").map_err(|e| format!("write: {}", e))?;
    }

    let mut entry_num = 0usize;
    for base in &cmdline.basedns {
        let (entries, _result) = ldap
            .search(base, cmdline.scope, &cmdline.filter, &attr_refs)
            .map_err(|e| format!("search: {}", e))?
            .success()
            .map_err(|e| format!("search: {}", e))?;

        for raw_entry in entries {
            let pos = out.stream_position().map_err(|e| format!("tell: {}", e))?;
            offsets.push(pos as i64);

            let se = SearchEntry::construct(raw_entry);
            let entry = search_entry_to_entry(se);

            let key = entry_num.to_string();
            print::print_ldapvi_entry(out, &entry, Some(&key), mode)
                .map_err(|e| format!("write: {}", e))?;
            entry_num += 1;
        }
    }

    Ok(offsets)
}

/// Discover naming contexts from the root DSE.
pub fn discover_naming_contexts(ldap: &mut LdapConn) -> Result<Vec<String>, String> {
    let (entries, _) = ldap
        .search("", Scope::Base, "(objectclass=*)", vec!["namingContexts"])
        .map_err(|e| format!("search root DSE: {}", e))?
        .success()
        .map_err(|e| format!("search root DSE: {}", e))?;

    let mut contexts = Vec::new();
    for raw_entry in entries {
        let se = SearchEntry::construct(raw_entry);
        // LDAP attribute names are case-insensitive; servers may return
        // "namingContexts", "namingcontexts", etc.
        for (key, values) in &se.attrs {
            if key.eq_ignore_ascii_case("namingContexts") {
                for v in values {
                    contexts.push(v.clone());
                }
            }
        }
    }
    Ok(contexts)
}

/// Convert our LdapMod values to ldap3 Mod format.
fn ldapmod_to_ldap3_mod(m: &LdapMod) -> ldap3::Mod<Vec<u8>> {
    let attr = m.attr.clone().into_bytes();
    let vals: HashSet<Vec<u8>> = m.values.iter().cloned().collect();
    match m.op {
        ModOp::Add => ldap3::Mod::Add(attr, vals),
        ModOp::Delete => ldap3::Mod::Delete(attr, vals),
        ModOp::Replace => ldap3::Mod::Replace(attr, vals),
    }
}

/// Apply a modify operation to the LDAP server.
pub fn ldap_modify(ldap: &mut LdapConn, dn: &str, mods: &[LdapMod]) -> Result<(), String> {
    let ldap3_mods: Vec<ldap3::Mod<Vec<u8>>> = mods.iter().map(ldapmod_to_ldap3_mod).collect();
    let result = ldap
        .modify(dn, ldap3_mods)
        .map_err(|e| format!("modify {}: {}", dn, e))?;
    if result.rc != 0 {
        return Err(format!("modify {}: {} {}", dn, result.rc, result.text));
    }
    Ok(())
}

/// Apply an add operation to the LDAP server.
pub fn ldap_add(ldap: &mut LdapConn, dn: &str, mods: &[LdapMod]) -> Result<(), String> {
    // Convert mods (all should be Add) to attribute vec for ldap3::add
    let mut attr_map: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = Vec::new();
    for m in mods {
        let attr = m.attr.clone().into_bytes();
        let vals: HashSet<Vec<u8>> = m.values.iter().cloned().collect();
        // Check if we already have this attribute
        if let Some(existing) = attr_map.iter_mut().find(|(a, _)| *a == attr) {
            existing.1.extend(vals);
        } else {
            attr_map.push((attr, vals));
        }
    }
    let result = ldap
        .add(dn, attr_map)
        .map_err(|e| format!("add {}: {}", dn, e))?;
    if result.rc != 0 {
        return Err(format!("add {}: {} {}", dn, result.rc, result.text));
    }
    Ok(())
}

/// Apply a delete operation to the LDAP server.
pub fn ldap_delete(ldap: &mut LdapConn, dn: &str) -> Result<(), String> {
    let result = ldap
        .delete(dn)
        .map_err(|e| format!("delete {}: {}", dn, e))?;
    if result.rc != 0 {
        return Err(format!("delete {}: {} {}", dn, result.rc, result.text));
    }
    Ok(())
}

/// Rename an entry (modifyDN).
pub fn ldap_rename(
    ldap: &mut LdapConn,
    old_dn: &str,
    new_rdn: &str,
    new_superior: Option<&str>,
    delete_old_rdn: bool,
) -> Result<(), String> {
    let result = ldap
        .modifydn(old_dn, new_rdn, delete_old_rdn, new_superior)
        .map_err(|e| format!("rename {}: {}", old_dn, e))?;
    if result.rc != 0 {
        return Err(format!("rename {}: {} {}", old_dn, result.rc, result.text));
    }
    Ok(())
}

/// Perform a simple bind on an existing connection.
pub fn simple_bind(ldap: &mut LdapConn, dn: &str, password: &str) -> Result<(), String> {
    let result = ldap
        .simple_bind(dn, password)
        .map_err(|e| format!("bind: {}", e))?;
    if result.rc != 0 {
        return Err(format!("bind failed: {} {}", result.rc, result.text));
    }
    Ok(())
}

/// Read the LDAP schema from the server.
///
/// 1. Query root DSE for subschemaSubentry
/// 2. Search that DN for objectClasses and attributeTypes
/// 3. Parse and build a Schema
pub fn read_schema(ldap: &mut LdapConn) -> Result<Schema, String> {
    // Step 1: Find subschemaSubentry from root DSE
    let (entries, _) = ldap
        .search(
            "",
            Scope::Base,
            "(objectclass=*)",
            vec!["subschemaSubentry"],
        )
        .map_err(|e| format!("search root DSE: {}", e))?
        .success()
        .map_err(|e| format!("search root DSE: {}", e))?;

    let mut subschema_dn = String::new();
    for raw_entry in entries {
        let se = SearchEntry::construct(raw_entry);
        for (key, values) in &se.attrs {
            if key.eq_ignore_ascii_case("subschemaSubentry") {
                if let Some(v) = values.first() {
                    subschema_dn = v.clone();
                }
            }
        }
    }

    if subschema_dn.is_empty() {
        // Fallback: try cn=Subschema (common default)
        subschema_dn = "cn=Subschema".to_string();
    }

    // Step 2: Read objectClasses and attributeTypes from subschema entry
    let (entries, _) = ldap
        .search(
            &subschema_dn,
            Scope::Base,
            "(objectclass=*)",
            vec!["objectClasses", "attributeTypes"],
        )
        .map_err(|e| format!("search schema {}: {}", subschema_dn, e))?
        .success()
        .map_err(|e| format!("search schema {}: {}", subschema_dn, e))?;

    let mut s = Schema::new();

    for raw_entry in entries {
        let se = SearchEntry::construct(raw_entry);
        for (key, values) in &se.attrs {
            if key.eq_ignore_ascii_case("objectClasses") {
                for v in values {
                    if let Ok(cls) = schema::parse_objectclass(v) {
                        s.add_objectclass(cls);
                    }
                }
            }
            if key.eq_ignore_ascii_case("attributeTypes") {
                for v in values {
                    if let Ok(at) = schema::parse_attributetype(v) {
                        s.add_attributetype(at);
                    }
                }
            }
        }
    }

    Ok(s)
}
