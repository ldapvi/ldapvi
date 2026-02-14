use std::fs;
use std::io::{Cursor, Read, Write};

use ldap3::LdapConn;
use ldapvi::data::{Entry, LdapMod};
use ldapvi::diff::{self, DiffHandler};
use ldapvi::parse::LdapviParser;
use ldapvi::print::{self, BinaryMode};
use ldapvi::schema::{Entroid, Schema};

use crate::arguments::{self, Cmdline, Mode};
use crate::interactive;
use crate::ldap;

// ===========================================================================
// DiffHandler implementations
// ===========================================================================

/// Counts add/delete/modify/rename operations.
struct StatisticsHandler {
    adds: i32,
    deletes: i32,
    modifies: i32,
    renames: i32,
}

impl StatisticsHandler {
    fn new() -> Self {
        StatisticsHandler {
            adds: 0,
            deletes: 0,
            modifies: 0,
            renames: 0,
        }
    }

    fn total(&self) -> i32 {
        self.adds + self.deletes + self.modifies + self.renames
    }

    fn print_summary(&self) {
        fn counter(label: &str, n: i32, color: &str) -> String {
            if n > 0 {
                format!("\x1b[{}m{}: {}\x1b[0m", color, label, n)
            } else {
                format!("{}: {}", label, n)
            }
        }
        eprintln!(
            "{}, {}, {}, {}",
            counter("add", self.adds, "1;32"),
            counter("rename", self.renames, "1;34"),
            counter("modify", self.modifies, "1;33"),
            counter("delete", self.deletes, "1;31"),
        );
    }
}

impl DiffHandler for StatisticsHandler {
    fn handle_add(&mut self, _n: i32, _dn: &str, _mods: &[LdapMod]) -> i32 {
        self.adds += 1;
        0
    }
    fn handle_delete(&mut self, _n: i32, _dn: &str) -> i32 {
        self.deletes += 1;
        0
    }
    fn handle_change(&mut self, _n: i32, _old_dn: &str, _new_dn: &str, _mods: &[LdapMod]) -> i32 {
        self.modifies += 1;
        0
    }
    fn handle_rename(&mut self, _n: i32, _old_dn: &str, _entry: &Entry) -> i32 {
        self.renames += 1;
        0
    }
    fn handle_rename0(
        &mut self,
        _n: i32,
        _old_dn: &str,
        _new_dn: &str,
        _deleteoldrdn: bool,
    ) -> i32 {
        self.renames += 1;
        0
    }
}

/// Commits changes to the LDAP server.
struct LdapCommitHandler<'a> {
    ldap: &'a mut LdapConn,
    continuous: bool,
    errors: Vec<String>,
}

impl<'a> LdapCommitHandler<'a> {
    fn new(ldap: &'a mut LdapConn, continuous: bool) -> Self {
        LdapCommitHandler {
            ldap,
            continuous,
            errors: Vec::new(),
        }
    }
}

impl DiffHandler for LdapCommitHandler<'_> {
    fn handle_add(&mut self, _n: i32, dn: &str, mods: &[LdapMod]) -> i32 {
        match ldap::ldap_add(self.ldap, dn, mods) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ldapvi: {}", e);
                self.errors.push(e);
                if self.continuous {
                    0
                } else {
                    -1
                }
            }
        }
    }

    fn handle_delete(&mut self, _n: i32, dn: &str) -> i32 {
        match ldap::ldap_delete(self.ldap, dn) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ldapvi: {}", e);
                self.errors.push(e);
                if self.continuous {
                    0
                } else {
                    -1
                }
            }
        }
    }

    fn handle_change(&mut self, _n: i32, _old_dn: &str, new_dn: &str, mods: &[LdapMod]) -> i32 {
        match ldap::ldap_modify(self.ldap, new_dn, mods) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ldapvi: {}", e);
                self.errors.push(e);
                if self.continuous {
                    0
                } else {
                    -1
                }
            }
        }
    }

    fn handle_rename(&mut self, _n: i32, old_dn: &str, entry: &Entry) -> i32 {
        let new_dn = &entry.dn;
        // Extract new RDN from new DN
        let new_rdn = first_rdn(new_dn);
        let old_rdn = first_rdn(old_dn);

        // Determine new superior if parent changed
        let old_parent = parent_dn(old_dn);
        let new_parent = parent_dn(new_dn);
        let new_superior = if old_parent != new_parent {
            Some(new_parent.as_str())
        } else {
            None
        };

        // Determine deleteoldrdn by checking if old RDN values are still present
        let mut deleteoldrdn = new_rdn != old_rdn;

        // Use validate_rename logic: if old RDN values are still present, don't delete
        if deleteoldrdn {
            let mut clean_clone = Entry::new(old_dn.to_string());
            let mut data_clone = entry.clone();
            // Populate clean_clone with the RDN values
            diff::frob_rdn(&mut clean_clone, old_dn, diff::FrobMode::Add);
            let mut dor = false;
            if diff::validate_rename(&mut clean_clone, &mut data_clone, &mut dor) == 0 {
                deleteoldrdn = dor;
            }
        }

        match ldap::ldap_rename(self.ldap, old_dn, new_rdn, new_superior, deleteoldrdn) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ldapvi: {}", e);
                self.errors.push(e);
                if self.continuous {
                    0
                } else {
                    -1
                }
            }
        }
    }

    fn handle_rename0(&mut self, _n: i32, old_dn: &str, new_dn: &str, deleteoldrdn: bool) -> i32 {
        let new_rdn = first_rdn(new_dn);
        let old_parent = parent_dn(old_dn);
        let new_parent = parent_dn(new_dn);
        let new_superior = if old_parent != new_parent {
            Some(new_parent.as_str())
        } else {
            None
        };

        match ldap::ldap_rename(self.ldap, old_dn, new_rdn, new_superior, deleteoldrdn) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ldapvi: {}", e);
                self.errors.push(e);
                if self.continuous {
                    0
                } else {
                    -1
                }
            }
        }
    }
}

/// Prints changes as LDIF.
struct LdifPrintHandler<'a> {
    w: &'a mut dyn Write,
}

impl DiffHandler for LdifPrintHandler<'_> {
    fn handle_add(&mut self, _n: i32, dn: &str, mods: &[LdapMod]) -> i32 {
        let _ = print::print_ldif_add(self.w, dn, mods);
        0
    }
    fn handle_delete(&mut self, _n: i32, dn: &str) -> i32 {
        let _ = print::print_ldif_delete(self.w, dn);
        0
    }
    fn handle_change(&mut self, _n: i32, _old_dn: &str, new_dn: &str, mods: &[LdapMod]) -> i32 {
        let _ = print::print_ldif_modify(self.w, new_dn, mods);
        0
    }
    fn handle_rename(&mut self, _n: i32, old_dn: &str, entry: &Entry) -> i32 {
        // Determine deleteoldrdn
        let mut clean_clone = Entry::new(old_dn.to_string());
        let mut data_clone = entry.clone();
        diff::frob_rdn(&mut clean_clone, old_dn, diff::FrobMode::Add);
        let mut deleteoldrdn = false;
        let _ = diff::validate_rename(&mut clean_clone, &mut data_clone, &mut deleteoldrdn);
        let _ = print::print_ldif_rename(self.w, old_dn, &entry.dn, deleteoldrdn);
        0
    }
    fn handle_rename0(&mut self, _n: i32, old_dn: &str, new_dn: &str, deleteoldrdn: bool) -> i32 {
        let _ = print::print_ldif_rename(self.w, old_dn, new_dn, deleteoldrdn);
        0
    }
}

/// Prints changes in ldapvi (vdif) format.
struct VdifPrintHandler<'a> {
    w: &'a mut dyn Write,
    mode: BinaryMode,
}

impl DiffHandler for VdifPrintHandler<'_> {
    fn handle_add(&mut self, _n: i32, dn: &str, mods: &[LdapMod]) -> i32 {
        let _ = print::print_ldapvi_add(self.w, dn, mods, self.mode);
        0
    }
    fn handle_delete(&mut self, _n: i32, dn: &str) -> i32 {
        let _ = print::print_ldapvi_delete(self.w, dn, self.mode);
        0
    }
    fn handle_change(&mut self, _n: i32, _old_dn: &str, new_dn: &str, mods: &[LdapMod]) -> i32 {
        let _ = print::print_ldapvi_modify(self.w, new_dn, mods, self.mode);
        0
    }
    fn handle_rename(&mut self, _n: i32, old_dn: &str, entry: &Entry) -> i32 {
        let mut clean_clone = Entry::new(old_dn.to_string());
        let mut data_clone = entry.clone();
        diff::frob_rdn(&mut clean_clone, old_dn, diff::FrobMode::Add);
        let mut deleteoldrdn = false;
        let _ = diff::validate_rename(&mut clean_clone, &mut data_clone, &mut deleteoldrdn);
        let _ = print::print_ldapvi_rename(self.w, old_dn, &entry.dn, deleteoldrdn, self.mode);
        0
    }
    fn handle_rename0(&mut self, _n: i32, old_dn: &str, new_dn: &str, deleteoldrdn: bool) -> i32 {
        let _ = print::print_ldapvi_rename(self.w, old_dn, new_dn, deleteoldrdn, self.mode);
        0
    }
}

// ===========================================================================
// DN helpers
// ===========================================================================

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

fn parent_dn(dn: &str) -> String {
    let rdn = first_rdn(dn);
    if rdn.len() < dn.len() {
        dn[rdn.len() + 1..].to_string()
    } else {
        String::new()
    }
}

// ===========================================================================
// Analysis and commit
// ===========================================================================

enum AnalysisResult {
    NoChanges,
    Changes(StatisticsHandler),
    ParseError(u64),
}

fn analyze_changes(clean_data: &[u8], data_data: &[u8], offsets: &[i64]) -> AnalysisResult {
    let mut clean_parser = LdapviParser::new(Cursor::new(clean_data));
    let mut data_parser = LdapviParser::new(Cursor::new(data_data));
    let mut stats = StatisticsHandler::new();
    let mut offsets = offsets.to_vec();

    let rc = diff::compare_streams(
        &mut clean_parser,
        &mut data_parser,
        &mut stats,
        &mut offsets,
    );

    match rc {
        0 => {
            if stats.total() == 0 {
                AnalysisResult::NoChanges
            } else {
                AnalysisResult::Changes(stats)
            }
        }
        _ => {
            // Get error position from data parser
            let pos = data_parser.stream_position().unwrap_or(0);
            AnalysisResult::ParseError(pos)
        }
    }
}

fn commit_changes(
    ldap: &mut LdapConn,
    clean_data: &[u8],
    data_data: &[u8],
    offsets: &[i64],
    continuous: bool,
) -> Result<(), String> {
    let mut clean_parser = LdapviParser::new(Cursor::new(clean_data));
    let mut data_parser = LdapviParser::new(Cursor::new(data_data));
    let mut handler = LdapCommitHandler::new(ldap, continuous);
    let mut offsets = offsets.to_vec();

    let rc = diff::compare_streams(
        &mut clean_parser,
        &mut data_parser,
        &mut handler,
        &mut offsets,
    );

    if rc == -2 || !handler.errors.is_empty() {
        Err(handler.errors.join("; "))
    } else if rc == -1 {
        Err("parse error during commit".to_string())
    } else {
        Ok(())
    }
}

fn write_ldif_changes(clean_data: &[u8], data_data: &[u8], offsets: &[i64], out: &mut dyn Write) {
    let _ = writeln!(out, "version: 1");
    let mut clean_parser = LdapviParser::new(Cursor::new(clean_data));
    let mut data_parser = LdapviParser::new(Cursor::new(data_data));
    let mut handler = LdifPrintHandler { w: out };
    let mut offsets = offsets.to_vec();

    diff::compare_streams(
        &mut clean_parser,
        &mut data_parser,
        &mut handler,
        &mut offsets,
    );
}

fn write_vdif_changes(
    clean_data: &[u8],
    data_data: &[u8],
    offsets: &[i64],
    out: &mut dyn Write,
    mode: BinaryMode,
) {
    let _ = writeln!(out, "version: ldapvi");
    let mut clean_parser = LdapviParser::new(Cursor::new(clean_data));
    let mut data_parser = LdapviParser::new(Cursor::new(data_data));
    let mut handler = VdifPrintHandler { w: out, mode };
    let mut offsets = offsets.to_vec();

    diff::compare_streams(
        &mut clean_parser,
        &mut data_parser,
        &mut handler,
        &mut offsets,
    );
}

/// Forget deletions: rewrite the data file to include any entries that
/// were deleted (present in clean but missing from data).
fn forget_deletions(clean_data: &[u8], data_path: &str, offsets: &[i64], mode: BinaryMode) {
    let data_data = fs::read(data_path).unwrap_or_default();

    // Parse data to find which keys are present
    let mut data_parser = LdapviParser::new(Cursor::new(data_data.as_slice()));
    let mut seen_keys = std::collections::HashSet::new();
    while let Ok(Some((key, _pos))) = data_parser.peek_entry(None) {
        if let Ok(n) = key.parse::<usize>() {
            seen_keys.insert(n);
        }
        let _ = data_parser.skip_entry(None);
    }

    // Append missing entries from clean to the data file
    let mut clean_parser = LdapviParser::new(Cursor::new(clean_data));
    let mut appended = Vec::new();
    for (i, &offset) in offsets.iter().enumerate() {
        if seen_keys.contains(&i) {
            continue;
        }
        // This entry was deleted; read it from clean and append
        if let Ok(Some((_key, entry, _pos))) = clean_parser.read_entry(Some(offset as u64)) {
            print::print_ldapvi_entry(&mut appended, &entry, Some(&i.to_string()), mode)
                .unwrap_or(());
        }
    }

    if !appended.is_empty() {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(data_path)
            .expect("failed to open data file for appending");
        f.write_all(&appended)
            .expect("failed to append to data file");
    }
}

/// Set up an Entroid for a given entry by requesting its objectClasses
/// and computing the MUST/MAY attributes.
fn entroid_set_entry<'a>(entroid: &mut Entroid<'a>, entry: &Entry) {
    entroid.reset();

    // Find objectClass attribute (case-insensitive)
    for attr in &entry.attributes {
        if attr.ad.eq_ignore_ascii_case("objectClass") {
            for value in &attr.values {
                let class_name = String::from_utf8_lossy(value);
                entroid.request_class(&class_name);
            }
        }
    }

    if let Err(e) = entroid.compute() {
        entroid.comment.push_str(&format!("### {}\n", e));
    }
}

/// Rewrite the data file with schema comment annotations.
fn rewrite_with_schema_comments(data_path: &str, schema: &Schema, mode: BinaryMode) {
    let data = fs::read(data_path).unwrap_or_default();
    let mut parser = LdapviParser::new(Cursor::new(data.as_slice()));
    let mut output = Vec::new();
    let mut entroid = Entroid::new(schema);

    while let Ok(Some((key, entry, _pos))) = parser.read_entry(None) {
        entroid_set_entry(&mut entroid, &entry);
        print::print_ldapvi_entry_annotated(&mut output, &entry, Some(&key), mode, &mut entroid)
            .unwrap_or(());
    }

    fs::write(data_path, output).expect("failed to rewrite data file");
}

/// Skip the first entry in the data file.
/// If data has entries, cut the first one from the data file and mark its offset as -1.
/// If data is empty, remove the first positive offset from the array (skip a deletion).
fn skip_first_entry(data_path: &str, offsets: &mut [i64]) {
    let data = fs::read(data_path).unwrap_or_default();
    let mut parser = LdapviParser::new(Cursor::new(data.as_slice()));

    match parser.skip_entry(None) {
        Ok(Some(key)) => {
            let end_pos = parser.stream_position().unwrap_or(0) as usize;

            // Cut the data file: remove everything before end_pos
            let remaining = data[end_pos..].to_vec();
            fs::write(data_path, remaining).expect("failed to rewrite data file");

            // Mark the offset as -1 if it's a numeric key
            if let Ok(n) = key.parse::<usize>() {
                if n < offsets.len() {
                    offsets[n] = -1;
                }
            }
        }
        _ => {
            // No more entries in data — skip a deletion by removing the first
            // positive offset from the array
            if let Some(pos) = offsets.iter().position(|&o| o >= 0) {
                offsets[pos] = -1;
            }
        }
    }
}

fn save_ldif_to_file(clean_data: &[u8], data_data: &[u8], offsets: &[i64]) -> String {
    // Create LDIF file in the current directory
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let filename = format!(",ldapvi-{}.ldif", timestamp);

    let mut f = fs::File::create(&filename).expect("failed to create LDIF file");
    write_ldif_changes(clean_data, data_data, offsets, &mut f);
    filename
}

fn binary_mode(cmdline: &Cmdline) -> BinaryMode {
    match cmdline.encoding.as_deref() {
        Some("ascii") => BinaryMode::Ascii,
        Some("binary") => BinaryMode::Junk,
        _ => BinaryMode::Utf8,
    }
}

// ===========================================================================
// Main edit loop
// ===========================================================================

const ACTION_HELP: &str = "Commands:
  y -- commit changes
  Y -- commit, ignoring all errors
  q -- save changes as LDIF and quit
  Q -- discard changes and quit
  v -- view changes as LDIF change records
  V -- view changes as ldapvi change records
  e -- open editor again
  b -- show login dialog and rebind
  B -- toggle SASL
  * -- set SASL mechanism
  r -- reconnect to server
  s -- skip one entry
  f -- forget deletions
  + -- rewrite file to include schema comments
  ? -- this help";

const PARSE_ERROR_HELP: &str = "Commands:
  e -- re-edit (cursor at error)
  Q -- discard changes and quit
  ? -- this help";

fn do_edit(conn: &mut LdapConn, cmdline: &Cmdline) {
    let mode = binary_mode(cmdline);

    // Create temp directory
    let tmpdir = tempfile::tempdir().expect("failed to create temp directory");
    let clean_path = tmpdir.path().join("clean");
    let data_path = tmpdir.path().join("data");

    // Search and write to clean file
    let mut clean_file = fs::File::create(&clean_path).expect("failed to create clean file");
    let offsets = ldap::search_to_file(conn, cmdline, &mut clean_file).unwrap_or_else(|e| {
        eprintln!("ldapvi: {}", e);
        std::process::exit(1);
    });
    drop(clean_file);

    // Copy clean to data
    fs::copy(&clean_path, &data_path).expect("failed to copy clean to data");

    let clean_data = fs::read(&clean_path).expect("failed to read clean file");
    let data_path_str = data_path.to_str().unwrap().to_string();
    let mut offsets = offsets;

    // First edit
    interactive::edit(&data_path_str, None);

    // Main loop
    loop {
        let data_data = fs::read(&data_path).expect("failed to read data file");

        match analyze_changes(&clean_data, &data_data, &offsets) {
            AnalysisResult::NoChanges => {
                println!("No changes.");
                std::process::exit(0);
            }
            AnalysisResult::ParseError(pos) => {
                let line = interactive::line_number(&data_path_str, pos);
                let c = interactive::choose("What now?", "eQ?", PARSE_ERROR_HELP);
                match c {
                    'e' => {
                        interactive::edit(&data_path_str, line);
                        continue;
                    }
                    'Q' => {
                        std::process::exit(0);
                    }
                    '?' => {
                        eprintln!("{}", PARSE_ERROR_HELP);
                        continue;
                    }
                    _ => continue,
                }
            }
            AnalysisResult::Changes(stats) => {
                stats.print_summary();

                loop {
                    let c = interactive::choose("Action?", "yYqQvVebB*rsf+?", ACTION_HELP);
                    match c {
                        'y' => {
                            let data_data = fs::read(&data_path).expect("failed to read data file");
                            match commit_changes(conn, &clean_data, &data_data, &offsets, false) {
                                Ok(()) => {
                                    println!("Done.");
                                    std::process::exit(0);
                                }
                                Err(_e) => {
                                    // Error already printed by handler; loop back to Action?
                                    continue;
                                }
                            }
                        }
                        'Y' => {
                            let data_data = fs::read(&data_path).expect("failed to read data file");
                            match commit_changes(conn, &clean_data, &data_data, &offsets, true) {
                                Ok(()) => {
                                    println!("Done.");
                                    std::process::exit(0);
                                }
                                Err(_e) => {
                                    continue;
                                }
                            }
                        }
                        'e' => {
                            interactive::edit(&data_path_str, None);
                            break; // back to outer loop to re-analyze
                        }
                        'q' => {
                            let data_data = fs::read(&data_path).expect("failed to read data file");
                            let filename = save_ldif_to_file(&clean_data, &data_data, &offsets);
                            println!("Your changes have been saved to {}", filename);
                            std::process::exit(0);
                        }
                        'Q' => {
                            std::process::exit(0);
                        }
                        'v' => {
                            // Write LDIF to temp file and view
                            let data_data = fs::read(&data_path).expect("failed to read data file");
                            let view_path = tmpdir.path().join("view.ldif");
                            let mut f =
                                fs::File::create(&view_path).expect("failed to create view file");
                            write_ldif_changes(&clean_data, &data_data, &offsets, &mut f);
                            drop(f);
                            interactive::view(view_path.to_str().unwrap());
                            continue;
                        }
                        'V' => {
                            // Write vdif to temp file and view
                            let data_data = fs::read(&data_path).expect("failed to read data file");
                            let view_path = tmpdir.path().join("view.vdif");
                            let mut f =
                                fs::File::create(&view_path).expect("failed to create view file");
                            write_vdif_changes(&clean_data, &data_data, &offsets, &mut f, mode);
                            drop(f);
                            interactive::view(view_path.to_str().unwrap());
                            continue;
                        }
                        'b' => {
                            let dn = interactive::read_line("Bind DN: ");
                            let password = interactive::read_password("Password: ");
                            match ldap::simple_bind(conn, &dn, &password) {
                                Ok(()) => {
                                    eprintln!("Bound as {}.", dn);
                                }
                                Err(e) => {
                                    eprintln!("bind: {}", e);
                                }
                            }
                            continue;
                        }
                        'B' => {
                            eprintln!("SASL not yet supported.");
                            continue;
                        }
                        '*' => {
                            eprintln!("SASL not yet supported.");
                            continue;
                        }
                        'r' => {
                            match ldap::do_connect(cmdline) {
                                Ok(new_conn) => {
                                    *conn = new_conn;
                                    let server = cmdline.server.as_deref().unwrap_or("localhost");
                                    eprintln!("Connected to {}.", server);
                                }
                                Err(e) => {
                                    eprintln!("reconnect: {}", e);
                                }
                            }
                            continue;
                        }
                        's' => {
                            skip_first_entry(&data_path_str, &mut offsets);
                            break; // back to outer loop to re-analyze
                        }
                        'f' => {
                            forget_deletions(&clean_data, &data_path_str, &offsets, mode);
                            break; // back to outer loop to re-analyze
                        }
                        '+' => {
                            match ldap::read_schema(conn) {
                                Ok(schema) => {
                                    rewrite_with_schema_comments(&data_path_str, &schema, mode);
                                    interactive::edit(&data_path_str, None);
                                    break; // back to outer loop to re-analyze
                                }
                                Err(e) => {
                                    eprintln!("Error: {}", e);
                                    continue;
                                }
                            }
                        }
                        '?' => {
                            eprintln!("{}", ACTION_HELP);
                            continue;
                        }
                        _ => continue,
                    }
                }
            }
        }
    }
}

// ===========================================================================
// --in mode
// ===========================================================================

fn do_in(conn: &mut LdapConn, cmdline: &Cmdline) {
    let input: Box<dyn Read> = match &cmdline.in_file {
        Some(path) => Box::new(fs::File::open(path).unwrap_or_else(|e| {
            eprintln!("ldapvi: open {}: {}", path, e);
            std::process::exit(1);
        })),
        None => Box::new(std::io::stdin()),
    };

    // Read all input, parse as ldapvi format, apply each changerecord
    let mut data = Vec::new();
    {
        let mut input = input;
        input.read_to_end(&mut data).unwrap_or_else(|e| {
            eprintln!("ldapvi: read: {}", e);
            std::process::exit(1);
        });
    }

    let mut parser = LdapviParser::new(Cursor::new(data.as_slice()));
    let empty_clean = Vec::new();
    let mut clean_parser = LdapviParser::new(Cursor::new(empty_clean.as_slice()));
    let mut handler = LdapCommitHandler::new(conn, cmdline.continuous);
    let mut offsets: Vec<i64> = Vec::new();

    let rc = diff::compare_streams(&mut clean_parser, &mut parser, &mut handler, &mut offsets);

    if rc != 0 || !handler.errors.is_empty() {
        eprintln!("ldapvi: some operations failed");
        std::process::exit(1);
    }
}

// ===========================================================================
// --delete mode
// ===========================================================================

fn do_delete(conn: &mut LdapConn, cmdline: &Cmdline) {
    for dn in &cmdline.delete_dns {
        ldap::ldap_delete(conn, dn).unwrap_or_else(|e| {
            eprintln!("ldapvi: {}", e);
            if !cmdline.continuous {
                std::process::exit(1);
            }
        });
    }
}

// ===========================================================================
// --rename / --modrdn mode
// ===========================================================================

fn do_rename(conn: &mut LdapConn, cmdline: &Cmdline) {
    let old_dn = cmdline.rename_old.as_deref().unwrap_or_else(|| {
        eprintln!("ldapvi: --rename requires old and new DN");
        std::process::exit(1);
    });
    let new_dn = cmdline.rename_new.as_deref().unwrap_or_else(|| {
        eprintln!("ldapvi: --rename requires old and new DN");
        std::process::exit(1);
    });

    let new_rdn = first_rdn(new_dn);
    let old_parent = parent_dn(old_dn);
    let new_parent = parent_dn(new_dn);
    let new_superior = if old_parent != new_parent {
        Some(new_parent.as_str())
    } else {
        None
    };

    ldap::ldap_rename(conn, old_dn, new_rdn, new_superior, cmdline.deleteoldrdn).unwrap_or_else(
        |e| {
            eprintln!("ldapvi: {}", e);
            std::process::exit(1);
        },
    );
}

fn do_modrdn(conn: &mut LdapConn, cmdline: &Cmdline) {
    let old_dn = cmdline.rename_old.as_deref().unwrap_or_else(|| {
        eprintln!("ldapvi: --modrdn requires old DN and new RDN");
        std::process::exit(1);
    });
    let new_rdn = cmdline.rename_new.as_deref().unwrap_or_else(|| {
        eprintln!("ldapvi: --modrdn requires old DN and new RDN");
        std::process::exit(1);
    });

    ldap::ldap_rename(conn, old_dn, new_rdn, None, cmdline.deleteoldrdn).unwrap_or_else(|e| {
        eprintln!("ldapvi: {}", e);
        std::process::exit(1);
    });
}

// ===========================================================================
// Entry point
// ===========================================================================

pub fn run() {
    let mut cmdline = match arguments::parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ldapvi: {}", e);
            std::process::exit(1);
        }
    };

    let mut conn = ldap::do_connect(&cmdline).unwrap_or_else(|e| {
        eprintln!("ldapvi: {}", e);
        std::process::exit(1);
    });

    // Discover naming contexts if requested
    if cmdline.discover && cmdline.basedns.is_empty() {
        match ldap::discover_naming_contexts(&mut conn) {
            Ok(contexts) => {
                cmdline.basedns = contexts;
            }
            Err(e) => {
                eprintln!("ldapvi: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Default base DN if none specified
    if cmdline.basedns.is_empty() {
        cmdline.basedns.push(String::new());
    }

    match cmdline.mode {
        Mode::Out => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            ldap::search_and_print(&mut conn, &cmdline, &mut out).unwrap_or_else(|e| {
                eprintln!("ldapvi: {}", e);
                std::process::exit(1);
            });
        }
        Mode::Edit => {
            do_edit(&mut conn, &cmdline);
        }
        Mode::In => {
            do_in(&mut conn, &cmdline);
        }
        Mode::Delete => {
            do_delete(&mut conn, &cmdline);
        }
        Mode::Rename => {
            do_rename(&mut conn, &cmdline);
        }
        Mode::Modrdn => {
            do_modrdn(&mut conn, &cmdline);
        }
    }

    let _ = conn.unbind();
}
