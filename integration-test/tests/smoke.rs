use std::fs;
use std::io::Write;
use std::process::Command;
use std::sync::{Mutex, Once};
use test_driver::TestSession;

const PORT: u16 = 3390; // different from test-ldap.sh's 3389

fn image() -> String {
    std::env::var("LDAPVI_TEST_IMAGE").unwrap_or_else(|_| "ldapvi-test-slapd".into())
}

fn container() -> String {
    format!("ldapvi-inttest-{}", image().replace("ldapvi-test-", ""))
}

fn target_dir() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../target/debug")
}

fn test_ldapvi_binary() -> String {
    format!("{}/test-ldapvi", target_dir())
}

fn ldapvi_binary() -> String {
    format!("{}/ldapvi", target_dir())
}

fn ldap_url() -> String {
    format!("ldap://localhost:{PORT}")
}

/// Search LDAP using ldapvi --ldapsearch and return stdout.
fn ldapsearch(filter: &str) -> String {
    let output = Command::new(ldapvi_binary())
        .args([
            "--ldapsearch",
            "--bind",
            "simple",
            "-h",
            &ldap_url(),
            "-D",
            "cn=admin,dc=example,dc=com",
            "-w",
            "secret",
            "-b",
            "dc=example,dc=com",
            filter,
        ])
        .output()
        .expect("ldapvi --ldapsearch failed");
    assert!(output.status.success(), "ldapvi --ldapsearch failed");
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn ldapsearch_test_user() -> String {
    ldapsearch("(cn=Test User)")
}

/// Common args for authenticated bind against the test LDAP.
fn bind_args() -> Vec<String> {
    vec![
        "--bind".into(),
        "simple".into(),
        "-h".into(),
        ldap_url(),
        "-D".into(),
        "cn=admin,dc=example,dc=com".into(),
        "-w".into(),
        "secret".into(),
        "-b".into(),
        "dc=example,dc=com".into(),
    ]
}

/// Spawn test-ldapvi with a given search filter.
fn spawn_session(filter: &str) -> TestSession {
    let mut args: Vec<String> = bind_args();
    args.push(filter.into());
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    TestSession::spawn(&test_ldapvi_binary(), &arg_refs, &[]).expect("failed to spawn test-ldapvi")
}

/// Spawn test-ldapvi with a given search filter and working directory.
fn spawn_session_in(filter: &str, cwd: &str) -> TestSession {
    let mut args: Vec<String> = bind_args();
    args.push(filter.into());
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    TestSession::spawn_in(&test_ldapvi_binary(), &arg_refs, &[], Some(cwd))
        .expect("failed to spawn test-ldapvi")
}

fn spawn_test_session() -> TestSession {
    spawn_session("(cn=Test User)")
}

/// Ensure an inetOrgPerson entry with the given cn exists.
fn ensure_entry(cn: &str) {
    if ldapsearch(&format!("(cn={cn})")).contains(&format!("cn: {cn}")) {
        return;
    }
    let mut session = spawn_session("(objectClass=*)");
    session.expect_edit(|path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(f, "\nadd cn={cn},dc=example,dc=com").unwrap();
        writeln!(f, "objectClass: inetOrgPerson").unwrap();
        writeln!(f, "cn: {cn}").unwrap();
        writeln!(f, "sn: TestEntry").unwrap();
    });
    session.expect_choose();
    session.respond('y');
    session.wait_exit(0);
}

/// Ensure an entry with the given cn does NOT exist.
fn remove_entry(cn: &str) {
    if !ldapsearch(&format!("(cn={cn})")).contains(&format!("cn: {cn}")) {
        return;
    }
    let mut session = spawn_session(&format!("(cn={cn})"));
    session.expect_edit(|path| {
        fs::write(path, "").unwrap();
    });
    session.expect_choose();
    session.respond('y');
    session.wait_exit(0);
}

static BUILD_INIT: Once = Once::new();
static DOCKER_INIT: Once = Once::new();
/// Serialize tests — they share an LDAP database and concurrent
/// connections to the tiny Alpine slapd cause hangs.
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the test lock (ignoring poison from prior panics).
fn serial() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Build the ldapvi binaries (ldapvi + test-ldapvi) if not already done.
fn ensure_binaries() {
    BUILD_INIT.call_once(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let workspace_root = format!("{manifest_dir}/..");
        let status = Command::new("cargo")
            .args(["build", "-p", "ldapvi"])
            .current_dir(&workspace_root)
            .status()
            .expect("failed to run cargo build");
        assert!(status.success(), "cargo build -p ldapvi failed");
    });
}

fn ensure_slapd() {
    ensure_binaries();
    DOCKER_INIT.call_once(|| {
        let image = image();
        let container = container();

        // Remove stale containers — both backends share the same port.
        let _ = Command::new("docker")
            .args(["rm", "-f", "ldapvi-inttest-slapd", "ldapvi-inttest-389ds"])
            .output();

        // Start container.
        let status = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &container,
                "-p",
                &format!("{PORT}:389"),
                &image,
            ])
            .status()
            .expect("failed to start docker container");
        assert!(status.success(), "docker run failed");

        // Wait for slapd to be ready (up to 10 seconds).
        let ldapvi = ldapvi_binary();
        for _ in 0..50 {
            let result = Command::new(&ldapvi)
                .args([
                    "--ldapsearch",
                    "--bind",
                    "simple",
                    "-h",
                    &ldap_url(),
                    "-b",
                    "",
                    "-s",
                    "base",
                    "(objectClass=*)",
                ])
                .output();
            if let Ok(output) = result {
                if output.status.success() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("slapd did not become ready within 10 seconds");
    });
}

#[test]
fn smoke_edit_discard() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // test-ldapvi searches, then invokes edit() which sends EDIT on fd 3.
    // We append a description attribute to the temp file.
    session.expect_edit(|path| {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("failed to open editor file");
        writeln!(f, "description: added by discard test").expect("failed to write to editor file");
    });

    // After the editor, ldapvi detects changes and presents the Action? prompt.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('Q'),
        "expected Q in charbag, got '{charbag}'"
    );

    // Respond Q to discard changes and quit.
    session.respond('Q');

    let output = session.wait_exit(0);

    // Verify that the description was NOT actually committed.
    let search_output = ldapsearch_test_user();
    assert!(
        !search_output.contains("added by discard test"),
        "description should NOT have been committed (Q = discard)\n\
         ldapsearch:\n{search_output}\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );
}

#[test]
fn smoke_edit_commit() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Edit: append a description attribute.
    session.expect_edit(|path| {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("failed to open editor file");
        writeln!(f, "description: added by commit test").expect("failed to write to editor file");
    });

    // Action? prompt — respond y to commit.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('y'),
        "expected y in charbag, got '{charbag}'"
    );
    session.respond('y');

    // On success, commit() calls exit(0) directly.
    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "expected 'Done.' in stdout:\n{}",
        output.stdout,
    );

    // Verify the change was actually committed.
    let search_output = ldapsearch_test_user();
    assert!(
        search_output.contains("added by commit test"),
        "description should have been committed\n\
         ldapsearch:\n{search_output}\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );
}

#[test]
fn smoke_reedit_then_commit() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // First edit: add a telephone number.
    session.expect_edit(|path| {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("failed to open editor file");
        writeln!(f, "telephoneNumber: 555-first-edit").expect("failed to write to editor file");
    });

    // Action? prompt — respond 'e' to re-edit.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('e'),
        "expected e in charbag, got '{charbag}'"
    );
    session.respond('e');

    // Second edit: replace the first phone number with a different one.
    session.expect_edit(|path| {
        let content = fs::read_to_string(path).expect("failed to read editor file");
        let updated = content.replace("555-first-edit", "555-second-edit");
        fs::write(path, updated).expect("failed to write editor file");
    });

    // Action? prompt — now commit.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('y'),
        "expected y in charbag, got '{charbag}'"
    );
    session.respond('y');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "expected 'Done.' in stdout:\n{}",
        output.stdout,
    );

    // Verify only the second edit was committed.
    let search_output = ldapsearch_test_user();
    assert!(
        search_output.contains("555-second-edit"),
        "telephoneNumber from second edit should be committed\n\
         ldapsearch:\n{search_output}\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr,
    );
    assert!(
        !search_output.contains("555-first-edit"),
        "telephoneNumber from first edit should NOT be present\n\
         ldapsearch:\n{search_output}",
    );
}

// ── B.8: No changes → immediate exit ──────────────────────────

#[test]
fn no_changes_immediate_exit() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Don't modify the file in the editor.
    session.expect_edit(|_path| {});

    // analyze_changes sees data == clean → "No changes." → exit 0.
    // No CHOOSE is sent.
    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("No changes."),
        "expected 'No changes.' in stdout:\n{}",
        output.stdout,
    );
}

// ── C.10: Syntax error → Q ────────────────────────────────────

#[test]
fn syntax_error_quit() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Corrupt the file with invalid syntax.
    session.expect_edit(|path| {
        let content = fs::read_to_string(path).unwrap();
        // Prepend a garbage line that the parser can't handle.
        fs::write(path, format!("INVALID GARBAGE LINE\n{content}")).unwrap();
    });

    // analyze_changes hits a parse error → "What now?" prompt.
    let charbag = session.expect_choose();
    assert_eq!(
        charbag, "eQ?",
        "expected 'What now?' charbag, got '{charbag}'"
    );

    session.respond('Q');
    session.wait_exit(0);
}

// ── C.9: Syntax error → fix → no changes ─────────────────────

#[test]
fn syntax_error_fix() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Save the original content, then corrupt the file.
    // We use a known prefix so the second edit can strip it.
    const GARBAGE: &str = "INVALID GARBAGE LINE\n";
    session.expect_edit(|path| {
        let content = fs::read_to_string(path).unwrap();
        fs::write(path, format!("{GARBAGE}{content}")).unwrap();
    });

    // "What now?" prompt.
    let charbag = session.expect_choose();
    assert_eq!(charbag, "eQ?");
    session.respond('e');

    // Second edit: remove the garbage prefix (restoring original).
    session.expect_edit(|path| {
        let content = fs::read_to_string(path).unwrap();
        fs::write(path, content.strip_prefix(GARBAGE).unwrap()).unwrap();
    });

    // No changes from clean → "No changes." → exit 0.
    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("No changes."),
        "expected 'No changes.' after fixing syntax error:\n{}",
        output.stdout,
    );
}

// ── B.4: q — save as LDIF and quit ───────────────────────────

#[test]
fn save_ldif_and_quit() {
    let _lock = serial();
    ensure_slapd();

    let tmpdir = tempfile::tempdir().expect("failed to create temp dir");
    let mut session = spawn_session_in("(cn=Test User)", tmpdir.path().to_str().unwrap());

    // Make a change so there's something to save.
    session.expect_edit(|path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(f, "description: saved by ldif test").unwrap();
    });

    // Action? → respond q to save as LDIF.
    let charbag = session.expect_choose();
    assert!(charbag.contains('q'));
    session.respond('q');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Your changes have been saved to"),
        "expected save confirmation in stdout:\n{}",
        output.stdout,
    );

    // Verify a ,ldapvi-*.ldif file was created in the tmpdir.
    let ldif_files: Vec<_> = fs::read_dir(tmpdir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(",ldapvi-") && name.ends_with(".ldif")
        })
        .collect();
    assert_eq!(
        ldif_files.len(),
        1,
        "expected exactly one LDIF file in tmpdir, found: {:?}",
        ldif_files.iter().map(|e| e.file_name()).collect::<Vec<_>>(),
    );

    // Verify the LDIF contains the change.
    let ldif = fs::read_to_string(ldif_files[0].path()).unwrap();
    assert!(
        ldif.contains("description"),
        "LDIF file should contain the description change:\n{ldif}",
    );

    // Verify LDAP was NOT modified (q saves locally, doesn't commit).
    let search_output = ldapsearch_test_user();
    assert!(
        !search_output.contains("saved by ldif test"),
        "description should NOT have been committed (q = save locally)\n\
         ldapsearch:\n{search_output}",
    );
}

// ── E.13: Add a new entry ────────────────────────────────────

#[test]
fn add_new_entry() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Append a new entry in ldapvi format.
    session.expect_edit(|path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(f, "\nadd cn=Added By Test,dc=example,dc=com").unwrap();
        writeln!(f, "objectClass: inetOrgPerson").unwrap();
        writeln!(f, "cn: Added By Test").unwrap();
        writeln!(f, "sn: Test").unwrap();
    });

    let charbag = session.expect_choose();
    assert!(charbag.contains('y'));
    session.respond('y');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "stdout:\n{}",
        output.stdout
    );

    // Verify the new entry exists in LDAP.
    let search_output = ldapsearch("(cn=Added By Test)");
    assert!(
        search_output.contains("cn: Added By Test"),
        "new entry should exist in LDAP:\n{search_output}",
    );
}

// ── E.14: Delete an entry ────────────────────────────────────

#[test]
fn delete_entry() {
    let _lock = serial();
    ensure_slapd();

    // Make sure the entry from add_new_entry exists (or add it).
    if !ldapsearch("(cn=Added By Test)").contains("cn: Added By Test") {
        // Add it first.
        let mut session = spawn_session("(objectClass=*)");
        session.expect_edit(|path| {
            let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
            writeln!(f, "\nadd cn=Added By Test,dc=example,dc=com").unwrap();
            writeln!(f, "objectClass: inetOrgPerson").unwrap();
            writeln!(f, "cn: Added By Test").unwrap();
            writeln!(f, "sn: Test").unwrap();
        });
        session.expect_choose();
        session.respond('y');
        session.wait_exit(0);
    }

    // Now search for it and delete it.
    let mut session = spawn_session("(cn=Added By Test)");

    session.expect_edit(|path| {
        // Empty the data file — the entry is in clean but not data,
        // so compare() detects it as a deletion.
        fs::write(path, "").unwrap();
    });

    let charbag = session.expect_choose();
    assert!(charbag.contains('y'));
    session.respond('y');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "stdout:\n{}",
        output.stdout
    );

    // Verify the entry is gone.
    let search_output = ldapsearch("(cn=Added By Test)");
    assert!(
        !search_output.contains("cn: Added By Test"),
        "entry should have been deleted:\n{search_output}",
    );
}

// ── B.7: f — forget deletions ────────────────────────────────

#[test]
fn forget_deletions() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Remove the entry from the data file → appears as a deletion.
    session.expect_edit(|path| {
        fs::write(path, "").unwrap();
    });

    // Action? prompt — changes detected (1 delete).
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('f'),
        "expected f in charbag, got '{charbag}'"
    );

    // Respond f to forget deletions.
    session.respond('f');

    // After forgetting, analyze_changes sees no changes → "No changes." → exit.
    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("No changes."),
        "expected 'No changes.' after forgetting deletion:\n{}",
        output.stdout,
    );

    // Verify the entry is still there.
    let search_output = ldapsearch_test_user();
    assert!(
        search_output.contains("cn: Test User"),
        "entry should still exist after forgetting deletion:\n{search_output}",
    );
}

// ── B.6: s — skip entry ──────────────────────────────────────

#[test]
fn skip_entry() {
    let _lock = serial();
    ensure_slapd();

    // Ensure we have two entries to work with.
    ensure_entry("Skip Alpha");
    ensure_entry("Skip Beta");

    // Search for both entries.
    let mut session = spawn_session("(|(cn=Skip Alpha)(cn=Skip Beta))");

    // Edit: add a description to both entries.
    session.expect_edit(|path| {
        let content = fs::read_to_string(path).unwrap();
        let updated = content.replace(
            "sn: TestEntry",
            "sn: TestEntry\ndescription: skip-test-marker",
        );
        fs::write(path, updated).unwrap();
    });

    // Action? — shows 2 modifications. Press s to skip the first entry.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('s'),
        "expected s in charbag, got '{charbag}'"
    );
    session.respond('s');

    // After skip, only 1 modification remains. Action? again.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('y'),
        "expected y in charbag, got '{charbag}'"
    );
    session.respond('y');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "stdout:\n{}",
        output.stdout
    );

    // Exactly one of the two entries should have the description.
    let a = ldapsearch("(cn=Skip Alpha)");
    let b = ldapsearch("(cn=Skip Beta)");
    let a_has = a.contains("skip-test-marker");
    let b_has = b.contains("skip-test-marker");
    assert!(
        a_has ^ b_has,
        "exactly one entry should have the description after skip\n\
         Alpha has it: {a_has}\nBeta has it: {b_has}",
    );

    // Clean up.
    remove_entry("Skip Alpha");
    remove_entry("Skip Beta");
}

// ── E.12: Modify multiple entries ────────────────────────────

#[test]
fn modify_multiple_entries() {
    let _lock = serial();
    ensure_slapd();

    ensure_entry("Multi Alpha");
    ensure_entry("Multi Beta");

    let mut session = spawn_session("(|(cn=Multi Alpha)(cn=Multi Beta))");

    // Edit: add a unique description to each entry.
    // Insert after the DN line to be independent of attribute order.
    session.expect_edit(|path| {
        let content = fs::read_to_string(path).unwrap();
        let updated = content
            .replace(
                "cn=Multi Alpha,dc=example,dc=com\n",
                "cn=Multi Alpha,dc=example,dc=com\ndescription: multi-alpha\n",
            )
            .replace(
                "cn=Multi Beta,dc=example,dc=com\n",
                "cn=Multi Beta,dc=example,dc=com\ndescription: multi-beta\n",
            );
        fs::write(path, updated).unwrap();
    });

    let charbag = session.expect_choose();
    assert!(charbag.contains('y'));
    session.respond('y');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "stdout:\n{}",
        output.stdout
    );

    // Both entries should have their descriptions.
    let a = ldapsearch("(cn=Multi Alpha)");
    let b = ldapsearch("(cn=Multi Beta)");
    assert!(
        a.contains("multi-alpha"),
        "Multi Alpha should have description:\n{a}",
    );
    assert!(
        b.contains("multi-beta"),
        "Multi Beta should have description:\n{b}",
    );

    // Clean up.
    remove_entry("Multi Alpha");
    remove_entry("Multi Beta");
}

// ── E.15: Rename an entry (modrdn) ──────────────────────────

#[test]
fn rename_entry() {
    let _lock = serial();
    ensure_slapd();

    ensure_entry("Rename Source");
    remove_entry("Renamed Target");

    let mut session = spawn_session("(cn=Rename Source)");

    // Edit: change the DN and cn attribute to rename the entry.
    session.expect_edit(|path| {
        let content = fs::read_to_string(path).unwrap();
        let updated = content
            .replace("cn=Rename Source", "cn=Renamed Target")
            .replace("cn: Rename Source", "cn: Renamed Target");
        fs::write(path, updated).unwrap();
    });

    let charbag = session.expect_choose();
    assert!(charbag.contains('y'));
    session.respond('y');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "stdout:\n{}",
        output.stdout
    );

    // Old entry should be gone, new entry should exist.
    let old = ldapsearch("(cn=Rename Source)");
    let new = ldapsearch("(cn=Renamed Target)");
    assert!(
        !old.contains("cn: Rename Source"),
        "old entry should be gone:\n{old}",
    );
    assert!(
        new.contains("cn: Renamed Target"),
        "renamed entry should exist:\n{new}",
    );

    // Clean up.
    remove_entry("Renamed Target");
}

// ── F.16: v — view changes as LDIF ──────────────────────────

#[test]
fn view_ldif() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Make a change so there's something to view.
    session.expect_edit(|path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(f, "description: view-ldif-test").unwrap();
    });

    // Action? → press v to view LDIF.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('v'),
        "expected v in charbag, got '{charbag}'"
    );
    session.respond('v');

    // test-ldapvi calls view_ldif which writes a file then calls view().
    // Our test version of view() sends VIEW <path> on the control fd.
    session.expect_view(|path| {
        let content = fs::read_to_string(path).unwrap();
        assert!(
            content.contains("version: 1"),
            "LDIF view should start with version line:\n{content}",
        );
        assert!(
            content.contains("description"),
            "LDIF view should contain the description change:\n{content}",
        );
    });

    // After view, we're back at Action?. Quit.
    let charbag = session.expect_choose();
    assert!(charbag.contains('Q'));
    session.respond('Q');

    session.wait_exit(0);
}

// ── F.17: V — view changes as vdif ──────────────────────────

#[test]
fn view_vdif() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    session.expect_edit(|path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(f, "description: view-vdif-test").unwrap();
    });

    // Action? → press V to view vdif.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('V'),
        "expected V in charbag, got '{charbag}'"
    );
    session.respond('V');

    // view_vdif writes a file and calls view().
    session.expect_view(|path| {
        let content = fs::read_to_string(path).unwrap();
        assert!(
            content.contains("version: ldapvi"),
            "vdif view should start with ldapvi version line:\n{content}",
        );
        assert!(
            content.contains("description"),
            "vdif view should contain the description change:\n{content}",
        );
    });

    // Back at Action?. Quit.
    let _charbag = session.expect_choose();
    session.respond('Q');

    session.wait_exit(0);
}

// ── D.11: Commit failure → Action? again → Q ────────────────

#[test]
fn commit_failure_then_quit() {
    let _lock = serial();
    ensure_slapd();

    // Ensure target doesn't exist.
    remove_entry("Bad Entry");

    let mut session = spawn_test_session();

    // Add an entry missing the required 'sn' attribute → schema violation.
    session.expect_edit(|path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(f, "\nadd cn=Bad Entry,dc=example,dc=com").unwrap();
        writeln!(f, "objectClass: inetOrgPerson").unwrap();
        writeln!(f, "cn: Bad Entry").unwrap();
        // Deliberately omit sn — required by inetOrgPerson schema.
    });

    // Action? → commit.
    let charbag = session.expect_choose();
    assert!(charbag.contains('y'));
    session.respond('y');

    // Commit fails (LDAP schema violation). We get Action? again.
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('Q'),
        "expected Action? prompt after commit failure, got charbag '{charbag}'",
    );

    // Discard and quit.
    session.respond('Q');
    session.wait_exit(0);

    // Verify the bad entry was NOT created.
    let search_output = ldapsearch("(cn=Bad Entry)");
    assert!(
        !search_output.contains("cn: Bad Entry"),
        "bad entry should not exist after failed commit:\n{search_output}",
    );
}

// ── B.5: Y — continuous commit ──────────────────────────────

#[test]
fn continuous_commit() {
    let _lock = serial();
    ensure_slapd();

    let mut session = spawn_test_session();

    // Edit: add a description.
    session.expect_edit(|path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        writeln!(f, "description: continuous-commit-test").unwrap();
    });

    // Action? → Y (continuous mode, but on success behaves like y).
    let charbag = session.expect_choose();
    assert!(
        charbag.contains('Y'),
        "expected Y in charbag, got '{charbag}'"
    );
    session.respond('Y');

    let output = session.wait_exit(0);
    assert!(
        output.stdout.contains("Done."),
        "stdout:\n{}",
        output.stdout
    );

    // Verify the change was committed.
    let search_output = ldapsearch_test_user();
    assert!(
        search_output.contains("continuous-commit-test"),
        "description should have been committed:\n{search_output}",
    );
}

// ── Profile --base override ──────────────────────────────────

/// Helper: run ldapvi --ldapsearch with a custom HOME directory.
fn ldapsearch_with_home(home: &str, extra_args: &[&str], filter: &str) -> std::process::Output {
    let mut cmd = Command::new(ldapvi_binary());
    cmd.env("HOME", home);
    cmd.args([
        "--ldapsearch",
        "--bind",
        "simple",
        "-h",
        &ldap_url(),
        "-D",
        "cn=admin,dc=example,dc=com",
        "-w",
        "secret",
    ]);
    cmd.args(extra_args);
    cmd.arg(filter);
    cmd.output().expect("ldapvi --ldapsearch failed")
}

#[test]
fn profile_base_used_when_no_cli_base() {
    let _lock = serial();
    ensure_slapd();

    let tmpdir = tempfile::tempdir().expect("failed to create temp dir");

    // Write a profile with the correct base.
    fs::write(
        tmpdir.path().join(".ldapvirc"),
        "profile default\n\
         base: dc=example,dc=com\n\
         \n",
    )
    .unwrap();

    // Run without CLI --base → profile base should be used.
    let output = ldapsearch_with_home(tmpdir.path().to_str().unwrap(), &[], "(cn=Test User)");

    assert!(
        output.status.success(),
        "ldapsearch should succeed with profile base"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cn: Test User"),
        "profile base should find the test entry:\n{stdout}",
    );
}

#[test]
fn cli_base_overrides_profile_base() {
    let _lock = serial();
    ensure_slapd();

    let tmpdir = tempfile::tempdir().expect("failed to create temp dir");

    // Write a profile with a non-existent base.
    fs::write(
        tmpdir.path().join(".ldapvirc"),
        "profile default\n\
         base: ou=nonexistent,dc=example,dc=com\n\
         \n",
    )
    .unwrap();

    // Without CLI --base, the profile's bad base should cause no results.
    let output = ldapsearch_with_home(tmpdir.path().to_str().unwrap(), &[], "(cn=Test User)");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("cn: Test User"),
        "profile's non-existent base should return no results:\n{stdout}",
    );

    // With CLI --base, it should override the profile's base.
    let output = ldapsearch_with_home(
        tmpdir.path().to_str().unwrap(),
        &["-b", "dc=example,dc=com"],
        "(cn=Test User)",
    );
    assert!(
        output.status.success(),
        "ldapsearch with CLI --base should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cn: Test User"),
        "CLI --base should override profile base and find test entry:\n{stdout}",
    );
}

#[test]
fn named_profile_base_override() {
    let _lock = serial();
    ensure_slapd();

    let tmpdir = tempfile::tempdir().expect("failed to create temp dir");

    // Write a named profile with a non-existent base.
    fs::write(
        tmpdir.path().join(".ldapvirc"),
        "profile myprofile\n\
         base: ou=nonexistent,dc=example,dc=com\n\
         \n",
    )
    .unwrap();

    // Use named profile, but override base on CLI.
    let output = ldapsearch_with_home(
        tmpdir.path().to_str().unwrap(),
        &["-p", "myprofile", "-b", "dc=example,dc=com"],
        "(cn=Test User)",
    );
    assert!(
        output.status.success(),
        "named profile with CLI --base override should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cn: Test User"),
        "CLI --base should override named profile base:\n{stdout}",
    );
}
