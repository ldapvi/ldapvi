# ldapvi — Rust Rewrite

ldapvi is `vipw(1)` for LDAP: it fetches entries, opens them in an editor, and
diffs the result to compute LDAP modifications. This branch (`rust`) is a
ground-up rewrite from C to Rust. The `master` branch has the original C code.

## Build & Check

```sh
cargo build                 # build all crates
cargo test                  # unit tests (no LDAP server needed)
cargo clippy                # lint (workspace clippy config in root Cargo.toml)
cargo fmt -- --check        # format check (default rustfmt, no rustfmt.toml)
```

Edition 2021, resolver v2. Clippy allows: `uninlined_format_args`,
`write_with_newline`, `manual_strip`, `collapsible_if`, `too_many_arguments`,
`redundant_pattern_matching`, `manual_range_contains`.

## Workspace Layout

```
ldapvi/             Main application crate (v2.0.0)
  src/
    main.rs         Production entry point
    test_main.rs    Test binary entry point (fd 3 protocol)
    app.rs          Application logic, DiffHandler impls
    arguments.rs    CLI argument parsing (uses popt)
    interactive.rs  Interactive UI (edit/choose/view)
    noninteractive.rs  Non-interactive mode for test binary
    ldap.rs         LDAP operations wrapper (ldap3)
    lib.rs          Public library API (re-exports below)
    data.rs         Core types: Entry, Attribute, LdapMod, etc.
    diff.rs         Diff engine (heart of ldapvi)
    parse.rs        ldapvi native format parser
    parseldif.rs    RFC 2849 LDIF parser
    print.rs        Output formatting (ldapvi + LDIF)
    schema.rs       LDAP schema handling (RFC 4512)
    base64.rs       Base64 with LDIF line folding
    port.rs         Password hashing ({SHA}, {SSHA}, {MD5}, {SMD5})
    error.rs        Error types (thiserror)
popt/               Pure-Rust reimplementation of C popt library (no deps)
integration-test/   Docker-based integration tests
```

## Architecture

### Key Traits (diff.rs)

**`EntryParser`** — Strategy for reading LDAP entries from a stream.
Methods: `read_entry`, `peek_entry`, `skip_entry`, `read_rename`,
`read_delete`, `read_modify`, `parser_tell`, `parser_seek`, `parser_read_raw`.
Implementations: `LdifParser<R>`, `LdapviParser<R>`.

**`DiffHandler`** — Strategy for processing diff operations.
Methods: `handle_add`, `handle_delete`, `handle_change`, `handle_rename`,
`handle_rename0`.
Implementations (app.rs): `StatisticsHandler`, `LdapCommitHandler`,
`VdifHandler`, `LdifHandler`, `ForgetDeletionsHandler`.
Test impl: `MockHandler` (in diff.rs tests).

### Diff Engine (diff.rs — `compare_streams`)

1. Read key from edited file via `peek_entry`
2. Numeric key → look up offset in clean file, `fastcmp()` for quick byte
   comparison, full parse + attribute diff if different, detect renames
3. Keyword key (add/delete/modify/rename) → parse change record directly
4. After all edited entries processed → unmarked clean entries are deletions

## Integration Tests

Require Docker. Two LDAP backends available:

```sh
# Build & start OpenLDAP (default)
docker build -t ldapvi-slapd -f integration-test/Dockerfile.slapd integration-test
docker run -d --name ldapvi-test -p 3390:389 ldapvi-slapd

# Or 389 Directory Server
docker build -t ldapvi-389ds -f integration-test/Dockerfile.389ds integration-test
docker run -d --name ldapvi-test -p 3390:3389 ldapvi-389ds

# Run tests (serialized — shared LDAP database)
cargo test -p test-driver

# Select backend
LDAPVI_TEST_IMAGE=389ds cargo test -p test-driver
```

Test database: `dc=example,dc=com`, admin `cn=admin,dc=example,dc=com` / `secret`, port 3390.

Tests use a `TestSession` that spawns `test-ldapvi` and communicates over a
Unix socketpair (fd 3) with a CHOOSE/CHOSE, EDIT/EDITED, VIEW/VIEWED protocol.

## Git Workflow

- **`rust` branch** — active development (this branch)
- **`master` branch** — original C codebase (stable 1.x)

## Key Dependencies

ldapvi: `ldap3`, `tokio`, `rustyline`, `nix`, `tempfile`, `thiserror`, `base64`, `sha1`, `md-5`
popt: none (stdlib only)
integration-test: `libc`, `nix`, `tempfile`
