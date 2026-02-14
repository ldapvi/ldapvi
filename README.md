# ldapvi

An interactive LDAP client for Unix terminals.  Using it, you can update
LDAP entries with a text editor.  Think of it as `vipw(1)` for LDAP.

![ldapvi demo](web/vhs.gif)

## Getting Started

Try querying the ROOT DSE for available naming contexts:

```
ldapvi --host HOSTNAME --discover
```

Assuming a suitably configured LDAP library, run ldapvi without arguments
to see all entries available:

```
ldapvi
```

Many LDAP serversn respond to such read-only requests without authentication.
Otherwise or to make changes, simple auth may work like this:

```
ldapvi ... -w PASSWORD --bind simple -D cn=YOURUSERNAME,dc=example,dc=com
```

## Configuration file

Once it works interactively, it is possible to generate sample configuration for `~/.ldaprc` or
`/etc/ldap/ldap.conf` using:

```
ldapvi --host HOSTNAME --discover --config
```

Alternatively set up `~/.ldapvirc` which supports the program's command line parameters.

## Usage

```
ldapvi [OPTION]... [FILTER] [AD]...
```

| Mode | Description |
|------|-------------|
| `ldapvi [OPTION]... [FILTER] [AD]...` | Search and edit entries interactively |
| `ldapvi --out [OPTION]... [FILTER] [AD]...` | Print entries to stdout |
| `ldapvi --in [OPTION]... [FILENAME]` | Load change records from file |
| `ldapvi --delete [OPTION]... DN...` | Edit a delete record |
| `ldapvi --rename [OPTION]... DN1 DN2` | Edit a rename record |

Shortcut aliases: `--ldapsearch` (`--quiet --out`), `--ldapmodify`
(`--noninteractive --in`), `--ldapdelete` (`--noninteractive --delete`),
`--ldapmoddn` (`--noninteractive --rename`).

### Key Options

| Option | Description |
|--------|-------------|
| `-h`, `--host` URL | LDAP server |
| `-b`, `--base` DN | Search base |
| `-s`, `--scope` base\|one\|sub | Search scope |
| `-D`, `--user` USER | Bind DN or search filter (sets `--bind simple`) |
| `-w`, `--password` SECRET | Password (simple or SASL) |
| `-d`, `--discover` | Auto-detect naming contexts from ROOT DSE |
| `-Z`, `--starttls` | Require StartTLS |
| `--tls` never\|allow\|try\|strict | TLS strictness (default: strict) |
| `--bind` simple\|sasl | Authentication method |
| `-m`, `--may` | Show optional attributes as comments |
| `--encoding` ASCII\|UTF-8\|binary | Allowed encoding (default: UTF-8) |
| `-c`, `--continue` | Ignore errors and continue processing |
| `-v`, `--verbose` | Note every update |

SASL options: `-I` (interactive), `-Q` (quiet), `-O` (secprops), `-R`
(realm), `-U` (authcid), `-X` (authzid), `-Y` (mechanism).

Environment variables: `VISUAL`, `EDITOR`, `PAGER`.

## File Format

By default, ldapvi uses an extended LDIF-like syntax.  Use --ldif for standard LDIF.
See the [manual](http://www.lichteblau.com/ldapvi/manual#syntax) for details.

## Building from Source

### Dependencies (Debian/Ubuntu)

```
apt-get build-dep ldapvi
# or in detail:
sudo apt-get install autoconf pkg-config \
  libldap-dev libglib2.0-dev libpopt-dev \
  libreadline-dev libncurses-dev libssl-dev \
  libsasl2-dev libcrypt-dev
```

### Build

```
cd ldapvi
./autogen.sh # if building from git
./configure
make
make install
```

### Tests

```
make test          # unit tests
```

Integration tests (require Docker and Rust) run against OpenLDAP and 389
Directory Server:

```
docker build -t ldapvi-test-slapd -f integration-test/Dockerfile.slapd integration-test/
cd integration-test
LDAPVI_TEST_IMAGE=ldapvi-test-slapd cargo test
```

The docker containers can also be useful for interactive testing, with the following parameters:

```
ldapvi -h ldap://localhost:3390 --discover -w secret --bind simple -D cn=admin,dc=example,dc=com
```
