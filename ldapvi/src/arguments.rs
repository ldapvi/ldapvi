use std::io::Cursor;

use popt::{ArgType, Context, Opt, OptionTable};

use ldapvi::data::Entry;
use ldapvi::parse::LdapviParser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Edit,
    Out,
    In,
    Delete,
    Rename,
    Modrdn,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Cmdline {
    pub server: Option<String>,
    pub basedns: Vec<String>,
    pub scope: ldap3::Scope,
    pub filter: String,
    pub attrs: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub quiet: bool,
    pub discover: bool,
    pub starttls: bool,
    pub deref: i32,
    pub managedsait: bool,
    pub continuous: bool,
    pub sortkeys: Option<String>,
    pub ldif: bool,
    pub mode: Mode,
    pub in_file: Option<String>,
    pub verbose: bool,
    pub noquestions: bool,
    pub noninteractive: bool,
    pub encoding: Option<String>,
    pub delete_dns: Vec<String>,
    pub rename_old: Option<String>,
    pub rename_new: Option<String>,
    pub deleteoldrdn: bool,
    pub bind: Option<String>,
    pub tls: Option<String>,
    pub password_file: Option<String>,
    pub schema_comments: bool,
    pub config: bool,
    pub empty: bool,
    pub ldapmodify_add: bool,
    pub classes: Vec<String>,
    pub ldap_conf: bool,
    pub profile: Option<String>,
}

const USAGE: &str = r#"Usage: ldapvi [OPTION]... [FILTER] [AD]...
Quickstart:
       ldapvi --discover --host HOSTNAME
Perform an LDAP search and update results using a text editor.

Other usage:
       ldapvi --out [OPTION]... [FILTER] [AD]...  Print entries
       ldapvi --in [OPTION]... [FILENAME]         Load change records
       ldapvi --delete [OPTION]... DN...          Edit a delete record
       ldapvi --rename [OPTION]... DN1 DN2        Edit a rename record

Configuration profiles:
  -p, --profile NAME     Section of ~/.ldapvirc or /etc/ldap.conf to use.

Connection options:
  -h, --host URL         Server.
  -D, --user USER        Search filter or DN: User to bind as.     [1]
                         Sets --bind simple.
  -w, --password SECRET  Password (also valid for SASL).
  -y, --password-file FILE  Password file (also valid for SASL).
      --bind [simple,sasl]
                         Disable or enable SASL.
      --bind-dialog [never,auto,always]
                         Interactive login dialog.

SASL options (these parameters set --bind sasl):
  -I, --sasl-interactive Set --bind-dialog always.
  -O, --sasl-secprops P  SASL security properties.
  -Q, --sasl-quiet       Set --bind-dialog never.
  -R, --sasl-realm    R  SASL realm.
  -U, --sasl-authcid AC  SASL authentication identity.
  -X, --sasl-authzid AZ  SASL authorization identity.
  -Y, --sasl-mech  MECH  SASL mechanism.

Search parameters:
  -b, --base DN          Search base.
  -s, --scope SCOPE      Search scope.  One of base|one|sub.
  -S, --sort KEYS        Sort control (critical).

Miscellaneous options:
      --add              (Only with --in, --ldapmodify:)
                         Treat attrval records as new entries to add.
  -o, --class OBJCLASS   Class to add.  Can be repeated.  Implies -A.
      --config           Print parameters in ldap.conf syntax.
  -c  --continue         Ignore LDAP errors and continue processing.
      --deleteoldrdn     (Only with --rename:) Delete the old RDN.
  -a, --deref            never|searching|finding|always
  -d, --discover         Auto-detect naming contexts.              [2]
  -A, --empty            Don't search, start with empty file.  See -o.
      --encoding [ASCII|UTF-8|binary]
                         The encoding to allow.  Default is UTF-8.
  -H, --help             This help.
      --ldap-conf        Always read libldap configuration.
  -m, --may              Show missing optional attributes as comments.
  -M, --managedsait      manageDsaIT control (critical).
      --noquestions      Commit without asking for confirmation.
  -!, --noninteractive   Never ask any questions.
  -q, --quiet            Disable progress output.
  -R, --read DN          Same as -b DN -s base '(objectclass=*)' + *
  -Z, --starttls         Require startTLS.
      --tls [never|allow|try|strict]  Level of TLS strictess.
  -v, --verbose          Note every update.

Shortcuts:
      --ldapsearch       Short for --quiet --out
      --ldapmodify       Short for --noninteractive --in
      --ldapdelete       Short for --noninteractive --delete
      --ldapmoddn        Short for --noninteractive --rename

Environment variables: VISUAL, EDITOR, PAGER.

[1] User names can be specified as distinguished names:
      uid=foo,ou=bar,dc=acme,dc=com
    or search filters:
      (uid=foo)
    Note the use of parenthesis, which can be omitted from search
    filters usually but are required here.  For this searching bind to
    work, your client library must be configured with appropriate
    default search parameters.

[2] Repeat the search for each naming context found and present the
    concatenation of all search results.  Conflicts with --base.
    With --config, show a BASE configuration line for each context.

A special (offline) option is --diff, which compares two files
and writes any changes to standard output in LDIF format.

Report bugs to "ldapvi@lists.askja.de".
"#;

// Constants for VAL options (matching C enum ldapvi_option_numbers)
const OPTION_OUT: i32 = 1004;
const OPTION_IN: i32 = 1005;
const OPTION_DELETE: i32 = 1006;
const OPTION_RENAME: i32 = 1007;
const OPTION_MODRDN: i32 = 1008;
const OPTION_NOQUESTIONS: i32 = 1009;
const OPTION_LDAPSEARCH: i32 = 1010;
const OPTION_LDAPMODIFY: i32 = 1011;
const OPTION_LDAPDELETE: i32 = 1012;
const OPTION_LDAPMODDN: i32 = 1013;
const OPTION_LDAPMODRDN: i32 = 1014;

fn build_options() -> OptionTable {
    OptionTable::new()
        // Help (handled before/after parse manually)
        .option(Opt::new("help").short('H'))
        .option(Opt::new("version"))
        .option(Opt::new("usage"))
        // Configuration profile
        .option(Opt::new("profile").short('p').arg_type(ArgType::String))
        // Connection options
        .option(Opt::new("host").short('h').arg_type(ArgType::String))
        .option(Opt::new("user").short('D').arg_type(ArgType::String))
        .option(Opt::new("password").short('w').arg_type(ArgType::String))
        .option(
            Opt::new("password-file")
                .short('y')
                .arg_type(ArgType::String),
        )
        .option(Opt::new("bind").arg_type(ArgType::String))
        .option(Opt::new("bind-dialog").arg_type(ArgType::String))
        // SASL options
        .option(Opt::new("sasl-interactive").short('I'))
        .option(
            Opt::new("sasl-secprops")
                .short('O')
                .arg_type(ArgType::String),
        )
        .option(Opt::new("sasl-quiet").short('Q'))
        .option(Opt::new("sasl-realm").arg_type(ArgType::String))
        .option(
            Opt::new("sasl-authcid")
                .short('U')
                .arg_type(ArgType::String),
        )
        .option(
            Opt::new("sasl-authzid")
                .short('X')
                .arg_type(ArgType::String),
        )
        .option(Opt::new("sasl-mech").short('Y').arg_type(ArgType::String))
        // Search parameters
        .option(Opt::new("base").short('b').arg_type(ArgType::Argv))
        .option(Opt::new("scope").short('s').arg_type(ArgType::String))
        .option(Opt::new("sort").short('S').arg_type(ArgType::String))
        // Miscellaneous flag options
        .option(Opt::new("add"))
        .option(Opt::new("class").short('o').arg_type(ArgType::Argv))
        .option(Opt::new("config"))
        .option(Opt::new("continuous").short('c'))
        .option(Opt::new("continue").store_as("continuous"))
        .option(Opt::new("deleteoldrdn").short('r'))
        .option(Opt::new("deref").short('a').arg_type(ArgType::String))
        .option(Opt::new("discover").short('d'))
        .option(Opt::new("empty").short('A'))
        .option(Opt::new("encoding").arg_type(ArgType::String))
        .option(Opt::new("ldap-conf"))
        .option(Opt::new("may").short('m'))
        .option(Opt::new("managedsait").short('M'))
        .option(Opt::val("noquestions", OPTION_NOQUESTIONS))
        .option(Opt::new("noninteractive").short('!'))
        .option(Opt::new("quiet").short('q'))
        .option(Opt::new("read").short('R').arg_type(ArgType::String))
        .option(Opt::new("starttls").short('Z'))
        .option(Opt::new("tls").arg_type(ArgType::String))
        .option(Opt::new("verbose").short('v'))
        // Format options (simple flags)
        .option(Opt::new("ldif"))
        .option(Opt::new("ldapvi"))
        // Mode options (VAL)
        .option(Opt::val("out", OPTION_OUT).store_as("mode"))
        .option(Opt::val("ldapsearch", OPTION_LDAPSEARCH).store_as("mode"))
        .option(Opt::val("in", OPTION_IN).store_as("mode"))
        .option(Opt::val("ldapmodify", OPTION_LDAPMODIFY).store_as("mode"))
        .option(Opt::val("delete", OPTION_DELETE).store_as("mode"))
        .option(Opt::val("ldapdelete", OPTION_LDAPDELETE).store_as("mode"))
        .option(Opt::val("rename", OPTION_RENAME).store_as("mode"))
        .option(Opt::val("ldapmoddn", OPTION_LDAPMODDN).store_as("mode"))
        .option(Opt::val("modrdn", OPTION_MODRDN).store_as("mode"))
        .option(Opt::val("ldapmodrdn", OPTION_LDAPMODRDN).store_as("mode"))
}

fn parse_scope(s: &str) -> Result<ldap3::Scope, String> {
    match s {
        "base" => Ok(ldap3::Scope::Base),
        "one" => Ok(ldap3::Scope::OneLevel),
        "sub" => Ok(ldap3::Scope::Subtree),
        _ => Err(format!("invalid scope: {}", s)),
    }
}

fn parse_deref(s: &str) -> Result<i32, String> {
    match s {
        "never" => Ok(0),
        "search" | "searching" => Ok(1),
        "find" | "finding" => Ok(2),
        "always" => Ok(3),
        _ => Err(format!("invalid deref mode: {}", s)),
    }
}

/// Search config file content for a named profile.
/// Returns Ok(Some(entry)) if found, Ok(None) if not found,
/// Err on parse error or duplicate profile.
fn find_profile(content: &[u8], name: &str) -> Result<Option<Entry>, String> {
    let mut parser = LdapviParser::new(Cursor::new(content));
    let mut found: Option<Entry> = None;

    loop {
        match parser.read_profile() {
            Ok(Some(entry)) => {
                if entry.dn == name {
                    if found.is_some() {
                        return Err(format!("Duplicate configuration profile '{}'.", name));
                    }
                    found = Some(entry);
                }
            }
            Ok(None) => break,
            Err(_) => {
                return Err("Error in configuration file, giving up.".to_string());
            }
        }
    }

    Ok(found)
}

/// Read ~/.ldapvirc (or /etc/ldapvi.conf), find the named profile
/// (defaulting to "default"), and return it as an Entry.
fn parse_configuration(profile_name: Option<&str>) -> Option<Entry> {
    let name = profile_name.unwrap_or("default");

    // Try ~/.ldapvirc first, then /etc/ldapvi.conf
    let content = std::env::var("HOME")
        .ok()
        .and_then(|home| std::fs::read(format!("{}/.ldapvirc", home)).ok())
        .or_else(|| std::fs::read("/etc/ldapvi.conf").ok());

    let content = match content {
        Some(c) => c,
        None => {
            if profile_name.is_some() {
                eprintln!("Error: ldapvi configuration file not found.");
                std::process::exit(1);
            }
            return None;
        }
    };

    match find_profile(&content, name) {
        Ok(found) => {
            if found.is_none() && profile_name.is_some() {
                eprintln!("Error: Configuration profile not found: '{}'.", name);
                std::process::exit(1);
            }
            found
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Look up a single-valued string option from a profile Entry.
fn profile_get(profile: &Entry, key: &str) -> Option<String> {
    for attr in &profile.attributes {
        if attr.ad == key {
            return attr
                .values
                .last()
                .map(|v| String::from_utf8_lossy(v).into_owned());
        }
    }
    None
}

/// Look up a multi-valued string option from a profile Entry.
fn profile_get_all(profile: &Entry, key: &str) -> Vec<String> {
    for attr in &profile.attributes {
        if attr.ad == key {
            return attr
                .values
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect();
        }
    }
    vec![]
}

/// Check whether a profile has a boolean "yes" value for a key.
fn profile_get_bool(profile: &Entry, key: &str) -> bool {
    profile_get(profile, key).as_deref() == Some("yes")
}

pub fn parse_args() -> Result<Cmdline, String> {
    // Check for --help/-H before popt parsing
    for arg in std::env::args().skip(1) {
        if arg == "--help" || arg == "-H" {
            print!("{}", USAGE);
            std::process::exit(0);
        }
    }

    let opts = build_options();

    let mut ctx = Context::builder("ldapvi")
        .options(opts)
        .build()
        .map_err(|e| format!("{}", e))?;

    ctx.parse().map_err(|e| format!("{}", e))?;

    // Handle --help after parse (for combined short flags)
    if ctx.is_present("help") {
        print!("{}", USAGE);
        std::process::exit(0);
    }

    if ctx.is_present("version") {
        println!("ldapvi {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    // Secret --usage: print popt auto-generated help for verification
    if ctx.is_present("usage") {
        ctx.print_help();
        std::process::exit(0);
    }

    // Read configuration profile
    let profile_name: Option<String> = ctx.get("profile").ok();
    let profile = parse_configuration(profile_name.as_deref());

    // Helper: get CLI string, falling back to profile value
    let cli_or_profile = |cli_key: &str, profile_key: &str| -> Option<String> {
        ctx.get(cli_key)
            .ok()
            .or_else(|| profile.as_ref().and_then(|p| profile_get(p, profile_key)))
    };
    // Helper: get CLI bool, falling back to profile bool
    let cli_or_profile_bool = |cli_key: &str, profile_key: &str| -> bool {
        ctx.is_present(cli_key)
            || profile
                .as_ref()
                .is_some_and(|p| profile_get_bool(p, profile_key))
    };

    // Extract scope
    let mut scope = {
        let scope_str = cli_or_profile("scope", "scope");
        match scope_str {
            Some(s) => parse_scope(&s)?,
            None => ldap3::Scope::Subtree,
        }
    };

    // Extract deref
    let deref = {
        let deref_str = cli_or_profile("deref", "deref");
        match deref_str {
            Some(s) => parse_deref(&s)?,
            None => 0,
        }
    };

    // Extract mode
    let mode_val: i32 = ctx.get("mode").unwrap_or(0);
    let mode = match mode_val {
        OPTION_OUT | OPTION_LDAPSEARCH => Mode::Out,
        OPTION_IN | OPTION_LDAPMODIFY => Mode::In,
        OPTION_DELETE | OPTION_LDAPDELETE => Mode::Delete,
        OPTION_RENAME | OPTION_LDAPMODDN => Mode::Rename,
        OPTION_MODRDN | OPTION_LDAPMODRDN => Mode::Modrdn,
        _ => Mode::Edit,
    };

    // Apply shortcut side effects
    let mut quiet = cli_or_profile_bool("quiet", "quiet");
    let mut noninteractive = cli_or_profile_bool("noninteractive", "noninteractive");
    match mode_val {
        OPTION_LDAPSEARCH => {
            quiet = true;
            noninteractive = true;
        }
        OPTION_LDAPMODIFY | OPTION_LDAPDELETE | OPTION_LDAPMODDN | OPTION_LDAPMODRDN => {
            noninteractive = true;
        }
        _ => {}
    }

    // SASL option side effects
    let mut bind: Option<String> = cli_or_profile("bind", "bind");
    if ctx.is_present("sasl-interactive") || ctx.is_present("sasl-quiet") {
        bind = Some("sasl".to_string());
    }

    // Format
    let ldif = cli_or_profile_bool("ldif", "ldif");

    // Basedns: CLI --base overrides profile bases (not additive)
    let cli_basedns: Vec<String> = ctx.get("base").unwrap_or_default();
    let mut basedns = if !cli_basedns.is_empty() {
        cli_basedns
    } else {
        profile
            .as_ref()
            .map_or_else(Vec::new, |p| profile_get_all(p, "base"))
    };

    // Classes (repeatable -o)
    let classes: Vec<String> = ctx.get("class").unwrap_or_default();

    // Positional args — interpretation depends on mode
    let positional = ctx.args();

    let mut filter = "(objectclass=*)".to_string();
    let mut attrs = vec![];
    let mut delete_dns = vec![];
    let mut rename_old = None;
    let mut rename_new = None;
    let mut in_file = None;

    // Profile can set filter and attrs as defaults
    if let Some(ref p) = profile {
        if let Some(f) = profile_get(p, "filter") {
            filter = f;
        }
        let profile_attrs = profile_get_all(p, "ad");
        if !profile_attrs.is_empty() {
            attrs = profile_attrs;
        }
    }

    match mode {
        Mode::Edit | Mode::Out => {
            if let Some(f) = positional.first() {
                filter = f.clone();
            }
            if positional.len() > 1 {
                attrs = positional[1..].to_vec();
            }
        }
        Mode::Delete => {
            delete_dns = positional;
        }
        Mode::Rename | Mode::Modrdn => {
            if positional.len() > 2 {
                return Err("too many command line arguments".to_string());
            }
            rename_old = positional.first().cloned();
            rename_new = positional.get(1).cloned();
        }
        Mode::In => {
            if positional.len() > 1 {
                return Err("too many command line arguments".to_string());
            }
            in_file = positional.first().cloned();
        }
    }

    // Password file handling
    let password_file: Option<String> = ctx.get("password-file").ok();
    let mut password: Option<String> = ctx
        .get("password")
        .ok()
        .or_else(|| profile.as_ref().and_then(|p| profile_get(p, "password")));
    if let Some(ref path) = password_file {
        let content = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
        let pw = content.lines().next().unwrap_or("").to_string();
        password = Some(pw);
    }

    // --read DN handling
    if let Ok(dn) = ctx.get::<String>("read") {
        basedns.push(dn);
        scope = ldap3::Scope::Base;
        filter = "(objectclass=*)".to_string();
        attrs = vec!["+".to_string(), "*".to_string()];
    }

    // --class implies --empty
    let empty = cli_or_profile_bool("empty", "empty") || !classes.is_empty();

    Ok(Cmdline {
        server: cli_or_profile("host", "host"),
        basedns,
        scope,
        filter,
        attrs,
        user: cli_or_profile("user", "user"),
        password,
        quiet,
        discover: cli_or_profile_bool("discover", "discover"),
        starttls: cli_or_profile_bool("starttls", "starttls"),
        deref,
        managedsait: cli_or_profile_bool("managedsait", "managedsait"),
        continuous: cli_or_profile_bool("continuous", "continuous"),
        sortkeys: cli_or_profile("sort", "sort"),
        ldif,
        mode,
        in_file,
        verbose: cli_or_profile_bool("verbose", "verbose"),
        noquestions: ctx.is_present("noquestions"),
        noninteractive,
        encoding: cli_or_profile("encoding", "encoding"),
        delete_dns,
        rename_old,
        rename_new,
        deleteoldrdn: ctx.is_present("deleteoldrdn"),
        bind,
        tls: cli_or_profile("tls", "tls"),
        password_file,
        schema_comments: cli_or_profile_bool("may", "may"),
        config: ctx.is_present("config"),
        empty,
        ldapmodify_add: ctx.is_present("add"),
        classes,
        ldap_conf: ctx.is_present("ldap-conf"),
        profile: profile_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- find_profile tests --

    #[test]
    fn find_named_profile() {
        let config = b"profile myprofile\n\
                        host: ldapi:///\n\
                        base: dc=example,dc=com\n\
                        \n";
        let entry = find_profile(config, "myprofile").unwrap().unwrap();
        assert_eq!(entry.dn, "myprofile");
        assert_eq!(profile_get(&entry, "host").as_deref(), Some("ldapi:///"));
    }

    #[test]
    fn find_default_profile() {
        let config = b"profile default\n\
                        host: localhost\n\
                        \n";
        let entry = find_profile(config, "default").unwrap().unwrap();
        assert_eq!(profile_get(&entry, "host").as_deref(), Some("localhost"));
    }

    #[test]
    fn find_profile_not_found() {
        let config = b"profile other\n\
                        host: localhost\n\
                        \n";
        assert!(find_profile(config, "myprofile").unwrap().is_none());
    }

    #[test]
    fn find_profile_no_profiles() {
        assert!(find_profile(b"", "default").unwrap().is_none());
    }

    #[test]
    fn find_profile_duplicate_is_error() {
        let config = b"profile dup\n\
                        host: first\n\
                        \n\
                        profile dup\n\
                        host: second\n\
                        \n";
        assert!(find_profile(config, "dup").is_err());
    }

    #[test]
    fn find_profile_among_multiple() {
        let config = b"profile alpha\n\
                        host: alpha-host\n\
                        \n\
                        profile beta\n\
                        host: beta-host\n\
                        \n";
        let entry = find_profile(config, "beta").unwrap().unwrap();
        assert_eq!(profile_get(&entry, "host").as_deref(), Some("beta-host"));
    }

    // -- profile_get / profile_get_all / profile_get_bool --

    #[test]
    fn profile_get_single_value() {
        let config = b"profile test\n\
                        scope: sub\n\
                        \n";
        let entry = find_profile(config, "test").unwrap().unwrap();
        assert_eq!(profile_get(&entry, "scope").as_deref(), Some("sub"));
        assert_eq!(profile_get(&entry, "nonexistent"), None);
    }

    #[test]
    fn profile_get_all_multi_value() {
        let config = b"profile test\n\
                        base: dc=one,dc=com\n\
                        base: dc=two,dc=com\n\
                        base: dc=three,dc=com\n\
                        \n";
        let entry = find_profile(config, "test").unwrap().unwrap();
        let bases = profile_get_all(&entry, "base");
        assert_eq!(
            bases,
            vec!["dc=one,dc=com", "dc=two,dc=com", "dc=three,dc=com",]
        );
    }

    #[test]
    fn profile_get_all_missing_key() {
        let config = b"profile test\n\
                        host: localhost\n\
                        \n";
        let entry = find_profile(config, "test").unwrap().unwrap();
        assert!(profile_get_all(&entry, "base").is_empty());
    }

    #[test]
    fn profile_get_bool_yes() {
        let config = b"profile test\n\
                        discover: yes\n\
                        quiet: no\n\
                        \n";
        let entry = find_profile(config, "test").unwrap().unwrap();
        assert!(profile_get_bool(&entry, "discover"));
        assert!(!profile_get_bool(&entry, "quiet"));
        assert!(!profile_get_bool(&entry, "nonexistent"));
    }

    // -- base override logic --
    // These test the core rule: CLI bases replace profile bases.

    #[test]
    fn base_override_cli_only() {
        // No profile → CLI bases used as-is
        let cli_basedns = vec!["dc=cli,dc=com".to_string()];
        let profile: Option<Entry> = None;
        let basedns = if !cli_basedns.is_empty() {
            cli_basedns
        } else {
            profile
                .as_ref()
                .map_or_else(Vec::new, |p| profile_get_all(p, "base"))
        };
        assert_eq!(basedns, vec!["dc=cli,dc=com"]);
    }

    #[test]
    fn base_override_profile_only() {
        // No CLI bases → profile bases used
        let cli_basedns: Vec<String> = vec![];
        let config = b"profile default\n\
                        base: dc=profile,dc=com\n\
                        \n";
        let profile = find_profile(config, "default").unwrap();
        let basedns = if !cli_basedns.is_empty() {
            cli_basedns
        } else {
            profile
                .as_ref()
                .map_or_else(Vec::new, |p| profile_get_all(p, "base"))
        };
        assert_eq!(basedns, vec!["dc=profile,dc=com"]);
    }

    #[test]
    fn base_override_cli_replaces_profile() {
        // CLI bases replace profile bases entirely (the regression fix)
        let cli_basedns = vec!["dc=cli,dc=com".to_string()];
        let config = b"profile default\n\
                        base: dc=profile,dc=com\n\
                        \n";
        let profile = find_profile(config, "default").unwrap();
        let basedns = if !cli_basedns.is_empty() {
            cli_basedns
        } else {
            profile
                .as_ref()
                .map_or_else(Vec::new, |p| profile_get_all(p, "base"))
        };
        assert_eq!(basedns, vec!["dc=cli,dc=com"]);
    }

    #[test]
    fn base_override_cli_replaces_multiple_profile_bases() {
        let cli_basedns = vec!["dc=cli,dc=com".to_string()];
        let config = b"profile default\n\
                        base: dc=one,dc=com\n\
                        base: dc=two,dc=com\n\
                        base: dc=three,dc=com\n\
                        \n";
        let profile = find_profile(config, "default").unwrap();
        let basedns = if !cli_basedns.is_empty() {
            cli_basedns
        } else {
            profile
                .as_ref()
                .map_or_else(Vec::new, |p| profile_get_all(p, "base"))
        };
        assert_eq!(basedns, vec!["dc=cli,dc=com"]);
    }

    #[test]
    fn base_override_multiple_cli_replace_profile() {
        let cli_basedns = vec!["dc=a,dc=com".to_string(), "dc=b,dc=com".to_string()];
        let config = b"profile default\n\
                        base: dc=profile,dc=com\n\
                        \n";
        let profile = find_profile(config, "default").unwrap();
        let basedns = if !cli_basedns.is_empty() {
            cli_basedns
        } else {
            profile
                .as_ref()
                .map_or_else(Vec::new, |p| profile_get_all(p, "base"))
        };
        assert_eq!(basedns, vec!["dc=a,dc=com", "dc=b,dc=com"]);
    }

    #[test]
    fn base_override_no_base_anywhere() {
        let cli_basedns: Vec<String> = vec![];
        let profile: Option<Entry> = None;
        let basedns = if !cli_basedns.is_empty() {
            cli_basedns
        } else {
            profile
                .as_ref()
                .map_or_else(Vec::new, |p| profile_get_all(p, "base"))
        };
        assert!(basedns.is_empty());
    }
}
