/* -*- mode: c; c-backslash-column: 78; c-backslash-max-column: 78 -*-
 *
 * Copyright (c) 2003,2004,2005,2006 David Lichteblau
 * Copyright (c) 2006 Perry Nguyen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <popt.h>
#include "common.h"
#include "version.h" 

static void parse_configuration(char *, cmdline *, GPtrArray *);

#define USAGE								      \
"Usage: ldapvi [OPTION]... [FILTER] [AD]...\n"				      \
"Quickstart:\n"								      \
"       ldapvi --discover --host HOSTNAME\n"				      \
"Perform an LDAP search and update results using a text editor.\n"	      \
"\n"									      \
"Other usage:\n"							      \
"       ldapvi --out [OPTION]... [FILTER] [AD]...  Print entries\n"	      \
"       ldapvi --in [OPTION]... [FILENAME]         Load change records\n"     \
"       ldapvi --delete [OPTION]... DN...          Edit a delete record\n"    \
"       ldapvi --rename [OPTION]... DN1 DN2        Edit a rename record\n"    \
"\n"									      \
"Configuration profiles:\n"						      \
"  -p, --profile NAME     Section of ~/.ldapvirc or /etc/ldap.conf to use.\n" \
"\n"									      \
"Connection options:\n"							      \
"  -h, --host URL         Server.\n"					      \
"  -D, --user USER        Search filter or DN: User to bind as.     [1]\n"    \
"                         Sets --bind simple.\n"                              \
"  -w, --password SECRET  Password (also valid for SASL).\n"		      \
"  -y, --password-file FILE  Password file (also valid for SASL).\n"	      \
"      --bind [simple,sasl]\n"						      \
"                         Disable or enable SASL.\n"			      \
"      --bind-dialog [never,auto,always]\n"				      \
"                         Interactive login dialog.\n"			      \
"\n"									      \
"SASL options (these parameters set --bind sasl):\n"                          \
"  -I, --sasl-interactive Set --bind-dialog always.\n"		              \
"  -O, --sasl-secprops P  SASL security properties.\n"			      \
"  -Q, --sasl-quiet       Set --bind-dialog never.\n"		              \
"  -R, --sasl-realm    R  SASL realm.\n"				      \
"  -U, --sasl-authcid AC  SASL authentication identity.\n"		      \
"  -X, --sasl-authzid AZ  SASL authorization identity.\n"		      \
"  -Y, --sasl-mech  MECH  SASL mechanism.\n"				      \
"\n"									      \
"Search parameters:\n"							      \
"  -b, --base DN          Search base.\n"				      \
"  -s, --scope SCOPE      Search scope.  One of base|one|sub.\n"	      \
"  -S, --sort KEYS        Sort control (critical).\n"			      \
"\n"									      \
"Miscellaneous options:\n"						      \
"      --add              (Only with --in, --ldapmodify:)\n"		      \
"                         Treat attrval records as new entries to add.\n"     \
"  -o, --class OBJCLASS   Class to add.  Can be repeated.  Implies -A.\n"     \
"      --config           Print parameters in ldap.conf syntax.\n"	      \
"  -c  --continue         Ignore LDAP errors and continue processing.\n"      \
"      --deleteoldrdn     (Only with --rename:) Delete the old RDN.\n"	      \
"  -a, --deref            never|searching|finding|always\n"		      \
"  -d, --discover         Auto-detect naming contexts.              [2]\n"    \
"  -A, --empty            Don't search, start with empty file.  See -o.\n"    \
"      --encoding [ASCII|UTF-8|binary]\n"				      \
"                         The encoding to allow.  Default is UTF-8.\n"	      \
"  -H, --help             This help.\n"					      \
"      --ldap-conf        Always read libldap configuration.\n"		      \
"  -m, --may              Show missing optional attributes as comments.\n"    \
"  -M, --managedsait      manageDsaIT control (critical).\n"		      \
"      --noquestions      Commit without asking for confirmation.\n"	      \
"  -!, --noninteractive   Never ask any questions.\n"			      \
"  -q, --quiet            Disable progress output.\n"			      \
"  -R, --read DN          Same as -b DN -s base '(objectclass=*)' + *\n"      \
"  -Z, --starttls         Require startTLS.\n"				      \
"      --tls [never|allow|try|strict]  Level of TLS strictess.\n"	      \
"  -v, --verbose          Note every update.\n"				      \
"\n"									      \
"Shortcuts:\n"								      \
"      --ldapsearch       Short for --quiet --out\n"			      \
"      --ldapmodify       Short for --noninteractive --in\n"		      \
"      --ldapdelete       Short for --noninteractive --delete\n"	      \
"      --ldapmoddn        Short for --noninteractive --rename\n"	      \
"\n"									      \
"Environment variables: VISUAL, EDITOR, PAGER.\n"			      \
"\n"									      \
"[1] User names can be specified as distinguished names:\n"		      \
"      uid=foo,ou=bar,dc=acme,dc=com\n"					      \
"    or search filters:\n"						      \
"      (uid=foo)\n"							      \
"    Note the use of parenthesis, which can be omitted from search\n"	      \
"    filters usually but are required here.  For this searching bind to\n"    \
"    work, your client library must be configured with appropriate\n"	      \
"    default search parameters.\n"					      \
"\n"									      \
"[2] Repeat the search for each naming context found and present the\n"	      \
"    concatenation of all search results.  Conflicts with --base.\n"	      \
"    With --config, show a BASE configuration line for each context.\n"	      \
"\n"									      \
"A special (offline) option is --diff, which compares two files\n"	      \
"and writes any changes to standard output in LDIF format.\n"		      \
"\n"									      \
"Report bugs to \"ldapvi@lists.askja.de\"."

enum ldapvi_option_numbers {
	OPTION_TLS = 1000, OPTION_ENCODING, OPTION_LDIF, OPTION_LDAPVI,
	OPTION_OUT, OPTION_IN, OPTION_DELETE, OPTION_RENAME, OPTION_MODRDN,
	OPTION_NOQUESTIONS, OPTION_LDAPSEARCH, OPTION_LDAPMODIFY,
	OPTION_LDAPDELETE, OPTION_LDAPMODDN, OPTION_LDAPMODRDN, OPTION_ADD,
	OPTION_CONFIG, OPTION_READ, OPTION_LDAP_CONF, OPTION_BIND,
	OPTION_BIND_DIALOG, OPTION_UNPAGED_HELP
};

static struct poptOption options[] = {
	{"host",	'h', POPT_ARG_STRING, 0, 'h', 0, 0},
	{"scope",	's', POPT_ARG_STRING, 0, 's', 0, 0},
	{"base",	'b', POPT_ARG_STRING, 0, 'b', 0, 0},
	{"user",	'D', POPT_ARG_STRING, 0, 'D', 0, 0},
	{"sasl-interactive",'I',0, 0, 'I', 0, 0},
	{"sasl-quiet"  ,'Q',0, 0, 'Q', 0, 0},
	{"sasl-secprops",'O', POPT_ARG_STRING, 0, 'O', 0, 0},
	{"sasl-realm",	'R', POPT_ARG_STRING, 0, 'R', 0, 0},
	{"sasl-mech",	'Y', POPT_ARG_STRING, 0, 'Y', 0, 0},
	{"sasl-authzid",'X', POPT_ARG_STRING, 0, 'X', 0, 0},
	{"sasl-authcid",'U', POPT_ARG_STRING, 0, 'U', 0, 0},
	{"password",	'w', POPT_ARG_STRING, 0, 'w', 0, 0},
	{"password-file",'y',POPT_ARG_STRING, 0, 'y', 0, 0},
	{"chase",	'C', POPT_ARG_STRING, 0, 'C', 0, 0},
	{"deref",	'a', POPT_ARG_STRING, 0, 'a', 0, 0},
	{"sort",	'S', POPT_ARG_STRING, 0, 'S', 0, 0},
	{"class",	'o', POPT_ARG_STRING, 0, 'o', 0, 0},
	{"read",	  0, POPT_ARG_STRING, 0, OPTION_READ, 0, 0},
	{"profile",	'p', POPT_ARG_STRING, 0, 'p', 0, 0},
	{"tls",		  0, POPT_ARG_STRING, 0, OPTION_TLS, 0, 0},
	{"encoding",	  0, POPT_ARG_STRING, 0, OPTION_ENCODING, 0, 0},
	{"bind",	  0, POPT_ARG_STRING, 0, OPTION_BIND, 0, 0},
	{"bind-dialog",	  0, POPT_ARG_STRING, 0, OPTION_BIND_DIALOG, 0, 0},
	{"continuous",	'c', 0, 0, 'c', 0, 0},
	{"continue",	'c', 0, 0, 'c', 0, 0},
	{"empty",	'A', 0, 0, 'A', 0, 0},
	{"discover",	'd', 0, 0, 'd', 0, 0},
	{"quiet",	'q', 0, 0, 'q', 0, 0},
	{"verbose",	'v', 0, 0, 'v', 0, 0},
	{"managedsait",	'M', 0, 0, 'M', 0, 0},
	{"may",		'm', 0, 0, 'm', 0, 0},
	{"starttls",	'Z', 0, 0, 'Z', 0, 0},
	{"help",	'H', 0, 0, 'H', 0, 0},
	{"version",	'V', 0, 0, 'V', 0, 0},
	{"noninteractive", '!', 0, 0, '!', 0, 0},
	{"deleteoldrdn", 'r', 0, 0, 'r', 0, 0},
	{"add",		  0, 0, 0, OPTION_ADD, 0, 0},
	{"config",	  0, 0, 0, OPTION_CONFIG, 0, 0},
	{"noquestions",   0, 0, 0, OPTION_NOQUESTIONS, 0, 0},
	{"ldap-conf",     0, 0, 0, OPTION_LDAP_CONF, 0, 0},
	{"ldif",	  0, 0, 0, OPTION_LDIF, 0, 0},
	{"ldapvi",	  0, 0, 0, OPTION_LDAPVI, 0, 0},
	{"out",		  0, 0, 0, OPTION_OUT, 0, 0},
	{"in",		  0, 0, 0, OPTION_IN, 0, 0},
	{"delete",	  0, 0, 0, OPTION_DELETE, 0, 0},
	{"rename",	  0, 0, 0, OPTION_RENAME, 0, 0},
	{"modrdn",	  0, 0, 0, OPTION_MODRDN, 0, 0},
	{"ldapsearch",	  0, 0, 0, OPTION_LDAPSEARCH, 0, 0},
	{"ldapmodify",	  0, 0, 0, OPTION_LDAPMODIFY, 0, 0},
	{"ldapdelete",	  0, 0, 0, OPTION_LDAPDELETE, 0, 0},
	{"ldapmoddn",	  0, 0, 0, OPTION_LDAPMODDN, 0, 0},
	{"ldapmodrdn",	  0, 0, 0, OPTION_LDAPMODRDN, 0, 0},
	{"unpaged-help",  0, 0, 0, OPTION_UNPAGED_HELP, 0, 0},
	{0, 0, 0, 0, 0}
};


static int usage_pagerp = 1;

void
usage(int fd, int rc)
{
	if (usage_pagerp && fd == -1 && rc == 0 && isatty(1)) {
		int fd;
		int pid = pipeview(&fd);
		write(fd, USAGE, strlen(USAGE));
		close(fd);
		pipeview_wait(pid);
	} else {
		if (fd != -1) dup2(fd, 1);
		puts(USAGE);
	}
	if (rc != -1) exit(rc);
}

void
init_cmdline(cmdline *cmdline)
{
	cmdline->server = 0;
	cmdline->basedns = g_ptr_array_new();
	cmdline->scope = LDAP_SCOPE_SUBTREE;
	cmdline->filter = 0;
	cmdline->attrs = 0;
	cmdline->quiet = 0;
	cmdline->referrals = 1;
	cmdline->classes = 0;
	cmdline->ldapmodify_add = 0;
	cmdline->managedsait = 0;
	cmdline->sortkeys = 0;
	cmdline->starttls = 0;
	cmdline->tls = LDAP_OPT_X_TLS_TRY;
	cmdline->deref = LDAP_DEREF_NEVER;
	cmdline->verbose = 0;
	cmdline->noquestions = 0;
	cmdline->noninteractive = 0;
	cmdline->discover = 0;
	cmdline->config = 0;
	cmdline->ldif = 0;
	cmdline->ldapvi = 0;
	cmdline->mode = ldapvi_mode_edit;
	cmdline->rename_dor = 0;
	cmdline->schema_comments = 0;
	cmdline->continuous = 0;
	cmdline->profileonlyp = 0;

        cmdline->bind_options.authmethod = LDAP_AUTH_SIMPLE;
        cmdline->bind_options.dialog = BD_AUTO;
        cmdline->bind_options.user = 0;
        cmdline->bind_options.password = 0;
        cmdline->bind_options.sasl_authcid = 0;
        cmdline->bind_options.sasl_authzid = 0;
        cmdline->bind_options.sasl_mech = 0;
        cmdline->bind_options.sasl_realm = 0;
        cmdline->bind_options.sasl_secprops = 0;
}

static void
read_password_file(bind_options *bind_options, char *filename)
{
	struct stat st;
	int fd;
	char *data;
	char *ptr;

	if (stat(filename, &st) == -1) {
		fprintf(stderr, "Failed to stat password file: %s\n",
			filename);
		exit(1);
	}
	data = xalloc(st.st_size + 1);
	if ( (fd = open(filename, O_RDONLY)) == -1) syserr();
	if (read(fd, data, st.st_size) != st.st_size) syserr();
	close(fd);
	data[st.st_size] = 0;
	if ( (ptr = strchr(data, '\n')))
	     *ptr = 0;

	bind_options->password = data;
}

static void
parse_argument(int c, char *arg, cmdline *result, GPtrArray *ctrls)
{
	LDAPControl *control;

	switch (c) {
	case 'H':
		usage(-1, 0);
	case 'h':
		result->server = arg;
		break;
	case 's':
		if (!strcmp(arg, "base"))
			result->scope = LDAP_SCOPE_BASE;
		else if (!strcmp(arg, "one"))
			result->scope = LDAP_SCOPE_ONELEVEL;
		else if (!strcmp(arg, "sub"))
			result->scope = LDAP_SCOPE_SUBTREE;
		else {
			fprintf(stderr, "invalid scope: %s\n", arg);
			usage(2, 1);
		}
		break;
	case 'b':
		g_ptr_array_add(result->basedns, arg);
		break;
	case 'D':
		result->bind_options.authmethod = LDAP_AUTH_SIMPLE;
		result->bind_options.user = *arg ? arg : 0;
		break;
	case 'w':
		result->bind_options.password = arg;
		break;
	case 'y':
		read_password_file(&result->bind_options, arg);
		break;
	case 'd':
		result->discover = 1;
		break;
	case 'c':
		result->continuous = 1;
		break;
	case OPTION_CONFIG:
		result->config = 1;
		break;
	case 'q':
		result->quiet = 1;
		break;
	case 'A':
		if (!result->classes)
			result->classes = g_ptr_array_new();
		break;
	case 'o':
		if (!result->classes)
			result->classes = g_ptr_array_new();
		adjoin_str(result->classes, arg);
		break;
	case 'C':
		if (!strcasecmp(arg, "yes"))
			result->referrals = 1;
		else if (!strcasecmp(arg, "no"))
			result->referrals = 0;
		else {
			fprintf(stderr, "--chase invalid%s\n", arg);
			usage(2, 1);
		}
		break;
	case 'm':
		result->schema_comments = 1;
		break;
	case 'M':
		result->managedsait = 1;
		control = malloc(sizeof(LDAPControl));
		control->ldctl_oid = LDAP_CONTROL_MANAGEDSAIT;
		control->ldctl_value.bv_len = 0;
		control->ldctl_value.bv_val = 0;
		control->ldctl_iscritical = 1;
		g_ptr_array_add(ctrls, control);
		break;
	case 'V':
		puts("ldapvi " VERSION);
		exit(0);
	case 'S':
		result->sortkeys = arg;
		break;
	case 'Z':
		result->starttls = 1;
		break;
	case OPTION_TLS:
		if (!strcmp(arg, "never"))
			result->tls = LDAP_OPT_X_TLS_NEVER;
		else if (!strcmp(arg, "allow"))
			result->tls = LDAP_OPT_X_TLS_ALLOW;
		else if (!strcmp(arg, "try"))
			result->tls = LDAP_OPT_X_TLS_TRY;
		else if (!strcmp(arg, "strict"))
			result->tls = LDAP_OPT_X_TLS_HARD;
		else {
			fprintf(stderr, "invalid tls level: %s\n",
				arg);
			usage(2, 1);
		}
		break;
	case OPTION_ENCODING:
		if (!strcasecmp(arg, "ASCII"))
			print_binary_mode = PRINT_ASCII;
		else if (!strcasecmp(arg, "binary"))
			print_binary_mode = PRINT_JUNK;
		else if (!strcasecmp(arg, "UTF-8")
			 || !strcasecmp(arg, "UTF_8")
			 || !strcasecmp(arg, "UTF8"))
			print_binary_mode = PRINT_UTF8;
		else {
			fprintf(stderr, "invalid encoding: %s\n", arg);
			usage(2, 1);
		}
		break;
	case OPTION_LDIF:
		result->ldif = 1;
		break;
	case OPTION_LDAPVI:
		result->ldapvi = 1;
		break;
	case OPTION_ADD:
		result->ldapmodify_add = 1;
		break;

	case OPTION_LDAPSEARCH:
		result->quiet = 1;
		result->noninteractive = 1;
		/* fall through */
	case OPTION_OUT:
		result->mode = ldapvi_mode_out;
		break;

	case OPTION_LDAPMODIFY:
		result->noninteractive = 1;
		/* fall through */
	case OPTION_IN:
		result->mode = ldapvi_mode_in;
		break;

	case OPTION_LDAPDELETE:
		result->noninteractive = 1;
		/* fall through */
	case OPTION_DELETE:
		result->mode = ldapvi_mode_delete;
		break;

	case OPTION_LDAPMODDN:
		result->noninteractive = 1;
		/* fall through */
	case OPTION_RENAME:
		result->mode = ldapvi_mode_rename;
		break;

	case OPTION_LDAPMODRDN:
		result->noninteractive = 1;
		/* fall through */
	case OPTION_MODRDN:
		result->mode = ldapvi_mode_modrdn;
		break;

	case 'r':
		result->rename_dor = 1;
		break;
	case OPTION_READ:
		g_ptr_array_add(result->basedns, arg);
		result->scope = LDAP_SCOPE_BASE;
		result->filter = "(objectclass=*)";
		{
			static char *attrs[3] = {"+", "*", 0};
			result->attrs = attrs;
		}
		break;
	case 'a':
		if (!strcasecmp(arg, "never"))
			result->deref = LDAP_DEREF_NEVER;
		else if (!strcasecmp(arg, "searching"))
			result->deref = LDAP_DEREF_SEARCHING;
		else if (!strcasecmp(arg, "finding"))
			result->deref = LDAP_DEREF_FINDING;
		else if (!strcasecmp(arg, "always"))
			result->deref = LDAP_DEREF_ALWAYS;
		else {
			fprintf(stderr, "--deref invalid: %s\n", arg);
			usage(2, 1);
		}
		break;
	case 'v':
		result->verbose = 1;
		break;
	case OPTION_BIND:
		if (!strcasecmp(arg, "simple"))
			result->bind_options.authmethod = LDAP_AUTH_SIMPLE;
		else if (!strcasecmp(arg, "sasl"))
			result->bind_options.authmethod = LDAP_AUTH_SASL;
		else {
			fprintf(stderr, "--bind invalid: %s\n", arg);
			usage(2, 1);
		}
		break;
	case OPTION_BIND_DIALOG:
		if (!strcasecmp(arg, "always"))
			result->bind_options.dialog = BD_ALWAYS;
		else if (!strcasecmp(arg, "auto"))
			result->bind_options.dialog = BD_AUTO;
		else if (!strcasecmp(arg, "never"))
			result->bind_options.dialog = BD_NEVER;
		else {
			fprintf(stderr, "--bind-dialog invalid: %s\n", arg);
			usage(2, 1);
		}
		break;
	case 'I':
		result->bind_options.authmethod = LDAP_AUTH_SASL;
		result->bind_options.dialog = BD_ALWAYS;
		break;
	case 'Q':
		result->bind_options.authmethod = LDAP_AUTH_SASL;
		result->bind_options.dialog = BD_NEVER;
		break;
	case 'U':
		result->bind_options.authmethod = LDAP_AUTH_SASL;
		result->bind_options.sasl_authcid = arg;
		break;
	case 'X':
		result->bind_options.authmethod = LDAP_AUTH_SASL;
		result->bind_options.sasl_authzid = arg;
		break;
	case 'Y':
		result->bind_options.authmethod = LDAP_AUTH_SASL;
		result->bind_options.sasl_mech = arg;
		break;
	case 'R':
		result->bind_options.authmethod = LDAP_AUTH_SASL;
		result->bind_options.sasl_realm = arg;
		break;
	case 'O':
		result->bind_options.authmethod = LDAP_AUTH_SASL;
		result->bind_options.sasl_secprops = arg;
		break;
	case '!':
		result->noninteractive = 1;
		break;
	case OPTION_NOQUESTIONS:
		result->noquestions = 1;
		break;
	case OPTION_LDAP_CONF:
		result->profileonlyp = 0;
		break;
	case OPTION_UNPAGED_HELP:
		usage_pagerp = 0;
		break;
	case 'p':
		parse_configuration(arg, result, ctrls);
		break;
	default:
		abort();
	}
}

static void
parse_profile_line(tattribute *attribute, cmdline *result, GPtrArray *ctrls)
{
	char *name = attribute_ad(attribute);
	GPtrArray *values = attribute_values(attribute);
	int i;
	struct poptOption *o = 0;

	if (!strcmp(name, "filter")) {
		int last = values->len - 1;
		result->filter = array2string(g_ptr_array_index(values, last));
		return;
	}
	if (!strcmp(name, "ad")) {
		int n = values->len;
		char **attrs = xalloc((n + 1) * sizeof(char *));
		for (i = 0; i < n; i++)
			attrs[i] = array2string(g_ptr_array_index(values, i));
		attrs[n] = 0;
		result->attrs = attrs;
		return;
	}

	for (i = 0; options[i].longName; i++)
		if (!strcmp(name, options[i].longName)) {
			o = &options[i];
			break;
		}
	if (!o) {
		fprintf(stderr, "Error: unknown configuration option: '%s'\n",
			name);
		exit(1);
	}

	for (i = 0; i < values->len; i++) {
		char *value = array2string(g_ptr_array_index(values, i));
		if (o->argInfo == 0)
			if (!strcmp(value, "no"))
				continue;
			else if (strcmp(value, "yes")) {
				fprintf(stderr,
					"invalid value '%s' to configuration"
					" option '%s', expected 'yes' or"
					" 'no'.\n",
					value,
					name);
				exit(1);
			}
		parse_argument(o->val, value, result, ctrls);
	}
}

static void
parse_configuration(char *profile_name, cmdline *result, GPtrArray *ctrls)
{
	struct stat st;
	char *profile_requested = profile_name;
	char *filename = home_filename(".ldapvirc");
	FILE *s;
	tentry *p;
	tentry *profile_found = 0;
	int duplicate = 0;

	if (!profile_name)
		profile_name = "default";

	if (!filename || stat(filename, &st)) {
		filename = "/etc/ldapvi.conf";
		if (stat(filename, &st))
			filename = 0;
	}
	if (!filename) {
		if (profile_requested) {
			fputs("Error: ldapvi configuration file not found.\n",
			      stderr);
			exit(1);
		}
		return;
	}

	if ( !(s = fopen(filename, "r"))) syserr();
	for (;;) {
		p = 0;
		if (read_profile(s, &p)) {
			fputs("Error in configuration file, giving up.\n",
			      stderr);
			exit(1);
		}
		if (!p)
			break;
		if (strcmp(entry_dn(p), profile_name))
			entry_free(p);
		else if (profile_found)
			duplicate = 1;
		else
			profile_found = p;
	}
	if (duplicate) {
		fprintf(stderr,
			"Error: Duplicate configuration profile '%s'.\n",
			profile_name);
		exit(1);
	}
	if (profile_found) {
		result->profileonlyp = 1;
		GPtrArray *attributes = entry_attributes(profile_found);
		int i;
		for (i = 0; i < attributes->len; i++) {
			tattribute *a = g_ptr_array_index(attributes, i);
			parse_profile_line(a, result, ctrls);
		}
		entry_free(profile_found);
	} else if (profile_requested) {
		fprintf(stderr,
			"Error: Configuration profile not found: '%s'.\n",
			profile_name);
		exit(1);
	}
	if (fclose(s) == EOF) syserr();
}

void
parse_arguments(int argc, const char **argv, cmdline *result, GPtrArray *ctrls)
{
	int c;
	poptContext ctx;
	char *profile = 0;

	ctx = poptGetContext(
		0, argc, argv, options, POPT_CONTEXT_POSIXMEHARDER);

	while ( (c = poptGetNextOpt(ctx)) > 0) {
		char *arg = (char *) poptGetOptArg(ctx);
		if (c != 'p') continue;
		if (profile) {
			fputs("Multiple profile options given.\n", stderr);
			usage(2, 1);
		}
		profile = arg;
	}
	parse_configuration(profile, result, ctrls);

	{
		int profile_basedns = result->basedns->len;
		int cleared_bases = 0;

		poptResetContext(ctx);
		while ( (c = poptGetNextOpt(ctx)) > 0) {
			char *arg = (char *) poptGetOptArg(ctx);
			if (c == 'p') continue;
			if (c == 'b' && !cleared_bases && profile_basedns) {
				g_ptr_array_remove_range(
					result->basedns, 0, profile_basedns);
				cleared_bases = 1;
			}
			parse_argument(c, arg, result, ctrls);
		}
	}
	if (c != -1) {
		fprintf(stderr, "%s: %s\n",
			poptBadOption(ctx, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		usage(2, 1);
	}

	if (result->classes
	    && result->mode != ldapvi_mode_edit
	    && result->mode != ldapvi_mode_out)
	{
		fputs("Error: Conflicting options given;"
		      " cannot use --class in this mode.\n",
		      stderr);
		exit(1);
	}

	switch (result->mode) {
	case ldapvi_mode_edit: /* fall through */
	case ldapvi_mode_out:
		if (!result->filter)
			result->filter = (char *) poptGetArg(ctx);
		if (!result->attrs)
			result->attrs = (char **) poptGetArgs(ctx);
		break;
	case ldapvi_mode_delete:
		result->delete_dns = (char **) poptGetArgs(ctx);
		break;
	case ldapvi_mode_rename: /* fall through */
	case ldapvi_mode_modrdn:
		result->rename_old = (char *) poptGetArg(ctx);
		result->rename_new = (char *) poptGetArg(ctx);
		if (poptGetArg(ctx)) {
			fputs("Error: Too many command line arguments.\n",
			      stderr);
			exit(1);
		}
		break;
	case ldapvi_mode_in:
		result->in_file = (char *) poptGetArg(ctx);
		if (poptGetArg(ctx)) {
			fputs("Error: Too many command line arguments.\n",
			      stderr);
			exit(1);
		}
		break;
	default:
		abort();
	}

	if (result->profileonlyp)
		if (putenv("LDAPNOINIT=thanks")) syserr();

	/* don't free! */
/* 	poptFreeContext(ctx); */
}
