/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
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
#include <curses.h>
#include <signal.h>
#include <term.h>
#include "common.h"

typedef void (*handler_entry)(char *, tentry *, void *);
static void parse_file(
	FILE *, tparser *, thandler *, void *, handler_entry, void *, int);
static void cut_datafile(char *, long, cmdline *);
static int write_file_header(FILE *, cmdline *);
static int rebind(LDAP *, bind_options *, int, char *, int);

static int
compare(tparser *p, thandler *handler, void *userdata, GArray *offsets,
	char *cleanname, char *dataname, long *error_position,
	cmdline *cmdline)
{
	FILE *clean, *data;
	int rc;
	long pos;

	if ( !(clean = fopen(cleanname, "r+"))) syserr();
	if ( !(data = fopen(dataname, "r"))) syserr();
	rc = compare_streams(p, handler, userdata, offsets, clean, data, &pos,
			     error_position);
	if (fclose(clean) == EOF) syserr();
	if (fclose(data) == EOF) syserr();

	if (rc == -2) {
		/* an error has happened */
		int n;

		if (!cmdline) {
			fputs("error: unexpected error in handler\n", stderr);
			exit(1);
		}

		/* remove already-processed entries from the data file */
		cut_datafile(dataname, pos, cmdline);

		/* flag already-processed entries in the offset table */
		for (n = 0; n < offsets->len; n++)
			if (g_array_index(offsets, long, n) < 0)
				g_array_index(offsets, long, n) = -1;
	}
	return rc;
}

static void
cleanup(int rc, char *pathname)
{
	DIR *dir;
	struct dirent *entry;
	GString *str = g_string_new(pathname);
	int len;
	struct termios term;

	/*
	 * delete temporary directory
	 */
	g_string_append(str, "/");
	len = str->len;

	if ( !(dir = opendir(pathname))) syserr();
	while ( (entry = readdir(dir)))
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")){
			g_string_truncate(str, len);
			g_string_append(str, entry->d_name);
			if (unlink(str->str) == -1) syserr();
		}
	if (closedir(dir) == -1) syserr();
	if (rmdir(pathname) == -1) syserr();
	g_string_free(str, 1);

	/*
	 * reset terminal
	 */
	if (tcgetattr(0, &term) == -1)
		/* oh, running without a terminal */
		return;
	term.c_lflag |= ICANON;
	term.c_lflag |= ECHO;
	if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
}

static void
cleanup_signal(int n)
{
	fprintf(stderr, "\nCaught signal %d, exiting...\n", n);
	exit(2);
}

static int
moddn(LDAP *ld, char *old, char *new, int dor, LDAPControl **ctrls)
{
	int rc;
	char **newrdns = ldap_explode_dn(new, 0);
	char **ptr = newrdns;
	char *newrdn = *ptr++;
	GString *newsup = g_string_sized_new(strlen(new));

	if (newrdn) {
		if (*ptr) g_string_append(newsup, *ptr++);
		for (; *ptr; ptr++) {
			g_string_append_c(newsup, ',');
			g_string_append(newsup, *ptr);
		}
	} else
		newrdn = "";
	rc = ldap_rename_s(ld, old, newrdn, newsup->str, dor, ctrls, 0);
	g_string_free(newsup, 1);
	ldap_value_free(newrdns);
	return rc;
}


/*****************************************
 * ldapmodify_handler
 */
struct ldapmodify_context {
	LDAP *ld;
	LDAPControl **controls;
	int verbose;
	int noquestions;
	int continuous;
};

static int
ldapmodify_error(struct ldapmodify_context *ctx, char *error)
{
	ldap_perror(ctx->ld, error);
	if (!ctx->continuous)
		return -1;
	fputs("(error ignored)\n", stderr);
	return 0;
}

static int
ldapmodify_change(
	int key, char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;

	if (verbose) printf("(modify) %s\n", labeldn);
	if (ldap_modify_ext_s(ld, dn, mods, ctrls, 0))
		return ldapmodify_error(ctx, "ldap_modify");
	return 0;
}

static int
ldapmodify_rename(int key, char *dn1, tentry *modified, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;

	char *dn2 = entry_dn(modified);
	int deleteoldrdn = frob_rdn(modified, dn1, FROB_RDN_CHECK) == -1;
	if (verbose) printf("(rename) %s to %s\n", dn1, dn2);
	if (moddn(ld, dn1, dn2, deleteoldrdn, ctrls))
		return ldapmodify_error(ctx, "ldap_rename");
	return 0;
}

static int
ldapmodify_add(int key, char *dn, LDAPMod **mods, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;

	if (verbose) printf("(add) %s\n", dn);
	if (ldap_add_ext_s(ld, dn, mods, ctrls, 0))
		return ldapmodify_error(ctx, "ldap_add");
	return 0;
}

static int
ldapmodify_delete(int key, char *dn, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;

	if (verbose) printf("(delete) %s\n", dn);
	switch (ldap_delete_ext_s(ld, dn, ctrls, 0)) {
	case 0:
		break;
	case LDAP_NOT_ALLOWED_ON_NONLEAF:
		if (!ctx->noquestions)
			return -2;
		/* else fall through */
	default:
		return ldapmodify_error(ctx, "ldap_delete");
	}
	return 0;
}

static int
ldapmodify_rename0(
	int key, char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	struct ldapmodify_context *ctx = userdata;
	LDAP *ld = ctx->ld;
	LDAPControl **ctrls = ctx->controls;
	int verbose = ctx->verbose;

	if (verbose) printf("(rename) %s to %s\n", dn1, dn2);
	if (moddn(ld, dn1, dn2, deleteoldrdn, ctrls))
		return ldapmodify_error(ctx, "ldap_rename");
	return 0;
}


/*****************************************
 * ldif_handler
 */
static int
ldif_change(int key, char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldif_modify(s, dn, mods);
	return 0;
}

static int
ldif_rename(int key, char *olddn, tentry *modified, void *userdata)
{
	FILE *s = userdata;
	int deleteoldrdn = frob_rdn(modified, olddn, FROB_RDN_CHECK) == -1;
	print_ldif_rename(
		s, olddn, entry_dn(modified),
		deleteoldrdn);
	return 0;
}

static int
ldif_add(int key, char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldif_add(s, dn, mods);
	return 0;
}

static int
ldif_delete(int key, char *dn, void *userdata)
{
	FILE *s = userdata;
	print_ldif_delete(s, dn);
	return 0;
}

static int
ldif_rename0(int key, char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	FILE *s = userdata;
	print_ldif_rename(s, dn1, dn2, deleteoldrdn);
	return 0;
}

static thandler ldif_handler = {
	ldif_change,
	ldif_rename,
	ldif_add,
	ldif_delete,
	ldif_rename0
};


/*****************************************
 * noop handler
 */
static int
noop_change(int key, char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	return 0;
}

static int
noop_rename(int key, char *olddn, tentry *modified, void *userdata)
{
	return 0;
}

static int
noop_add(int key, char *dn, LDAPMod **mods, void *userdata)
{
	return 0;
}

static int
noop_delete(int key, char *dn, void *userdata)
{
	return 0;
}

static int
noop_rename0(int key, char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	return 0;
}


/*****************************************
 * forget_deletions_handler
 */
static int
forget_deletion(int key, char *dn, void *userdata)
{
	GArray *deletions = userdata;
	g_array_append_val(deletions, key);
	return 0;
}

static thandler forget_deletions_handler = {
	noop_change,
	noop_rename,
	noop_add,
	forget_deletion,
	noop_rename0
};


/*****************************************
 * vdif_handler
 */
static int
vdif_change(int key, char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_modify(s, dn, mods);
	return 0;
}

static int
vdif_rename(int key, char *olddn, tentry *modified, void *userdata)
{
	FILE *s = userdata;
	int deleteoldrdn = frob_rdn(modified, olddn, FROB_RDN_CHECK) == -1;
	print_ldapvi_rename(s, olddn, entry_dn(modified), deleteoldrdn);
	return 0;
}

static int
vdif_add(int key, char *dn, LDAPMod **mods, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_add(s, dn, mods);
	return 0;
}

static int
vdif_delete(int key, char *dn, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_delete(s, dn);
	return 0;
}

static int
vdif_rename0(int key, char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	FILE *s = userdata;
	print_ldapvi_rename(s, dn1, dn2, deleteoldrdn);
	return 0;
}


/*****************************************
 * statistics_handler
 */
struct statistics {
	int nmodify, nadd, ndelete, nrename;
};

static int
statistics_change(
	int key, char *labeldn, char *dn, LDAPMod **mods, void *userdata)
{
	struct statistics *st = userdata;
	st->nmodify++;
	return 0;
}

static int
statistics_rename(int key, char *olddn, tentry *modified, void *userdata)
{
	struct statistics *st = userdata;
	st->nrename++;
	return 0;
}

static int
statistics_add(int key, char *dn, LDAPMod **mods, void *userdata)
{
	struct statistics *st = userdata;
	st->nadd++;
	return 0;
}

static int
statistics_delete(int key, char *dn, void *userdata)
{
	struct statistics *st = userdata;
	st->ndelete++;
	return 0;
}

static int
statistics_rename0(
	int key, char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	struct statistics *st = userdata;
	st->nrename++;
	return 0;
}


/* end of handlers
 * **************************************** */

struct rebind_data {
        bind_options bind_options;
	LDAPURLDesc *seen;
};

static void
toggle_sasl(bind_options *bo)
{
	if (bo->authmethod == LDAP_AUTH_SIMPLE) {
		bo->authmethod = LDAP_AUTH_SASL;
		puts("SASL authentication enabled.");
		printf("SASL mechanism: %s (use '*' to change)\n",
		       bo->sasl_mech ? bo->sasl_mech : "(none)");
	} else {
		bo->authmethod = LDAP_AUTH_SIMPLE;
		puts("Simple authentication enabled.");
	}
}

static void
change_mechanism(bind_options *bo)
{
	if (bo->authmethod == LDAP_AUTH_SIMPLE) {
		bo->authmethod = LDAP_AUTH_SASL;
		puts("Switching to SASL authentication.");
	}
	bo->sasl_mech = ldapvi_getline("SASL mechanism", bo->sasl_mech);
}

static int
rebind_callback(
	LDAP *ld, const char *url, ber_tag_t request, int msgid, void *args)
{
	struct rebind_data *rebind_data = args;
	LDAPURLDesc *urld;
	bind_options bo = rebind_data->bind_options;

	printf("Received referral to %s.\n", url);

	if (ldap_url_parse(url, &urld)) {
		puts("Error: Cannot parse URL.");
		return -1;
	}
	if (rebind_data->seen
	    && !strcmp(rebind_data->seen->lud_scheme, urld->lud_scheme)
	    && !strcmp(rebind_data->seen->lud_host, urld->lud_host)
	    && rebind_data->seen->lud_port == urld->lud_port)
		/* confirmed already */
		return 0;

	printf("You are not logged in to %s://%s:%d yet.\n"
	       "Type '!' or 'y' to do so.\n",
	       urld->lud_scheme, urld->lud_host, urld->lud_port);
	for (;;) {
		bo.dialog = BD_ALWAYS;

		switch (choose("Rebind?", "y!nB*qQ?", "(Type '?' for help.)"))
		{
		case '!':
                        bo.dialog = BD_NEVER;
			/* fall through */
		case 'y':
			if (rebind(ld, &bo, 0, 0, 1) == 0) {
				if (rebind_data->seen)
					ldap_free_urldesc(rebind_data->seen);
				rebind_data->seen = urld;
				return 0;
			}
			break;
		case 'n':
			ldap_free_urldesc(urld);
			return 0;
		case '*':
			change_mechanism(&bo);
			break;
		case 'B':
			toggle_sasl(&bo);
			break;
		case 'q':
			ldap_free_urldesc(urld);
			return -1;
		case 'Q':
			exit(0);
		case '?':
			puts("Commands:\n"
			     "  y -- ask for user name and rebind\n"
			     "  ! -- rebind using cached credentials\n"
			     "  n -- don't login, just continue\n"
			     "  B -- toggle SASL\n"
			     "  * -- set SASL mechanism\n"
			     "  q -- give up\n"
			     "  Q -- give up and exit ldapvi\n"
			     "  ? -- this help");
			break;
		}
	}
}

static char *
find_user(LDAP *ld, char *filter)
{
	char *dn = 0;
	LDAPMessage *result = 0;
	LDAPMessage *entry = 0;

	if (ldap_bind_s(ld, 0, 0, LDAP_AUTH_SIMPLE)) {
		ldap_perror(ld, "ldap_bind");
		goto cleanup;
	}
	if (ldap_search_s(ld, 0, LDAP_SCOPE_SUBTREE, filter, 0, 0, &result)) {
		ldap_perror(ld, "ldap_search");
		goto cleanup;
	}
	if ( !(entry = ldap_first_entry(ld, result))) {
		puts("User not found.");
		goto cleanup;
	}
	if (ldap_next_entry(ld, result)) {
		puts("More than one entry matched user filter.");
		goto cleanup;
	}
	dn = ldap_get_dn(ld, entry);

cleanup:
	if (result) ldap_msgfree(result);
	return dn;
}

static void
ensure_tmp_directory(char *dir)
{
	if (strcmp(dir, "/tmp/ldapvi-XXXXXX")) return;
	mkdtemp(dir);
	on_exit((on_exit_function) cleanup, dir);
	signal(SIGTERM, cleanup_signal);
	signal(SIGINT, cleanup_signal);
	signal(SIGPIPE, SIG_IGN);
}

static int
rebind_sasl(LDAP *ld, bind_options *bind_options, char *dir, int verbose)
{
	tsasl_defaults *defaults = sasl_defaults_new(bind_options);
	int rc;
	int sasl_mode;

	switch (bind_options->dialog) {
	case BD_NEVER: sasl_mode = LDAP_SASL_QUIET; break;
	case BD_AUTO: sasl_mode = LDAP_SASL_AUTOMATIC; break;
	case BD_ALWAYS: sasl_mode = LDAP_SASL_INTERACTIVE; break;
	default: abort();
	}

	if (dir) {
		ensure_tmp_directory(dir);
		init_sasl_redirection(defaults, append(dir, "/sasl"));
	}

	rc = ldap_sasl_interactive_bind_s(
		ld, bind_options->user, bind_options->sasl_mech, NULL,
		NULL, sasl_mode, ldapvi_sasl_interact, defaults);

	sasl_defaults_free(defaults);
	if (defaults->fd != -1) {
		finish_sasl_redirection(defaults);
		free(defaults->pathname);
	}

	if (rc != LDAP_SUCCESS) {
		ldap_perror(ld, "ldap_sasl_interactive_bind_s");
		return -1;
	}

	if (verbose)
		printf("Bound as authzid=%s, authcid=%s.\n",
		       bind_options->sasl_authzid,
		       bind_options->sasl_authcid);
	return 0;
}

static int
rebind_simple(LDAP *ld, bind_options *bo, int verbose)
{
	if (bo->dialog == BD_ALWAYS
	    || (bo->dialog == BD_AUTO && bo->user && !bo->password))
	{
		tdialog d[2];
		init_dialog(d, DIALOG_DEFAULT, "Filter or DN", bo->user);
		init_dialog(d + 1, DIALOG_PASSWORD, "Password", bo->password);
		dialog("--- Login", d, 2, bo->user ? 1 : 0);
		bo->user = d[0].value;
		bo->password = d[1].value;
	}
	if (bo->user && bo->user[0] == '(')
		/* user is a search filter, not a name */
		if ( !(bo->user = find_user(ld, bo->user)))
			return -1;
	if (ldap_bind_s(ld, bo->user, bo->password, LDAP_AUTH_SIMPLE)) {
		ldap_perror(ld, "ldap_bind");
		return -1;
	}
	if (verbose)
		printf("Bound as %s.\n", bo->user);
	return 0;
}

static int
rebind(LDAP *ld, bind_options *bind_options, int register_callback,
       char *dir, int verbose)
{
	int rc = -1;
	struct rebind_data *rebind_data = xalloc(sizeof(struct rebind_data));

	switch (bind_options->authmethod) {
	case LDAP_AUTH_SASL:
		if (rebind_sasl(ld, bind_options, dir, verbose))
			return -1;
		break;
	case LDAP_AUTH_SIMPLE:
		if (rebind_simple(ld, bind_options, verbose))
			return -1;
		break;
	}

	if (register_callback) {
		rebind_data->bind_options = *bind_options;
		rebind_data->bind_options.password
			= xdup(bind_options->password);
		rebind_data->seen = 0;
		if (ldap_set_rebind_proc(ld, rebind_callback, rebind_data))
			ldaperr(ld, "ldap_set_rebind_proc");
	}
	return 0;
}

void
init_sasl_arguments(LDAP *ld, bind_options *bind_options)
{
	if (!bind_options->sasl_mech)
		ldap_get_option(ld,
				LDAP_OPT_X_SASL_MECH,
				&bind_options->sasl_mech);
	if (!bind_options->sasl_realm)
		ldap_get_option(ld,
				LDAP_OPT_X_SASL_REALM,
				&bind_options->sasl_realm);
	if (!bind_options->sasl_authcid)
		ldap_get_option(ld,
				LDAP_OPT_X_SASL_AUTHCID,
				&bind_options->sasl_authcid);
	if (!bind_options->sasl_authzid)
		ldap_get_option(ld,
				LDAP_OPT_X_SASL_AUTHZID,
				&bind_options->sasl_authzid);
}

static LDAP *
do_connect(char *server, bind_options *bind_options,
	   int referrals, int starttls, int tls, int deref, int profileonlyp,
	   char *dir)
{
	LDAP *ld = 0;
	int rc = 0;
	int drei = 3;

	if (server && !strstr(server, "://")) {
		char *url = xalloc(strlen(server) + sizeof("ldap://"));
		strcpy(url, "ldap://");
		strcpy(url + 7, server);
		server = url;
	}

	if (ldap_set_option(0, LDAP_OPT_X_TLS_REQUIRE_CERT, (void *) &tls))
		ldaperr(0, "ldap_set_option(LDAP_OPT_X_TLS)");
	if ( rc = ldap_initialize(&ld, server)) {
		fprintf(stderr, "ldap_initialize: %s\n", ldap_err2string(rc));
		exit(1);
	}
	if (!profileonlyp)
		init_sasl_arguments(ld, bind_options);
	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &drei))
		ldaperr(ld, "ldap_set_option(LDAP_OPT_PROTOCOL_VERSION)");
	if (starttls)
		if (ldap_start_tls_s(ld, 0, 0))
			ldaperr(ld, "ldap_start_tls_s");
	if (rebind(ld, bind_options, 1, dir, 0) == -1) {
		ldap_unbind_s(ld);
		return 0;
	}
	/* after initial bind, always ask interactively (except in '!' rebinds,
	 * which are special-cased): */
	bind_options->dialog = BD_ALWAYS;
	if (ldap_set_option(ld, LDAP_OPT_REFERRALS,
                            referrals ? LDAP_OPT_ON : LDAP_OPT_OFF))
		ldaperr(ld, "ldap_set_option(LDAP_OPT_REFERRALS)");
	if (ldap_set_option(ld, LDAP_OPT_DEREF, (void *) &deref))
		ldaperr(ld, "ldap_set_option(LDAP_OPT_DEREF)");

	return ld;
}

/*
 * fixme: do we need the user parameter?  if so, we should add
 * SASL support here.
 *
 * An ldapvi command line option for this wouldn't hurt either.
 */
static int
save_ldif(tparser *parser, GArray *offsets, char *clean, char *data,
	  char *server, char *user, int managedsait)
{
	int fd;
	FILE *s;

	GString *name = g_string_sized_new(300);
	g_string_append(name, ",ldapvi-");
	if (gethostname(name->str + name->len, 300 - name->len) == -1)
		syserr();
	name->len = strlen(name->str);
	g_string_append_printf(name, "-%d.ldif", getpid());

	if ( (fd = open(name->str, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
		int error = errno;
		fprintf(stderr, "Cannot save %s: ", name->str);
		errno = error;
		perror(0);
		g_string_free(name, 1);
		return 1;
	}
	if ( !(s = fdopen(fd, "w"))) syserr();

	fputs("version: 1\n", s);
	fputs("# to apply these changes using ldapvi, run:\n", s);
	fputs("#   ldapvi --ldapmodify", s);
	if (managedsait)
		fputs(" -M", s);
	if (server) {
		fputs(" -h ", s);
		fputs(server, s);
	}
	fputc(' ', s);
	fputs(name->str, s);
	fputc('\n', s);

	compare(parser, &ldif_handler, s, offsets, clean, data, 0, 0);
	if (fclose(s) == EOF) syserr();

	printf("Your changes have been saved to %s.\n", name->str);
	return 0;
}

static void
view_ldif(tparser *parser, char *dir, GArray *offsets, char *clean, char *data)
{
	FILE *s;
	char *name = append(dir, "/ldif");
	if ( !(s = fopen(name, "w"))) syserr();
	fputs("version: 1\n", s);
	compare(parser, &ldif_handler, s, offsets, clean, data, 0, 0);
	if (fclose(s) == EOF) syserr();
	view(name);
	free(name);
}

static thandler vdif_handler = {
	vdif_change,
	vdif_rename,
	vdif_add,
	vdif_delete,
	vdif_rename0
};

static void
view_vdif(tparser *parser, char *dir, GArray *offsets, char *clean, char *data)
{
	FILE *s;
	char *name = append(dir, "/vdif");

	if ( !(s = fopen(name, "w"))) syserr();
	fputs("version: ldapvi\n", s);
	compare(parser, &vdif_handler, s, offsets, clean, data, 0, 0);
	if (fclose(s) == EOF) syserr();
	view(name);
	free(name);
}

static void
setcolor(int fg)
{
	char *bold = tigetstr("bold");
	char *setaf = tigetstr("setaf");
	if (setaf) putp(tparm(setaf, fg));
	if (bold) putp(bold);
}

static void
print_counter(int color, char *label, int value)
{
	char *sgr0 = tigetstr("sgr0");

	if (value) setcolor(color);
	printf("%s: %d", label, value);
	if (sgr0) putp(sgr0);
}

/* collect statistics.  This comparison step is important
 * for catching syntax errors before real processing starts.
 */
static int
analyze_changes(tparser *p, GArray *offsets, char *clean, char *data,
		cmdline *cmdline)
{
	struct statistics st;
	static thandler statistics_handler = {
		statistics_change,
		statistics_rename,
		statistics_add,
		statistics_delete,
		statistics_rename0
	};
	int rc;
	long pos;

retry:
	memset(&st, 0, sizeof(st));
	rc = compare(
		p, &statistics_handler, &st, offsets, clean, data, &pos, 0);

	/* Success? */
	if (rc == 0) {
		if (!(st.nadd + st.ndelete + st.nmodify + st.nrename)) {
			if (!cmdline->quiet)
				puts("No changes.");
			return 0;
		}
		if (cmdline->quiet)
			return 1;
		print_counter(COLOR_GREEN, "add", st.nadd);
		fputs(", ", stdout);
		print_counter(COLOR_BLUE, "rename", st.nrename);
		fputs(", ", stdout);
		print_counter(COLOR_YELLOW, "modify", st.nmodify);
		fputs(", ", stdout);
		print_counter(COLOR_RED, "delete", st.ndelete);
		putchar('\n');
		return 1;
	}

	if (cmdline->noninteractive) {
		fputs("Syntax error in noninteractive mode, giving up.\n",
		      stderr);
		exit(1);
	}

	/* Syntax error */
	for (;;) {
		switch (choose("What now?", "eQ?", "(Type '?' for help.)")) {
		case 'e':
			edit_pos(data, pos);
			goto retry;
		case 'Q':
			exit(0);
		case '?':
			puts("Commands:\n"
			     "  Q -- discard changes and quit\n"
			     "  e -- open editor again\n"
			     "  ? -- this help");
			break;
		}
	}
}

static void
commit(tparser *p, LDAP *ld, GArray *offsets, char *clean, char *data,
       LDAPControl **ctrls, int verbose, int noquestions, int continuous,
       cmdline *cmdline)
{
	struct ldapmodify_context ctx;
	static thandler ldapmodify_handler = {
		ldapmodify_change,
		ldapmodify_rename,
		ldapmodify_add,
		ldapmodify_delete,
		ldapmodify_rename0
	};
	ctx.ld = ld;
	ctx.controls = ctrls;
	ctx.verbose = verbose;
	ctx.noquestions = noquestions;
	ctx.continuous = continuous;

	switch (compare(p, &ldapmodify_handler, &ctx, offsets, clean, data, 0,
			cmdline))
	{
	case 0:
		if (!cmdline->quiet)
			puts("Done.");
		write_ldapvi_history();
		exit(0);
	case -1:
		yourfault("unexpected syntax error!");
	case -2:
		/* user error */
		break;
	default:
		abort();
	}
}

static int
getty(int fd)
{
	if (close(fd) == -1)
		syserr();
	if (open("/dev/tty", O_RDWR) != fd)
		return -1;
	return 0;
}

static int
fixup_streams(FILE **source, FILE **target)
{
	int rc = 0;

	/* find a terminal and restore fds 0, 1 to a sensible value for
	 * reading the password.  Save the original streams for later use.*/

	if (!isatty(0)) {
		/* user has redirected stdout */
		int in = dup(fileno(stdin));
		if (in == -1) syserr();
		*source = fdopen(in, "r");
		if (getty(0) == -1) rc = -1;
	}
	if (!isatty(1)) {
		/* user has redirected stdout */
		int out = dup(fileno(stdout));
		if (out == -1) syserr();
		*target = fdopen(out, "w");
		if (getty(1) == -1) rc = -1;
	}
	return rc;
}

static int
ndecimalp(char *str)
{
	char *ptr;
	strtol(str, &ptr, 10);
	return !*ptr;
}

static void
skip(tparser *p, char *dataname, GArray *offsets, cmdline *cmdline)
{
	long pos;
	char *key;
	FILE *s;

	if ( !(s = fopen(dataname, "r"))) syserr();
	p->skip(s, 0, &key);
	if ( (pos = ftell(s)) == -1) syserr();
	if (fclose(s) == EOF) syserr();

	if (key) {
		cut_datafile(dataname, pos, cmdline);
		if (ndecimalp(key))
			g_array_index(offsets, long, atoi(key)) = -1;
		free(key);
	} else {
                /* Normally we want to skip an entry in data.
                 * But if data is exhausted, the remaining entries
                 * in the offset table are deletions -- just remove
                 * the offset. */
                int n;
                for (n = 0; n < offsets->len; n++)
                        if (g_array_index(offsets, long, n) >= 0) {
                                g_array_remove_index(offsets, n);
				break;
			}
	}
}

static tentroid *
entroid_set_entry(LDAP *ld, tentroid *entroid, tentry *entry)
{
	int i;
	tattribute *oc = entry_find_attribute(entry, "objectClass", 0);
	GPtrArray *values;

	if (!oc)
		return 0;

	entroid_reset(entroid);
	values = attribute_values(oc);
	for (i = 0; i < values->len; i++) {
		GArray *av = g_ptr_array_index(values, i);
		LDAPObjectClass *cls;

		{
			char zero = 0;
			/* Hack: temporarily null-terminate the GArray for use as a C string. */
			g_array_append_val(av, zero);
			av->len--;
		}

		cls = entroid_request_class(entroid, av->data);
		if (!cls) {
			g_string_append(entroid->comment, "# ");
			g_string_append(entroid->comment, entroid->error->str);
			return entroid;
		}
	}

	if (compute_entroid(entroid) == -1) {
		g_string_append(entroid->comment, "# ");
		g_string_append(entroid->comment, entroid->error->str);
		return entroid;
	}
	return entroid;
}

struct annotation_context {
	LDAP *ld;
	FILE *out;
	tparser *parser;
	tentroid *entroid;
};

static void
annotate_entry(char *key, tentry *entry, void *userdata)
{
	struct annotation_context *ctx = userdata;
	tentroid *entroid = entroid_set_entry(ctx->ld, ctx->entroid, entry);
	ctx->parser->print(ctx->out, entry, key, entroid);
}

static void
rewrite_comments(LDAP *ld, char *dataname, cmdline *cmdline)
{
	FILE *in;
	FILE *out;
	char *tmpname;
	tparser *p = &ldapvi_parser;
	thandler *h = &vdif_handler;
	struct annotation_context ctx;
	int addp = cmdline->ldapmodify_add;
	tschema *schema = schema_new(ld);

	if (!schema) {
		fputs("Error: Failed to read schema.\n", stderr);
		return;
	}

	tmpname = append(dataname, ".tmp");
	if ( !(in = fopen(dataname, "r"))) syserr();
	if ( !(out = fopen(tmpname, "w"))) syserr();

	write_file_header(out, cmdline);
	if (cmdline->ldif) {
		p = &ldif_parser;
		h = &ldif_handler;
	}
	ctx.ld = ld;
	ctx.out = out;
	ctx.entroid = entroid_new(schema);
	ctx.parser = p;
	parse_file(in, p, h, out, annotate_entry, &ctx, addp);

	if (fclose(in) == EOF) syserr();
	if (fclose(out) == EOF) syserr();
	rename(tmpname, dataname);
	free(tmpname);
	schema_free(schema);
}


static void
forget_deletions(tparser *p, GArray *offsets, char *clean, char *data)
{
	int i;
	GArray *deletions = g_array_new(0, 0, sizeof(int));

	compare(p, &forget_deletions_handler, deletions,
		offsets, clean, data, 0, 0);
	for (i = 0; i < deletions->len; i++) {
		int n = g_array_index(deletions, int, i);
		g_array_index(offsets, long, n) = -1;
	}
	g_array_free(deletions, 1);
}

static void
append_sort_control(LDAP *ld, GPtrArray *ctrls, char *keystring)
{
	LDAPControl *ctrl;
	LDAPSortKey **keylist;

	if (ldap_create_sort_keylist(&keylist, keystring))
		ldaperr(ld, "ldap_create_sort_keylist");
	if (ldap_create_sort_control(ld, keylist, 1, &ctrl))
		ldaperr(ld, "ldap_create_sort_keylist");
	g_ptr_array_add(ctrls, ctrl);
}

static GArray *
read_offsets(tparser *p, char *file)
{
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	FILE *s;

	if ( !(s = fopen(file, "r"))) syserr();
	for (;;) {
		long offset;
		char *key, *ptr;
		int n;
		tentry *entry;

		key = 0;
		if (p->entry(s, -1, &key, &entry, &offset) == -1) exit(1);
		if (!key) break;

		n = strtol(key, &ptr, 10);
		if (*ptr) {
			fprintf(stderr, "Error: Invalid key: `%s'.\n", key);
			exit(1);
		}
		if (n != offsets->len) {
			fprintf(stderr, "Error: Unexpected key: `%s'.\n", key);
			exit(1);
		}
		free(key);
		entry_free(entry);
		g_array_append_val(offsets, offset);
	}
	if (fclose(s) == -1) syserr();

	return offsets;
}

static void
offline_diff(tparser *p, char *a, char *b)
{
	GArray *offsets = read_offsets(p, a);
	compare(p, &ldif_handler, stdout, offsets, a, b, 0, 0);
	g_array_free(offsets, 1);
}

void
write_config(LDAP *ld, FILE *f, cmdline *cmdline)
{
	char *user = cmdline->bind_options.user;
	char *server = cmdline->server;
	int limit;

	if (!f) f = stdout;
	fputs("# ldap.conf(5)\n", f);
	fputs("# edit this as needed and paste into ~/.ldaprc\n", f);

	/* URI/HOST */
	fputc('\n', f);
	fputs("# server name\n", f);
	fputs("# (for parameterless operation, make sure to include at"
	      " least this line)\n",
	      f);
	if (!server)
		ldap_get_option(ld, LDAP_OPT_URI, &server);
	if (!server)
		ldap_get_option(ld, LDAP_OPT_HOST_NAME, &server);
	if (server)
		if (strstr(server, "://"))
			fprintf(f, "URI %s\n", server);
		else
			fprintf(f, "HOST %s\n", server);

	/* BASE */
	fputc('\n', f);
	fputs("# default search base\n", f);
	if (cmdline->basedns->len) {
		GPtrArray *basedns = cmdline->basedns;
		int i;
		if (basedns->len > 1)
			fputs("### multiple namingcontexts found (uncomment"
			      " one of these lines):\n",
			      f);
		for (i = 0; i < basedns->len; i++) {
			if (basedns->len > 1) fputc('#', f);
			fprintf(f, "BASE %s\n", g_ptr_array_index(basedns, i));
		}
	} else {
		if (!cmdline->discover)
			fputs("### no search base specified, retry with"
			      " --discover?\n",
			      f);
		fputs("#BASE <dn>\n", f);
	}

	/* BINDDN */
	fputc('\n', f);
	fputs("# user to bind as\n", f);
	if (user && user[0] == '(')
		user = find_user(ld, user);
	if (user)
		fprintf(f, "BINDDN %s\n", user);
	else
		fputs("#BINDDN <dn>\n", f);

	/* search options */
	fputc('\n', f);
	fputs("# search parameters (uncomment as needed)\n", f);
	switch (cmdline->deref) {
	case LDAP_DEREF_NEVER:
		fputs("#DEREF never\n", f);
		break;
	case LDAP_DEREF_SEARCHING:
		fputs("#DEREF searcing\n", f);
		break;
	case LDAP_DEREF_FINDING:
		fputs("#DEREF finding\n", f);
		break;
	case LDAP_DEREF_ALWAYS:
		fputs("#DEREF always\n", f);
		break;
	}
	ldap_get_option(ld, LDAP_OPT_SIZELIMIT, &limit);
	fprintf(f, "#SIZELIMIT %d\n", limit);
	ldap_get_option(ld, LDAP_OPT_TIMELIMIT, &limit);
	fprintf(f, "#TIMELIMIT %d\n", limit);
}

static void
add_changerecord(FILE *s, cmdline *cmdline)
{
	switch (cmdline->mode) {
	case ldapvi_mode_delete: {
		char **ptr;
		for (ptr = cmdline->delete_dns; *ptr; ptr++)
			if (cmdline->ldif)
				print_ldif_delete(s, *ptr);
			else
				print_ldapvi_delete(s, *ptr);
		break;
	}
	case ldapvi_mode_rename:
		if (cmdline->ldif)
			print_ldif_rename(s,
					  cmdline->rename_old,
					  cmdline->rename_new,
					  cmdline->rename_dor);
		else
			print_ldapvi_rename(s,
					    cmdline->rename_old,
					    cmdline->rename_new,
					    cmdline->rename_dor);
		break;
	case ldapvi_mode_modrdn:
		if (cmdline->ldif)
			print_ldif_modrdn(s,
					  cmdline->rename_old,
					  cmdline->rename_new,
					  cmdline->rename_dor);
		else
			print_ldapvi_modrdn(s,
					    cmdline->rename_old,
					    cmdline->rename_new,
					    cmdline->rename_dor);
		break;
	default:
		abort();
	}
}

static void
add_template(LDAP *ld, FILE *s, GPtrArray *wanted, char *base)
{
	int i;
	tentroid *entroid;
	LDAPObjectClass *cls;
	LDAPAttributeType *at;
	tschema *schema = schema_new(ld);

	if (!schema) {
		fputs("Error: Failed to read schema, giving up.\n", stderr);
		exit(1);
	}

	entroid = entroid_new(schema);
	for (i = 0; i < wanted->len; i++) {
		char *name = g_ptr_array_index(wanted, i);
		cls = entroid_request_class(entroid, name);
		if (!cls) {
			fputs(entroid->error->str, stderr);
			exit(1);
		}
		if (cls->oc_kind == LDAP_SCHEMA_ABSTRACT) {
			g_string_append(entroid->comment,
					"### NOTE: objectclass is abstract: ");
			g_string_append(entroid->comment, name);
			g_string_append_c(entroid->comment, '\n');
		}
	}

	if (compute_entroid(entroid) == -1) {
		fputs(entroid->error->str, stderr);
		exit(1);
	}

	fputc('\n', s);
	fputs(entroid->comment->str, s);
	fprintf(s, "add %s\n", base ? base : "<DN>");

	for (i = 0; i < entroid->classes->len; i++) {
		cls = g_ptr_array_index(entroid->classes, i);
		fprintf(s, "objectClass: %s\n", objectclass_name(cls));
	}
	for (i = 0; i < entroid->must->len; i++) {
		at = g_ptr_array_index(entroid->must, i);
		if (strcmp(at->at_oid, "2.5.4.0"))
			fprintf(s, "%s: \n", attributetype_name(at));
	}
	for (i = 0; i < entroid->may->len; i++) {
		at = g_ptr_array_index(entroid->may, i);
		if (strcmp(at->at_oid, "2.5.4.0"))
			fprintf(s, "#%s: \n", attributetype_name(at));
	}

	entroid_free(entroid);
	schema_free(schema);
}

static void
parse_file(FILE *in,
	   tparser *p, thandler *h, void *userdata,
	   handler_entry hentry, void *entrydata,
	   int addp)
{
	char *key = 0;

	for (;;) {
		long pos;

		if (p->peek(in, -1, &key, &pos) == -1) exit(1);
		if (!key) break;

		if (ndecimalp(key)) {
			tentry *entry;
			if (p->entry(in, pos, 0, &entry, 0) == -1)
				exit(1);
			if (hentry)
				hentry(key, entry, entrydata);
			entry_free(entry);
		} else {
			char *k = key;
			if (!strcmp(key, "add") && !addp)
				k = "replace";
			if (process_immediate(p, h, userdata, in, pos, k) < 0)
				exit(1);
		}
		free(key);
	}
}

static int
write_file_header(FILE *s, cmdline *cmdline)
{
	int nlines = 0;

	if (print_binary_mode == PRINT_UTF8 && !cmdline->ldif) {
		/* Emacs coding cookie + vim modeline for UTF-8.
		 * Note: vim's "encoding" is disallowed in modelines;
		 * use "fileencoding" instead. */
		fputs("# -*- coding: utf-8 -*- vim:fileencoding=utf-8:\n", s);
		nlines++;
	}
	if (cmdline->ldif) {
		fputs("# " RFC_2849_URL "\n" "# " MANUAL_LDIF_URL "\n", s);
		nlines += 2;
	} else  {
		fputs("# " MANUAL_SYNTAX_URL "\n", s);
		nlines++;
	}

	return nlines;
}

static void
cut_datafile(char *dataname, long pos, cmdline *cmdline)
{
	FILE *in;
	FILE *out;
	char *tmpname = append(dataname, ".tmp");

	if ( !(in = fopen(dataname, "r"))) syserr();
	if ( !(out = fopen(tmpname, "w"))) syserr();
	if (fseek(in, pos, SEEK_SET) == -1) syserr();
	write_file_header(out, cmdline);
	fputc('\n', out);
	fcopy(in, out);
	if (fclose(in) == EOF) syserr();
	if (fclose(out) == EOF) syserr();
	rename(tmpname, dataname);
	free(tmpname);
}

static int
can_seek(FILE *s)
{
	long pos;
	if ( (pos = ftell(s)) == -1) return 0;
	if (fseek(s, pos, SEEK_SET) == -1) return 0;
	return 1;
}

static int
copy_sasl_output(FILE *out, char *sasl)
{
	struct stat st;
	FILE *in;
	int have_sharpsign = 0;
	int line = 0;
	int c;

	if (lstat(sasl, &st) == -1) return 0;
	if ( !(in = fopen(sasl, "r"))) syserr();

	if (st.st_size > 0) {
		fputs("\n# SASL output:\n", out);
		line += 2;
	}
	for (;;) {
		switch ( c = getc_unlocked(in)) {
		case 0:
		case '\r':
			break;
		case '\n':
			if (!have_sharpsign)
				fputc('#', out);
			line++;
			have_sharpsign = 0;
			fputc(c, out);
			break;
		case EOF:
			if (have_sharpsign) {
				line++;
				fputc('\n', out);
			}
			if (fclose(in) == EOF) syserr();
			return line;
		default:
			if (!have_sharpsign) {
				have_sharpsign = 1;
				fputs("# ", out);
			}
			fputc(c, out);
		}
	}
}

static GArray *
main_write_files(
	LDAP *ld, cmdline *cmdline,
	char *clean, char *data, char *sasl,
	GPtrArray *ctrls,
	FILE *source,
	int *nlines)
{
	FILE *s;
	int line;
	GArray *offsets;

	if ( !(s = fopen(data, "w"))) syserr();
	line = write_file_header(s, cmdline);
	line += copy_sasl_output(s, sasl);

	if (cmdline->mode == ldapvi_mode_in) {
		tparser *p = &ldif_parser;
		thandler *h = &vdif_handler;
		FILE *tmp = 0;

		if (cmdline->in_file) {
			if ( !(source = fopen(cmdline->in_file, "r+")))
				syserr();
		} else {
			if (!source)
				source = stdin;
			if (!can_seek(source)) {
				/* use the clean file as a temporary buffer */
				if ( !(tmp = fopen(clean, "w+"))) syserr();
				fcopy(source, tmp);
				if (fseek(tmp, 0, SEEK_SET) == -1) syserr();
				source = tmp;
				/* source was stdin, no need to close it */
			}
		}

		if (cmdline->ldif) h = &ldif_handler;
		if (cmdline->ldapvi) p = &ldapvi_parser;
		parse_file(source, p, h, s, 0, 0, cmdline->ldapmodify_add);

		if (cmdline->in_file)
			if (fclose(source) == EOF) syserr();
		if (tmp)
			if (unlink(clean) == -1) syserr();
		if (fclose(s) == EOF) syserr();
		cp("/dev/null", clean, 0, 0);
		offsets = g_array_new(0, 0, sizeof(long));
	} else if (cmdline->classes || cmdline->mode != ldapvi_mode_edit) {
		if (!cmdline->classes)
			add_changerecord(s, cmdline);
		else if (cmdline->classes->len) {
			char *base = 0;
			if (cmdline->basedns->len > 0)
				base = g_ptr_array_index(cmdline->basedns, 0);
			add_template(ld, s, cmdline->classes, base);
		} else
			fputc('\n', s);
		if (fclose(s) == EOF) syserr();
		cp("/dev/null", clean, 0, 0);
		offsets = g_array_new(0, 0, sizeof(long));
	} else {
		offsets = search(s, ld, cmdline, (void *) ctrls->pdata, 0,
				 cmdline->ldif);
		if (fclose(s) == EOF) syserr();
		cp(data, clean, 0, 0);
	}

	*nlines = line;
	return offsets;
}

static int
main_loop(LDAP *ld, cmdline *cmdline,
	  tparser *parser, GArray *offsets, char *clean, char *data,
	  GPtrArray *ctrls, char *dir)
{
	int changed = 1;
	int continuous = cmdline->continuous;

	for (;;) {
		if (changed)
			if (!analyze_changes(
				    parser, offsets, clean, data, cmdline))
			{
				write_ldapvi_history();
				return 0;
			}
		changed = 0;
		switch (choose("Action?",
			       "yYqQvVebB*rsf+?",
			       "(Type '?' for help.)")) {
		case 'Y':
			continuous = 1;
			/* fall through */
		case 'y':
			commit(parser, ld, offsets, clean, data,
			       (void *) ctrls->pdata, cmdline->verbose, 0,
			       continuous, cmdline);
			changed = 1;
			break; /* reached only on user error */
		case 'q':
			if (save_ldif(parser,
				      offsets, clean, data,
				      cmdline->server,
				      cmdline->bind_options.user,
				      cmdline->managedsait))
				break;
			write_ldapvi_history();
			return 0;
		case 'Q':
			write_ldapvi_history();
			return 0;
		case 'v':
			view_ldif(parser, dir, offsets, clean, data);
			break;
		case 'V':
			view_vdif(parser, dir, offsets, clean, data);
			break;
		case 'e':
			edit(data, 0);
			changed = 1;
			break;
		case 'b':
			rebind(ld, &cmdline->bind_options, 1, 0, 1);
			changed = 1; /* print stats again */
			break;
		case '*':
			change_mechanism(&cmdline->bind_options);
			puts("Type 'b' to log in.");
			break;
		case 'B':
			toggle_sasl(&cmdline->bind_options);
			puts("Type 'b' to log in.");
			break;
		case 'r':
			ldap_unbind_s(ld);
			ld = do_connect(
				cmdline->server,
				&cmdline->bind_options,
				cmdline->referrals,
				cmdline->starttls,
				cmdline->tls,
				cmdline->deref,
				1,
				0);
			printf("Connected to %s.\n", cmdline->server);
			changed = 1; /* print stats again */
			break;
		case 's':
			skip(parser, data, offsets, cmdline);
			changed = 1;
			break;
		case 'f':
			forget_deletions(parser, offsets, clean, data);
			changed = 1;
			break;
		case '+':
			rewrite_comments(ld, data, cmdline);
			edit(data, 0);
			changed = 1;
			break;
		case 'L' - '@':
			{
				char *clear = tigetstr("clear");
				if (clear && clear != (char *) -1)
					putp(clear);
			}
			break;
		case '?':
			puts("Commands:\n"
			     "  y -- commit changes\n"
			     "  Y -- commit, ignoring all errors\n"
			     "  q -- save changes as LDIF and quit\n"
			     "  Q -- discard changes and quit\n"
			     "  v -- view changes as LDIF change records\n"
			     "  V -- view changes as ldapvi change records\n"
			     "  e -- open editor again\n"
			     "  b -- show login dialog and rebind\n"
			     "  B -- toggle SASL\n"
			     "  * -- set SASL mechanism\n"
			     "  r -- reconnect to server\n"
			     "  s -- skip one entry\n"
			     "  f -- forget deletions\n"
			     "  + -- rewrite file to include schema comments\n"
			     "  ? -- this help");
			break;
		}
	}
}

int
main(int argc, const char **argv)
{
	LDAP *ld;
	cmdline cmdline;
	GPtrArray *ctrls = g_ptr_array_new();
	static char dir[] = "/tmp/ldapvi-XXXXXX";
	char *clean;
	char *data;
	char *sasl;
	GArray *offsets;
	FILE *source_stream = 0;
	FILE *target_stream = 0;
	tparser *parser;
	int nlines;

	init_cmdline(&cmdline);

	if (argc >= 2 && !strcmp(argv[1], "--diff")) {
		if (argc != 4) {
			fputs("wrong number of arguments to --diff\n", stderr);
			usage(2, 1);
		}
		offline_diff(&ldapvi_parser,
			     (char *) argv[2],
			     (char *) argv[3]);
		exit(0);
	}

	parse_arguments(argc, argv, &cmdline, ctrls);
	if (fixup_streams(&source_stream, &target_stream) == -1)
		cmdline.noninteractive = 1;
	if (cmdline.noninteractive) {
		cmdline.noquestions = 1;
		cmdline.quiet = 1;
		cmdline.bind_options.dialog = BD_NEVER;
	}
	if (cmdline.ldif)
		parser = &ldif_parser;
	else
		parser = &ldapvi_parser;
	read_ldapvi_history();

	setupterm(0, 1, 0);
	ld = do_connect(cmdline.server,
			&cmdline.bind_options,
			cmdline.referrals,
			cmdline.starttls,
			cmdline.tls,
			cmdline.deref,
			cmdline.profileonlyp,
			dir);
	if (!ld) {
		write_ldapvi_history();
		exit(1);
	}

	if (cmdline.sortkeys)
		append_sort_control(ld, ctrls, cmdline.sortkeys);
	g_ptr_array_add(ctrls, 0);

	if (cmdline.discover) {
		if (cmdline.basedns->len > 0)
			yourfault("Conflicting options given:"
				  " --base and --discover.");
		discover_naming_contexts(ld, cmdline.basedns);
	}

	if (cmdline.config) {
		write_config(ld, target_stream, &cmdline);
		write_ldapvi_history();
		exit(0);
	}

	if (cmdline.mode == ldapvi_mode_out
	    || (cmdline.mode == ldapvi_mode_edit && target_stream))
	{
		if (cmdline.classes)
			yourfault("Cannot edit entry templates noninteractively.");
		if (!target_stream)
			target_stream = stdout;
		search(target_stream, ld, &cmdline, (void *) ctrls->pdata, 1,
		       cmdline.mode == ldapvi_mode_out
		       ? !cmdline.ldapvi
		       : cmdline.ldif);
		write_ldapvi_history();
		exit(0);
	}

	ensure_tmp_directory(dir);
	clean = append(dir, "/clean");
	data = append(dir, "/data");
	sasl = append(dir, "/sasl");

	offsets = main_write_files(
		ld, &cmdline, clean, data, sasl, ctrls, source_stream,
		&nlines);

	if (!cmdline.noninteractive) {
		if (target_stream) {
			FILE *tmp = fopen(data, "r");
			if (!tmp) syserr();
			fcopy(tmp, target_stream);
			write_ldapvi_history();
			exit(0);
		}
		edit(data, nlines + 1);
	} else if (cmdline.mode == ldapvi_mode_edit)
		yourfault("Cannot edit entries noninteractively.");

	if (cmdline.noquestions) {
		if (!analyze_changes(parser, offsets, clean, data, &cmdline)) {
			write_ldapvi_history();
			return 0;
		}
		commit(parser, ld, offsets, clean, data, (void *) ctrls->pdata,
		       cmdline.verbose, 1, cmdline.continuous, &cmdline);
		fputs("Error in noninteractive mode, giving up.\n", stderr);
		return 1;
	}

	return main_loop(
		ld, &cmdline, parser, offsets, clean, data, ctrls, dir);
}
