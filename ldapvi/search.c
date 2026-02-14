/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Copyright (c) 2003,2004,2005,2006 David Lichteblau
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
#include "common.h"

static int
get_ws_col(void)
{
        struct winsize ws;
        if (ioctl(1, TIOCGWINSZ, &ws) == -1) return 80;
	return ws.ws_col;
}

static void
update_progress(LDAP *ld, int n, LDAPMessage *entry)
{
	int cols = get_ws_col();
	static struct timeval tv;
	static int usec = 0;
	int i;

	if (gettimeofday(&tv, 0) == -1) syserr();
	if (!entry)
		usec = 0;
	else if (!usec)
		usec = tv.tv_usec;
	else {
		if (tv.tv_usec < usec) usec -= 1000000;
		if (tv.tv_usec - usec < 200000)
			return;
		usec = tv.tv_usec;
	}

	putchar('\r');
	for (i = 0; i < cols; i++) putchar(' ');

	printf((n == 1) ? "\r%7d entry read  " :"\r%7d entries read", n);
	if (entry) {
		char *dn = ldap_get_dn(ld, entry);
		if (strlen(dn) < cols - 28)
			printf("        %s", dn);
		ldap_memfree(dn);
	}
	fflush(stdout);
}

void
handle_result(LDAP *ld, LDAPMessage *result, int start, int n,
	      int progress, int noninteractive)
{
        int rc;
        int err;
        char *matcheddn;
        char *text;

        rc = ldap_parse_result(ld, result, &err, &matcheddn, &text, 0, 0, 0);
        if (rc) ldaperr(ld, "ldap_parse_result");

	if (err) {
		fprintf(stderr, "Search failed: %s\n", ldap_err2string(err));
		if (text && *text) fprintf(stderr, "\t%s\n", text);
		if ((err != LDAP_NO_SUCH_OBJECT
		     && err != LDAP_TIMELIMIT_EXCEEDED
		     && err != LDAP_SIZELIMIT_EXCEEDED
		     && err != LDAP_ADMINLIMIT_EXCEEDED)
		    || noninteractive)
		{
			exit(1);
		}
		if (n > start /* otherwise there is only point in continuing
			       * if other searches find results, and we check
			       * that later */
		    && choose("Continue anyway?", "yn", 0) != 'y')
			exit(0);
	}

	if (n == start && progress) {
		fputs("No search results", stderr);
		if (matcheddn && *matcheddn)
			fprintf(stderr, " (matched: %s)", matcheddn);
		fputs(".\n", stderr);
	}

	if (matcheddn) ldap_memfree(matcheddn);
	if (text) ldap_memfree(text);
}

void
log_reference(LDAP *ld, LDAPMessage *reference, FILE *s)
{
        char **refs;
	char **ptr;

        if (ldap_parse_reference(ld, reference, &refs, 0, 0))
		ldaperr(ld, "ldap_parse_reference");
	fputc('\n', s);
	for (ptr = refs; *ptr; ptr++)
		fprintf(s, "# reference to: %s\n", *ptr);
	ldap_value_free(refs);
}

static tentroid *
entroid_set_message(LDAP *ld, tentroid *entroid, LDAPMessage *entry)
{
	struct berval **values = ldap_get_values_len(ld, entry, "objectClass");
	struct berval **ptr;

	if (!values || !*values)
		return 0;

	entroid_reset(entroid);
	for (ptr = values; *ptr; ptr++) {
		struct berval *value = *ptr;
		LDAPObjectClass *cls
			= entroid_request_class(entroid, value->bv_val);
		if (!cls) {
			g_string_append(entroid->comment, "# ERROR: ");
			g_string_append(entroid->comment, entroid->error->str);
			ldap_value_free_len(values);
			return entroid;
		}
	}
	ldap_value_free_len(values);

	if (compute_entroid(entroid) == -1) {
		g_string_append(entroid->comment, "# ERROR: ");
		g_string_append(entroid->comment, entroid->error->str);
		return entroid;
	}
	return entroid;
}

void
search_subtree(FILE *s, LDAP *ld, GArray *offsets, char *base,
	       cmdline *cmdline, LDAPControl **ctrls, int notty, int ldif,
	       tschema *schema)
{
	int msgid;
	LDAPMessage *result, *entry;
	int start = offsets->len;
	int n = start;
	long offset;
	tentroid *entroid;
	tentroid *e;

	if (schema)
		entroid = entroid_new(schema);
	else
		entroid = 0;

	if (ldap_search_ext(
		    ld, base,
		    cmdline->scope, cmdline->filter, cmdline->attrs,
		    0, ctrls, 0, 0, 0, &msgid))
		ldaperr(ld, "ldap_search");

	while (n >= 0)
		switch (ldap_result(ld, msgid, 0, 0, &result)) {
		case -1:
		case 0:
			ldaperr(ld, "ldap_result");
		case LDAP_RES_SEARCH_ENTRY:
			entry = ldap_first_entry(ld, result);
			offset = ftell(s);
			if (offset == -1 && !notty) syserr();
			g_array_append_val(offsets, offset);
			if (entroid)
				e = entroid_set_message(ld, entroid, entry);
			else
				e = 0;
			if (ldif)
				print_ldif_message(
					s, ld, entry, notty ? -1 : n, e);
			else
				print_ldapvi_message(s, ld, entry, n, e);
			n++;
			if (!cmdline->quiet && !notty)
				update_progress(ld, n, entry);
			ldap_msgfree(entry);
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			log_reference(ld, result, s);
			ldap_msgfree(result);
			break;
		case LDAP_RES_SEARCH_RESULT:
			if (!notty) {
				update_progress(ld, n, 0);
				putchar('\n');
			}
			handle_result(ld, result, start, n, !cmdline->quiet,
				      notty);
			n = -1;
			ldap_msgfree(result);
			break;
		default:
			abort();
		}
	if (entroid)
		entroid_free(entroid);
}

GArray *
search(FILE *s, LDAP *ld, cmdline *cmdline, LDAPControl **ctrls, int notty,
       int ldif)
{
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	GPtrArray *basedns = cmdline->basedns;
	int i;
	tschema *schema;

	if (cmdline->schema_comments) {
		schema = schema_new(ld);
		if (!schema) {
			fputs("Error: Failed to read schema, giving up.",
			      stderr);
			exit(1);
		}
	} else
		schema = 0;

	if (basedns->len == 0)
		search_subtree(s, ld, offsets, 0, cmdline, ctrls, notty, ldif,
			       schema);
	else
		for (i = 0; i < basedns->len; i++) {
			char *base = g_ptr_array_index(basedns, i);
			if (!cmdline->quiet && (basedns->len > 1))
				fprintf(stderr, "Searching in: %s\n", base);
			search_subtree(s, ld, offsets, base, cmdline, ctrls,
				       notty, ldif, schema);
		}

	if (!offsets->len) {
		if (!cmdline->noninteractive) {
			if (cmdline->quiet) /* if not printed already... */
				fputs("No search results.  ", stderr);
			fputs("(Maybe use --add or --discover instead?)\n",
			      stderr);
		}
		exit(0);
	}

	if (schema)
		schema_free(schema);
	return offsets;
}

LDAPMessage *
get_entry(LDAP *ld, char *dn, LDAPMessage **result)
{
	LDAPMessage *entry;
	char *attrs[3] = {"+", "*", 0};

	if (ldap_search_s(ld, dn, LDAP_SCOPE_BASE, 0, attrs, 0, result))
		ldaperr(ld, "ldap_search");
	if ( !(entry = ldap_first_entry(ld, *result)))
		ldaperr(ld, "ldap_first_entry");
	return entry;
}

void
discover_naming_contexts(LDAP *ld, GPtrArray *basedns)
{
	LDAPMessage *result, *entry;
	char **values;

	entry = get_entry(ld, "", &result);
	values = ldap_get_values(ld, entry, "namingContexts");
	if (values) {
		char **ptr = values;
		for (ptr = values; *ptr; ptr++)
			g_ptr_array_add(basedns, xdup(*ptr));
		ldap_value_free(values);
	}
	ldap_msgfree(result);
}
