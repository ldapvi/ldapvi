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
#define _XOPEN_SOURCE
#include <unistd.h>
#include "common.h"

#define fast_g_string_append_c(gstring, c)				\
	do {								\
		if ((gstring)->len + 1 >= (gstring)->allocated_len)	\
			g_string_append_c((gstring), (c));		\
		else {							\
			(gstring)->str[(gstring)->len++] = (c);		\
			(gstring)->str[(gstring)->len] = 0;		\
		}							\
	} while (0)

/*
 * 0: ok
 * -1: parse error
 * -2: line is just "-"
 */
static int
ldif_read_ad(FILE *s, GString *lhs)
{
	int c;

	for (;;) {
		switch ( c = getc_unlocked(s)) {
		case ':':
			if (ferror(s)) syserr();
			return 0;
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		case '\r':
			if (fgetc(s) != '\n')
				return -1;
			/* fall through */
		case '\n':
			if (lhs->len) {
				if ( (c = fgetc(s)) == ' ')
					/* folded line */
					break;
				ungetc(c, s);
				if (lhs->len == 1 && lhs->str[0] == '-')
					return -2;
			}
			fputs("Error: Unexpected EOL.\n", stderr);
			return -1;
		case 0:
			fputs("Error: Null byte not allowed.\n", stderr);
			return -1;
		default:
			fast_g_string_append_c(lhs, c);
		}
	}
}

static int
ldif_read_encoding(FILE *s)
{
	int c;

	for (;;) {
		switch ( c = getc_unlocked(s)) {
		case ' ':
			break;
		case ':': /* fall through */
		case '<':
			return c;
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		case '\r':
			if (fgetc(s) != '\n')
				return -1;
			/* fall through */
		case '\n':
			if ( (c = fgetc(s)) == ' ') /* folded line */ break;
			ungetc(c, s);
			return '\n';
		case 0:
			fputs("Error: Null byte not allowed.\n", stderr);
			return -1;
		default:
			ungetc(c, s);
			return 0;
		}
	}
}

static int
ldif_read_safe(FILE *s, GString *data)
{
	int c;

	for (;;)
		switch ( c = getc_unlocked(s)) {
		case '\r':
			if (fgetc(s) != '\n')
				return -1;
			/* fall through */
		case '\n':
			if ( (c = fgetc(s)) == ' ') /* folded line */ break;
			ungetc(c, s);
			if (ferror(s)) syserr();
			return 0;
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		default:
			fast_g_string_append_c(data, c);
		}
}

static int
ldif_read_from_file(GString *data, char *name)
{
	int fd, n;
	if ( (fd = open(name, O_RDONLY)) == -1) {
		perror("open");
		return -1;
	}
	data->len = 0;
	n = 1024;
	do {
		int olen = data->len;
		g_string_set_size(data, data->len + n);
		if ( (n = read(fd, data->str + olen, n)) == -1) syserr();
		data->len = olen + n;
	} while (n > 0);
	if (close(fd) == -1) syserr();
	return 0;
}

static int
ldif_skip_comment(FILE *s)
{
	int c;

	for (;;)
		switch ( c = fgetc(s)) {
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		case '\r':
			if (fgetc(s) != '\n')
				return -1;
			/* fall through */
		case '\n':
			if ( (c = fgetc(s)) == ' ') /* folded line */ break;
			ungetc(c, s);
			if (ferror(s)) syserr();
			return 0;
		}
}

/*
 * Read an LDIF line.
 *
 * 0: ok                           if name->len != 0
 * 0: end of file or empty line    if name->len == 0
 * -1: parse error
 * -2: line is just "-"
 */
static int
ldif_read_line1(FILE *s, GString *name, GString *value)
{
	int c;
	char encoding;
	unsigned char *ustr;
	int len;

	g_string_truncate(name, 0);
	g_string_truncate(value, 0);

	/* skip comment lines */
	do {
		c = fgetc(s);
		switch (c) {
		case EOF:
			if (ferror(s)) syserr();
			return 0;
		case '\n':
			return 0;
		case '\r':
			if (fgetc(s) != '\n')
				return -1;
			return 0;
		case '#':
			if (ldif_skip_comment(s) == -1) return -1;
			break;
		default:
			ungetc(c, s);
			c = -1;
		}
	} while (c != -1);

	if ( c = ldif_read_ad(s, name)) return c;
	if ( (encoding = ldif_read_encoding(s)) == -1) return -1;

	switch (encoding) {
	case 0:
		if (ldif_read_safe(s, value) == -1)
			return -1;
		break;
        case '\n':
                break;
	case ':':
		if (ldif_read_safe(s, value) == -1) return -1;
		ustr = (unsigned char *) value->str;;
		if ( (len = read_base64(value->str, ustr, value->len)) == -1) {
			fputs("Error: Invalid Base64 string.\n", stderr);
			return -1;
		}
		g_string_truncate(value, len);
		break;
	case '<':
		if (ldif_read_safe(s, value) == -1) return -1;
		if (strncmp(value->str, "file://", 7)) {
			fputs("Error: Unknown URL scheme.\n", stderr);
			return -1;
		}
		if (ldif_read_from_file(value, value->str + 7) == -1)
			return -1;
		break;
	default:
		abort();
	}
	return 0;
}


/*
 * Read an LDIF line ("-" not allowed).
 *
 * 0: ok                           if name->len != 0
 * 0: end of file or empty line    if name->len == 0
 * -1: parse error
 */
static int
ldif_read_line(FILE *s, GString *name, GString *value)
{
	int rc = ldif_read_line1(s, name, value);
	if (rc == -2) {
		fputs("Error: Unexpected EOL.\n", stderr);
		rc = -1;
	}
	return rc;
}

static char *
ldif_read_rename_body(FILE *s,
		      GString *tmp1, GString *tmp2,
		      char *olddn,
		      int *deleteoldrdn)
{
	char *newrdn;
	char *dn;
	int i;

	if (ldif_read_line(s, tmp1, tmp2) == -1) return 0;
	if (strcmp(tmp1->str, "newrdn")) {
		fputs("Error: Expected 'newrdn'.\n", stderr);
		return 0;
	}
	i = tmp2->len;
	newrdn = xdup(tmp2->str);

	if (ldif_read_line(s, tmp1, tmp2) == -1) {
		free(newrdn);
		return 0;
	}
	if (strcmp(tmp1->str, "deleteoldrdn")) {
		fputs("Error: Expected 'deleteoldrdn'.\n", stderr);
		free(newrdn);
		return 0;
	}
	if (!strcmp(tmp2->str, "0"))
		*deleteoldrdn = 0;
	else if (!strcmp(tmp2->str, "1"))
		*deleteoldrdn = 1;
	else {
		fputs("Error: Expected '0' or '1' for 'deleteoldrdn'.\n",
		      stderr);
		free(newrdn);
		return 0;
	}

	if (ldif_read_line(s, tmp1, tmp2) == -1) return 0;
	if (tmp1->len == 0) {
		char *komma = strchr(olddn, ',');
		if (!komma) {
			/* probably cannot rename an entry directly below
			 * the Root DSE, but let's play along for now */
			return newrdn;
		}
		dn = xalloc(i + strlen(komma) + 1);
		strcpy(dn, newrdn);
		strcpy(dn + i, komma);
		free(newrdn);
		return dn;
	}
	if (strcmp(tmp1->str, "newsuperior")) {
		free(newrdn);
		fputs("Error: Garbage at end of moddn record.\n", stderr);
		return 0;
	}
	if (tmp2->len == 0)
		return newrdn;

	dn = xalloc(i + tmp2->len + 2);
	strcpy(dn, newrdn);
	dn[i] = ',';
	strcpy(dn + i + 1, tmp2->str);
	free(newrdn);
	return dn;
}

static int
ldif_read_nothing(FILE *s, GString *tmp1, GString *tmp2)
{
	if (ldif_read_line(s, tmp1, tmp2) == -1)
		return -1;
	if (tmp1->len) {
		fputs("Error: Garbage at end of record.\n", stderr);
		return -1;
	}
	return 0;
}

static LDAPMod *
ldif_ldapmod4line(char *action, char *ad)
{
	LDAPMod *m;
	int op;

 	if (!strcmp(action, "add"))
		op = LDAP_MOD_ADD;
	else if (!strcmp(action, "delete"))
		op = LDAP_MOD_DELETE;
	else if (!strcmp(action, "replace"))
		op = LDAP_MOD_REPLACE;
	else {
		fputs(action, stderr);
		fputs("Error: Invalid change marker.\n", stderr);
		return 0;
	}

	m = xalloc(sizeof(LDAPMod));
	m->mod_op = op | LDAP_MOD_BVALUES;
	m->mod_type = xdup(ad);
	return m;
}

static LDAPMod **
ldif_read_modify_body(FILE *s, GString *tmp1, GString *tmp2)
{
	LDAPMod **result;
	GPtrArray *mods = g_ptr_array_new();
	GPtrArray *values;
	LDAPMod *m = 0;
	int rc;

	for (;;) {
		switch (ldif_read_line(s, tmp1, tmp2)) {
		case 0:
			break;
		case -1:
			goto error;
		default:
			abort();
		}
		if (tmp1->len == 0)
			break;

		values = g_ptr_array_new();
		if ( !(m = ldif_ldapmod4line(tmp1->str, tmp2->str)))
			goto error;
		g_ptr_array_add(mods, m);

		do {
			switch ( rc = ldif_read_line1(s, tmp1, tmp2)) {
			case 0:
				if (strcmp(tmp1->str, m->mod_type)) {
					fputs("Error: Attribute name mismatch"
					      " in change-modify.",
					      stderr);
					goto error;
				}
				g_ptr_array_add(values, gstring2berval(tmp2));
				break;
			case -2:
				break;
			case -1:
				goto error;
			default:
				abort();
			}
		} while (rc != -2);

		g_ptr_array_add(values, 0);
		m->mod_bvalues = (void *) values->pdata;
		g_ptr_array_free(values, 0);
		values = 0;
	}

	g_ptr_array_add(mods, 0);
	result = (LDAPMod **) mods->pdata;
	g_ptr_array_free(mods, 0);
	return result;

error:
	g_ptr_array_free(mods, 1);
	if (values) {
		int i;
		for (i = 0; i < values->len; i++)
			xfree_berval(values->pdata[i]);
		g_ptr_array_free(values, 0);
	}
	return 0;
}

/*
 * Lies die erste Zeile eines beliebigen Records nach position `offset' in `s'.
 * Setze *pos (falls pos != 0).
 * Liefere 0 bei Erfolg, -1 sonst.
 * Bei Erfolg:
 *   - pos ist die exakte Anfangsposition.
 *   - Setze *key auf den Schluessel (falls key != 0).
 *   - Setze *dn auf den Distinguished Name (falls dn != 0).
 * EOF ist kein Fehler und liefert *key = 0 (falls key != 0);
 *
 * Der Schluessel ist dabei
 *   "delete" fuer "changetype: delete"
 *   "modify" fuer "changetype: modify"
 *   "rename" fuer "changetype: moddn" und "changetype: modrdn",
 *   "add" fuer "changetype: add" erlauben wir mal ganz frech ebenfalls
 * oder andernfalls der Wert von "ldapvi-key: ...", das als erste
 * Zeile im attrval-record erscheinen muss.
 */
static int
ldif_read_header(GString *tmp1, GString *tmp2,
		 FILE *s, long offset, char **key, char **dn, long *pos)
{
	char **rdns = 0;
	char *k;
	char *d;
	long pos2;

	if (offset != -1)
		if (fseek(s, offset, SEEK_SET) == -1) syserr();
	do {
		if (pos)
			if ( (*pos = ftell(s)) == -1) syserr();
		if (ldif_read_line(s, tmp1, tmp2) == -1) return -1;
		if (tmp1->len == 0 && feof(s)) {
			if (key) *key = 0;
			return 0;
		}
		if (!strcmp(tmp1->str, "version")) {
			if (strcmp(tmp2->str, "1")) {
				fputs("Error: Invalid file format.\n", stderr);
				return -1;
			}
			tmp1->len = 0;
		}
	} while (!tmp1->len);

	rdns = ldap_explode_dn(tmp2->str, 0);
	if (!rdns) {
		fputs("Error: Invalid distinguished name string.\n", stderr);
		return -1;
	}
	if (dn)
		d = xdup(tmp2->str);

	if ( (pos2 = ftell(s)) == -1) syserr();

	if (ldif_read_line(s, tmp1, tmp2) == -1) {
		if (dn) free(d);
		return -1;
	}
	if (!strcmp(tmp1->str, "ldapvi-key"))
		k = tmp2->str;
	else if (!strcmp(tmp1->str, "changetype")) {
		if (!strcmp(tmp2->str, "modrdn"))
			k = "rename";
		else if (!strcmp(tmp2->str, "moddn"))
			k = "rename";
		else if (!strcmp(tmp2->str, "delete")
			 || !strcmp(tmp2->str, "modify")
			 || !strcmp(tmp2->str, "add"))
			k = tmp2->str;
		else {
			fputs("Error: invalid changetype.\n", stderr);
			if (dn) free(d);
			return -1;
		}
	} else if (!strcmp(tmp1->str, "control")) {
		fputs("Error: Sorry, 'control:' not supported.\n", stderr);
		if (dn) free(d);
		return -1;
	} else {
		k = "add";
		if (fseek(s, pos2, SEEK_SET) == -1) syserr();
	}

	if (key) *key = xdup(k);
	if (dn) *dn = d;
	ldap_value_free(rdns);
	return 0;
}

static int
ldif_read_attrval_body(GString *tmp1, GString *tmp2, FILE *s, tentry *entry)
{
	for (;;) {
		tattribute *attribute;

		if (ldif_read_line(s, tmp1, tmp2) == -1)
			return -1;
		if (!tmp1->len)
			break;
		attribute = entry_find_attribute(entry, tmp1->str, 1);
		attribute_append_value(attribute, tmp2->str, tmp2->len);
	}
	return 0;
}

/*
 * Lies ein attrval-record nach position `offset' in `s'.
 * Setze *pos (falls pos != 0).
 * Liefere 0 bei Erfolg, -1 sonst.
 * Bei Erfolg:
 *   - pos ist die exakte Anfangsposition.
 *   - Setze *entry auf den gelesenen Eintrag (falls entry != 0).
 *   - Setze *key auf den Schluessel (falls key != 0).
 * EOF ist kein Fehler und liefert *key = 0 (falls key != 0);
 */
int
ldif_read_entry(FILE *s, long offset, char **key, tentry **entry, long *pos)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *dn;
	char *k = 0;
	tentry *e = 0;

	int rc = ldif_read_header(tmp1, tmp2, s, offset, &k, &dn, pos);
	if (rc || !k) goto cleanup;

	e = entry_new(dn);
	rc = ldif_read_attrval_body(tmp1, tmp2, s, e);
	if (!rc) {
		if (entry) {
			*entry = e;
			e = 0;
		}
		if (key) {
			*key = k;
			k = 0;
		}
	}

cleanup:
	if (k) free(k);
	if (e) entry_free(e);
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);
	return rc;
}

/*
 * Lies die ersten beiden Zeilen eines beliebigen Records nach position
 * `offset' in `s'.
 *
 * Setze *pos (falls pos != 0).
 * Liefere 0 bei Erfolg, -1 sonst.
 * Bei Erfolg:
 *   - pos ist die exakte Anfangsposition.
 *   - Setze *key auf den Schluessel (falls key != 0).
 */
int
ldif_peek_entry(FILE *s, long offset, char **key, long *pos)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");

	int rc = ldif_read_header(tmp1, tmp2, s, offset, key, 0, pos);
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);
	return rc;
}

/*
 * Lies ein rename-record nach position `offset' in `s'.
 * Liefere 0 bei Erfolg, -1 sonst.
 * Bei Erfolg:
 *   - Setze *dn1 auf den alten DN.
 *   - Setze *dn2 auf den neuen DN.
 *   - *deleteoldrdn auf 1 oder 0;
 */
int
ldif_read_rename(FILE *s, long offset, char **dn1, char **dn2,
		 int *deleteoldrdn)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *olddn;
	char *newdn;

	int rc = ldif_read_header(tmp1, tmp2, s, offset, 0, &olddn, 0);
	if (rc) {
		g_string_free(tmp1, 1);
		g_string_free(tmp2, 1);
		return rc;
	}

	newdn = ldif_read_rename_body(s, tmp1, tmp2, olddn, deleteoldrdn);
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);

	if (!newdn) {
		free(olddn);
		return -1;
	}
	if (dn1) *dn1 = olddn; else free(olddn);
	if (dn2) *dn2 = newdn; else free(newdn);
	return 0;
}

int
ldif_read_delete(FILE *s, long offset, char **dn)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *str;

	int rc = ldif_read_header(tmp1, tmp2, s, offset, 0, &str, 0);
	if (rc) {
		g_string_free(tmp1, 1);
		g_string_free(tmp2, 1);
		return rc;
	}

	rc = ldif_read_nothing(s, tmp1, tmp2);
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);

	if (rc == -1)
		free(str);
	else
		*dn = str;
	return rc;
}

/*
 * Lies ein modify-record nach position `offset' in `s'.
 * Liefere 0 bei Erfolg, -1 sonst.
 * Bei Erfolg:
 *   - Setze *dn auf den DN.
 *   - Setze *mods auf die Aenderungen.
 */
int
ldif_read_modify(FILE *s, long offset, char **dn, LDAPMod ***mods)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *d;
	LDAPMod **m;

	int rc = ldif_read_header(tmp1, tmp2, s, offset, 0, &d, 0);
	if (rc) {
		g_string_free(tmp1, 1);
		g_string_free(tmp2, 1);
		return rc;
	}

	m = ldif_read_modify_body(s, tmp1, tmp2);
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);

	if (!m) {
		free(d);
		return -1;
	}
	if (dn) *dn = d; else free(d);
	if (mods) *mods = m; else ldap_mods_free(m, 1);
	return 0;
}

/*
 * Parse a complete entry or changerecord and ignore it.  Set *key accordingly.
 * Leave the stream positioned after the entry.
 *
 * Treat EOF as success and set *key to NULL.
 *
 * return value:
 *   0 on success
 *   -1 on parse error
 */
int
ldif_skip_entry(FILE *s, long offset, char **key)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *k = 0;

	int rc = ldif_read_header(tmp1, tmp2, s, offset, &k, 0, 0);
	if (!rc && k)
		for (;;) {
			if (ldif_read_line1(s, tmp1, tmp2) == -1) {
				rc = -1;
				break;
			}
			if (tmp1->len == 0) {
				if (key) *key = k; else free(k);
				break;
			}
		}
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);
	return rc;
}

tparser ldif_parser = {
	ldif_read_entry,
	ldif_peek_entry,
	ldif_skip_entry,
	ldif_read_rename,
	ldif_read_delete,
	ldif_read_modify,
	print_ldif_entry
};
