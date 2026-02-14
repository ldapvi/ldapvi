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
#include <crypt.h>
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

static int
read_lhs(FILE *s, GString *lhs)
{
	int c;

	for (;;) {
		switch ( c = getc_unlocked(s)) {
		case ' ':
			if (ferror(s)) syserr();
			return 0;
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		case '\n':
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
read_backslashed(FILE *s, GString *data)
{
	int c;

	for (;;) {
		switch ( c = getc_unlocked(s)) {
		case '\n':
			if (ferror(s)) syserr();
			return 0;
		case EOF:
			goto error;
		case '\\':
			if ( (c = fgetc(s)) == EOF) goto error;
			/* fall through */
		default:
			fast_g_string_append_c(data, c);
		}
	}

error:
	fputs("Error: Unexpected EOF.\n", stderr);
	return -1;
}

static int
read_ldif_attrval(FILE *s, GString *data)
{
	int c;

	for (;;)
		switch ( c = getc_unlocked(s)) {
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
read_from_file(GString *data, char *name)
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
skip_comment(FILE *s)
{
	int c;

	for (;;)
		switch ( c = fgetc(s)) {
		case EOF:
			fputs("Error: Unexpected EOF.\n", stderr);
			return -1;
		case '\n':
			if ( (c = fgetc(s)) == ' ') /* folded line */ break;
			ungetc(c, s);
			if (ferror(s)) syserr();
			return 0;
		}
}

static char *saltbag
	= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890./";

static char *
cryptdes(char *key)
{
	unsigned char salt[2];
	int fd = open("/dev/random", 2);
	if (fd == -1) {
		puts("Sorry, crypt not available: Cannot open /dev/random.");
		return 0;
	}
	if (read(fd, salt, 2) != 2) syserr();
	close(fd);
	salt[0] = saltbag[salt[0] & 63];
	salt[1] = saltbag[salt[1] & 63];
	return crypt(key, (char *) salt);
}

static char *
cryptmd5(char *key)
{
	char *result;
	unsigned char salt[11];
	int i;
	int fd = open("/dev/random", 2);
	if (fd == -1) {
		puts("Sorry, MD5 not available: Cannot open /dev/random.");
		return 0;
	}
	salt[0] = '$';
	salt[1] = '1';
	salt[2] = '$';
	if (read(fd, salt + 3, 8) != 8) syserr();
	close(fd);
	for (i = 3; i < 11; i++)
		salt[i] = saltbag[salt[i] & 63];
	result = crypt(key, (char *) salt);
	if (!result || strlen(result) < 25) {
		puts("Sorry, MD5 not available: Are you using the glibc?");
		return 0;
	}
	return result;
}

/*
 * Read a line in
 *   name ' ' (':' encoding)? value '\n'
 * syntax, skipping comments.  VALUE is parsed according to ENCODING.
 * Empty NAME is allowed.
 *
 * 0: ok
 * -1: fatal parse error
 * -2: end of file or empty line
 */
static int
read_line1(FILE *s, GString *name, GString *value)
{
	int c;
	char *encoding;

	g_string_truncate(name, 0);
	g_string_truncate(value, 0);

	/* skip comment lines */
	do {
		c = fgetc(s);
		switch (c) {
		case EOF:
			if (ferror(s)) syserr();
			return -2;
		case '\n':
			return -2;
		case '#':
			if (skip_comment(s) == -1) return -1;
			break;
		default:
			ungetc(c, s);
			c = -1;
		}
	} while (c != -1);

	if (read_lhs(s, name) == -1) return -1;
	if ( encoding = memchr(name->str, ':', name->len)) {
		encoding++;
		name->len = encoding - name->str - 1;
		name->str[name->len] = 0;
	}

	if (!encoding || !strcmp(encoding, ";")) {
		if (read_backslashed(s, value) == -1) return -1;
	} else if (!*encoding) {
		if (read_ldif_attrval(s, value) == -1) return -1;
	} else if (!strcmp(encoding, ":")) {
		unsigned char *ustr;
		int len;
		if (read_ldif_attrval(s, value) == -1) return -1;
		ustr = (unsigned char *) value->str;;
		if ( (len = read_base64(value->str, ustr, value->len)) == -1) {
			fputs("Error: Invalid Base64 string.\n", stderr);
			return -1;
		}
		value->len = len;
	} else if (!strcmp(encoding, "<")) {
		if (read_ldif_attrval(s, value) == -1) return -1;
		if (strncmp(value->str, "file://", 7)) {
			fputs("Error: Unknown URL scheme.\n", stderr);
			return -1;
		}
		if (read_from_file(value, value->str + 7) == -1)
			return -1;
	} else if (!strcasecmp(encoding, "crypt")) {
		char *hash;
		if (read_ldif_attrval(s, value) == -1) return -1;
		if ( !(hash = cryptdes(value->str))) return -1;
		g_string_assign(value, "{CRYPT}");
		g_string_append(value, hash);
	} else if (!strcasecmp(encoding, "cryptmd5")) {
		char *hash;
		if (read_ldif_attrval(s, value) == -1) return -1;
		if ( !(hash = cryptmd5(value->str))) return -1;
		g_string_assign(value, "{CRYPT}");
		g_string_append(value, hash);
	} else if (!strcasecmp(encoding, "sha")) {
		if (read_ldif_attrval(s, value) == -1) return -1;
		g_string_assign(value, "{SHA}");
		if (!g_string_append_sha(value, value->str)) return -1;
	} else if (!strcasecmp(encoding, "ssha")) {
		if (read_ldif_attrval(s, value) == -1) return -1;
		g_string_assign(value, "{SSHA}");
		if (!g_string_append_ssha(value, value->str)) return -1;
	} else if (!strcasecmp(encoding, "md5")) {
		if (read_ldif_attrval(s, value) == -1) return -1;
		g_string_assign(value, "{MD5}");
		if (!g_string_append_md5(value, value->str)) return -1;
	} else if (!strcasecmp(encoding, "smd5")) {
		if (read_ldif_attrval(s, value) == -1) return -1;
		g_string_assign(value, "{SMD5}");
		if (!g_string_append_smd5(value, value->str)) return -1;
	} else {
		char *ptr;
		int n = strtol(encoding, &ptr, 10);
		if (*ptr) {
			fputs("Error: Unknown value encoding.\n", stderr);
			return -1;
		}
		g_string_set_size(value, n);
		if (fread(value->str, 1, n, s) != n) syserr();
	}
	return 0;
}


/*
 * Read a line in
 *   name ' ' (':' encoding)? value '\n'
 * syntax, skipping comments.  VALUE is parsed according to ENCODING.
 * Empty NAME is a parse error.
 *
 * 0: ok                           if name->len != 0
 * 0: end of file or empty line    if name->len == 0
 * -1: parse error
 */
static int
read_line(FILE *s, GString *name, GString *value)
{
	int rc = read_line1(s, name, value);
	switch (rc) {
	case -2:
		return 0;
	case -1:
		return -1;
	case 0:
		if (!name->len) {
			fputs("Error: Space at beginning of line.\n", stderr);
			return -1;
		}
		return 0;
	default:
		abort();
	}
}

static char *
read_rename_body(FILE *s, GString *tmp1, GString *tmp2, int *deleteoldrdn)
{
	char *dn;

	if (read_line(s, tmp1, tmp2) == -1)
		return 0;
	if (!tmp1->len) {
		fputs("Error: Rename record lacks dn line.\n", stderr);
		return 0;
	}
	*deleteoldrdn = !strcmp(tmp1->str, "replace");
	if (!*deleteoldrdn && strcmp(tmp1->str, "add")) {
		fputs("Error: Expected 'add' or 'replace' in rename record.\n",
		      stderr);
		return 0;
	}
	dn = xdup(tmp2->str);
	if (read_line(s, tmp1, tmp2) == -1) {
		free(dn);
		return 0;
	}
	if (tmp1->len) {
		free(dn);
		fputs("Error: Garbage at end of rename record.\n", stderr);
		return 0;
	}
	return dn;
}

static int
read_nothing(FILE *s, GString *tmp1, GString *tmp2)
{
	if (read_line(s, tmp1, tmp2) == -1)
		return -1;
	if (tmp1->len) {
		fputs("Error: Garbage at end of record.\n", stderr);
		return -1;
	}
	return 0;
}

static LDAPMod *
ldapmod4line(char *action, char *ad)
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
		fputs("Error: Invalid change marker.\n", stderr);
		return 0;
	}

	m = xalloc(sizeof(LDAPMod));
	m->mod_op = op | LDAP_MOD_BVALUES;
	m->mod_type = xdup(ad);
	return m;
}

static LDAPMod **
read_modify_body(FILE *s, GString *tmp1, GString *tmp2)
{
	LDAPMod **result;
	GPtrArray *mods = g_ptr_array_new();
	GPtrArray *values;
	LDAPMod *m = 0;

	for (;;) {
		switch (read_line1(s, tmp1, tmp2)) {
		case 0:
			break;
		case -1:
			goto error;
		case -2:
			if (m) {
				g_ptr_array_add(values, 0);
				m->mod_bvalues = (void *) values->pdata;
				g_ptr_array_free(values, 0);
				values = 0;
			}
			goto done;
		default:
			abort();
		}
		if (tmp1->len) {
			if (m) {
				g_ptr_array_add(values, 0);
				m->mod_bvalues = (void *) values->pdata;
				g_ptr_array_free(values, 0);
				values = 0;
			}
			values = g_ptr_array_new();
			if ( !(m = ldapmod4line(tmp1->str, tmp2->str)))
				goto error;
			g_ptr_array_add(mods, m);
		} else
			g_ptr_array_add(values, gstring2berval(tmp2));
	}
done:

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
 */
static int
read_header(GString *tmp1, GString *tmp2,
	    FILE *s, long offset, char **key, char **dn, long *pos)
{
	char **rdns = 0;

	if (offset != -1)
		if (fseek(s, offset, SEEK_SET) == -1) syserr();
	do {
		if (pos)
			if ( (*pos = ftell(s)) == -1) syserr();
		if (read_line(s, tmp1, tmp2) == -1) return -1;
		if (tmp1->len == 0 && feof(s)) {
			if (key) *key = 0;
			return 0;
		}
		if (!strcmp(tmp1->str, "version")) {
			if (strcmp(tmp2->str, "ldapvi")) {
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

	if (key) *key = xdup(tmp1->str);
	if (dn) *dn = xdup(tmp2->str);
	ldap_value_free(rdns);
	return 0;
}

static int
read_attrval_body(GString *tmp1, GString *tmp2, FILE *s, tentry *entry)
{
	for (;;) {
		tattribute *attribute;

		if (read_line(s, tmp1, tmp2) == -1)
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
read_entry(FILE *s, long offset, char **key, tentry **entry, long *pos)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *dn;
	char *k = 0;
	tentry *e = 0;

	int rc = read_header(tmp1, tmp2, s, offset, &k, &dn, pos);
	if (rc || !k) goto cleanup;

	e = entry_new(dn);
	rc = read_attrval_body(tmp1, tmp2, s, e);
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
 * Lies die erste Zeile eines beliebigen Records nach position `offset' in `s'.
 * Setze *pos (falls pos != 0).
 * Liefere 0 bei Erfolg, -1 sonst.
 * Bei Erfolg:
 *   - pos ist die exakte Anfangsposition.
 *   - Setze *key auf den Schluessel (falls key != 0).
 */
int
peek_entry(FILE *s, long offset, char **key, long *pos)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");

	int rc = read_header(tmp1, tmp2, s, offset, key, 0, pos);
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
read_rename(FILE *s, long offset, char **dn1, char **dn2, int *deleteoldrdn)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *olddn;
	char *newdn;

	int rc = read_header(tmp1, tmp2, s, offset, 0, &olddn, 0);
	if (rc) {
		g_string_free(tmp1, 1);
		g_string_free(tmp2, 1);
		return rc;
	}

	newdn = read_rename_body(s, tmp1, tmp2, deleteoldrdn);
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
read_delete(FILE *s, long offset, char **dn)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *str;

	int rc = read_header(tmp1, tmp2, s, offset, 0, &str, 0);
	if (rc) {
		g_string_free(tmp1, 1);
		g_string_free(tmp2, 1);
		return rc;
	}

	rc = read_nothing(s, tmp1, tmp2);
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
read_modify(FILE *s, long offset, char **dn, LDAPMod ***mods)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *d;
	LDAPMod **m;

	int rc = read_header(tmp1, tmp2, s, offset, 0, &d, 0);
	if (rc) {
		g_string_free(tmp1, 1);
		g_string_free(tmp2, 1);
		return rc;
	}

	m = read_modify_body(s, tmp1, tmp2);
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
/*
 * FIXME: Warum lesen wir hier nicht einfach bis zur naechsten leeren Zeile?
 */
int
skip_entry(FILE *s, long offset, char **key)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *k = 0;

	int rc = read_header(tmp1, tmp2, s, offset, &k, 0, 0);
	if (rc || !k)
		;
	else if (!strcmp(k, "modify")) {
		LDAPMod **mods = read_modify_body(s, tmp1, tmp2);
		if (mods)
			ldap_mods_free(mods, 1);
		else
			rc = -1;
	} else if (!strcmp(k, "rename")) {
		int dor;
		char *newdn = read_rename_body(s, tmp1, tmp2, &dor);
		if (newdn)
			free(newdn);
		else
			rc = -1;
	} else if (!strcmp(k, "delete"))
		rc = read_nothing(s, tmp1, tmp2);
	else {
		tentry *e = entry_new(xdup(""));
		rc = read_attrval_body(tmp1, tmp2, s, e);
		entry_free(e);
	}

	if (key) *key = k; else free(k);
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);
	return rc;
}

static int
read_profile_header(GString *tmp1, GString *tmp2, FILE *s, char **name)
{
	do {
		if (read_line(s, tmp1, tmp2) == -1) return -1;
		if (tmp1->len == 0 && feof(s)) {
			*name = 0;
			return 0;
		}
	} while (!tmp1->len);

	if (strcmp(tmp1->str, "profile")) {
		fprintf(stderr,
			"Error: Expected 'profile' in configuration,"
			" found '%s' instead.\n",
			tmp1->str);
		return -1;
	}

	*name = xdup(tmp2->str);
	return 0;
}

int
read_profile(FILE *s, tentry **entry)
{
	GString *tmp1 = g_string_new("");
	GString *tmp2 = g_string_new("");
	char *name;
	tentry *e = 0;

	int rc = read_profile_header(tmp1, tmp2, s, &name);
	if (rc || !name) goto cleanup;

	e = entry_new(name);
	rc = read_attrval_body(tmp1, tmp2, s, e);
	if (!rc) {
		*entry = e;
		e = 0;
	}

cleanup:
	if (e) entry_free(e);
	g_string_free(tmp1, 1);
	g_string_free(tmp2, 1);
	return rc;
}

tparser ldapvi_parser = {
	read_entry,
	peek_entry,
	skip_entry,
	read_rename,
	read_delete,
	read_modify,
	print_ldapvi_entry
};
