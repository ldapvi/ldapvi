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
#include "config.h"

typedef void (*note_function)(void *, void *, void *);

static void
compare_ptr_arrays(GPtrArray *a, GPtrArray *b,
		   int (*cmp)(const void *, const void *),
		   note_function note,
		   void *x)
{
	int i = 0;
	int j = 0;

	qsort(a->pdata, a->len, sizeof(void *), cmp);
	qsort(b->pdata, b->len, sizeof(void *), cmp);

	while (i < a->len && j < b->len) {
		void *ax = g_ptr_array_index(a, i);
		void *bx = g_ptr_array_index(b, j);
		int n = cmp(&ax, &bx);
		if (n < 0)		{ note(ax, 0,  x);	i++; }
		else if (n == 0)	{ note(ax, bx, x);	i++; j++; }
		else 			{ note(0,  bx, x);	j++; }
	}
	if (i == a->len)
		for (; j < b->len; j++) note(0, g_ptr_array_index(b, j), x);
	else
		for (; i < a->len; i++) note(g_ptr_array_index(a, i), 0, x);
}

static int
ordered_array_equal(GPtrArray *a, GPtrArray *b,
		  int (*cmp)(const void *, const void *))
{
	int i;

	if (a->len != b->len)
		return 0;

	for (i = 0; i < a->len; i++) {
		void *ax = g_ptr_array_index(a, i);
		void *bx = g_ptr_array_index(b, i);
		if (cmp(&ax, &bx))
			return 0;
	}

	return 1;
}

static void
compare_attributes(tattribute *clean, tattribute *new, GPtrArray *mods)
{
	if (!ordered_array_equal(attribute_values(clean),
				 attribute_values(new),
				 carray_ptr_cmp))
	{
		LDAPMod *m = attribute2mods(new);
		m->mod_op |= LDAP_MOD_REPLACE;
		g_ptr_array_add(mods, m);
	}
}

static void
note_attributes(tattribute *a1, tattribute *a2, GPtrArray *mods)
{
	tattribute *a;
	GPtrArray *values;
	LDAPMod *m;
	int i;

	if (a1 && a2) {
		compare_attributes(a1, a2, mods);
		return;
	}

	m = xalloc(sizeof(LDAPMod));
	if (a1) {
		a = a1;
		m->mod_op = LDAP_MOD_DELETE;
	} else {
		a = a2;
		m->mod_op = LDAP_MOD_ADD;
	}

	values = attribute_values(a);
	m->mod_op |= LDAP_MOD_BVALUES;
	m->mod_type = xdup(attribute_ad(a));
	m->mod_bvalues = xalloc((1 + values->len) * sizeof(struct berval *));
	for (i = 0; i < values->len; i++)
		m->mod_bvalues[i]
			= string2berval(g_ptr_array_index(values, i));
	m->mod_bvalues[values->len] = 0;
	g_ptr_array_add(mods, m);
}

static LDAPMod **
compare_entries(tentry *eclean, tentry *enew)
{
	GPtrArray *mods = g_ptr_array_new();
	compare_ptr_arrays(entry_attributes(eclean),
			   entry_attributes(enew),
			   named_array_ptr_cmp,
			   (note_function) note_attributes,
			   mods);
	if (!mods->len) {
		g_ptr_array_free(mods, 1);
		return 0;
	}
	g_ptr_array_add(mods, 0);
	{
		LDAPMod **result = (LDAPMod **) mods->pdata;
		g_ptr_array_free(mods, 0);
		return result;
	}
}

void
long_array_invert(GArray *array, int i)
{
	g_array_index(array, long, i) = -2 - g_array_index(array, long, i);
}

/*
 * Read N bytes from stream S at position P and stream T at position Q
 * and compare them.  Return 0 if the segments are equal, else return 1.
 * If one the files terminates early, return 1.  In any case, reset the
 * streams to the position they had when this function was invoked.
 */
int
fastcmp(FILE *s, FILE *t, long p, long q, long n)
{
	char *b = xalloc(n);
	char *c = xalloc(n);
	int rc = -1;
	long p_save;
	long q_save;

	if ( (p_save = ftell(s)) == -1) syserr();
	if ( (q_save = ftell(t)) == -1) syserr();

	if (fseek(s, p, SEEK_SET) == -1) syserr();
	if (fseek(t, q, SEEK_SET) == -1) syserr();
	if (fread(b, 1, n, s) != n) { if (ferror(s)) syserr(); goto cleanup; }
	if (fread(c, 1, n, t) != n) { if (ferror(t)) syserr(); goto cleanup; }
	rc = memcmp(b, c, n) != 0;

cleanup:
	if (fseek(s, p_save, SEEK_SET) == -1) syserr();
	if (fseek(t, q_save, SEEK_SET) == -1) syserr();
	free(b);
	free(c);
	return rc;
}

/*
 * Do something with ENTRY and attribute AD, value DATA.
 *
 * With mode FROB_RDN_CHECK, determine whether the attribute value is present.
 * With mode FROB_RDN_CHECK_NONE, determine whether it isn't.
 * (Return 0 if so, -1 if not.)
 *
 * With mode FROB_RDN_REMOVE, remove it
 * With mode FROB_RDN_ADD, add it (unless already present)
 * (Return 0.)
 */
int
frob_ava(tentry *entry, int mode, char *ad, char *data, int n)
{
	tattribute *a;
	switch (mode) {
	case FROB_RDN_CHECK:
		a = entry_find_attribute(entry, ad, 0);
		if (!a) return -1;
		if (attribute_find_value(a, data, n) == -1) return -1;
		break;
	case FROB_RDN_CHECK_NONE:
		a = entry_find_attribute(entry, ad, 0);
		if (!a) return 0;
		if (attribute_find_value(a, data, n) == -1) return 0;
		return -1;
		break;
	case FROB_RDN_REMOVE:
		a = entry_find_attribute(entry, ad, 0);
		attribute_remove_value(a, data, n);
		break;
	case FROB_RDN_ADD:
		a = entry_find_attribute(entry, ad, 1);
                if (attribute_find_value(a, data, n) == -1)
                        attribute_append_value(a, data, n);
		break;
	}
	return 0;
}

/*
 * Call frob_ava for every ava in DN's (first) RDN.
 * DN must be valid.
 *
 * Return -1 if frob_ava ever does so, 0 else.
 */
int
frob_rdn(tentry *entry, char *dn, int mode)
{
#ifdef LIBLDAP21
	LDAPDN *olddn;
#else
	LDAPDN olddn;
#endif
	LDAPRDN rdn;
	int i;
	int rc = 0;

	ldap_str2dn(dn, &olddn, LDAP_DN_FORMAT_LDAPV3);

#ifdef LIBLDAP21
	rdn = (**olddn)[0];
#else
	rdn = olddn[0];
#endif
	for (i = 0; rdn[i]; i++) {
		LDAPAVA *ava = rdn[i];
		char *ad = ava->la_attr.bv_val;
		struct berval *bv = &ava->la_value;
		if (frob_ava(entry, mode, ad, bv->bv_val, bv->bv_len) == -1) {
			rc = -1;
			goto cleanup;
		}
	}

cleanup:
	ldap_dnfree(olddn);
	return rc;
}

/*
 * Check whether all of the following conditions are true and return a boolean.
 *   - none of the DNs is empty, so RDN-frobbing code can rely on senseful DNs
 *   - the attribute values in clean's RDN are contained in clean.
 *   - the attribute values in data's RDN are contained in data.
 *   - the attribute values in clean's RDN are either all contained in data
 *     or that none of them are.
 */
int
validate_rename(tentry *clean, tentry *data, int *deleteoldrdn)
{
	if (!*entry_dn(clean)) {
		puts("Error: Cannot rename ROOT_DSE.");
		return -1;
	}
	if (!*entry_dn(data)) {
		puts("Error: Cannot replace ROOT_DSE.");
		return -1;
	}
	if (frob_rdn(clean, entry_dn(clean), FROB_RDN_CHECK) == -1) {
		puts("Error: Old RDN not found in entry.");
		return -1;
	}
	if (frob_rdn(data, entry_dn(data), FROB_RDN_CHECK) == -1) {
		puts("Error: New RDN not found in entry.");
		return -1;
	}
	if (frob_rdn(data, entry_dn(clean), FROB_RDN_CHECK) != -1)
		*deleteoldrdn = 0;
	else if (frob_rdn(data, entry_dn(clean), FROB_RDN_CHECK_NONE) != -1)
		*deleteoldrdn = 1;
	else {
		puts("Error: Incomplete RDN change.");
		return -1;
	}
	return 0;
}

static void
rename_entry(tentry *entry, char *newdn, int deleteoldrdn)
{
	if (deleteoldrdn)
		frob_rdn(entry, entry_dn(entry), FROB_RDN_REMOVE);
	frob_rdn(entry, newdn, FROB_RDN_ADD);
	free(entry_dn(entry));
	entry_dn(entry) = xdup(newdn);
}

static void
update_clean_copy(
	GArray *offsets, char *key, FILE *s, tentry *cleanentry, tparser *p)
{
	long pos = fseek(s, 0, SEEK_END);
	if (pos == -1) syserr();
	g_array_index(offsets, long, atoi(key)) = ftell(s);
	p->print(s, cleanentry, key, 0);
}

/*
 * read a changerecord of type `key' from `data', handle it, and return
 *    0 on success
 *   -1 on syntax error
 *   -2 on handler error
 */
int
process_immediate(tparser *p, thandler *handler, void *userdata, FILE *data,
		  long datapos, char *key)
{
	if (!strcmp(key, "add")) {
		tentry *entry;
		LDAPMod **mods;
		if (p->entry(data, datapos, 0, &entry, 0) == -1)
			return -1;
		mods = entry2mods(entry);
		if (handler->add(-1, entry_dn(entry), mods, userdata) == -1) {
			ldap_mods_free(mods, 1);
			entry_free(entry);
			return -2;
		}
		ldap_mods_free(mods, 1);
		entry_free(entry);
		entry = 0;
	} else if (!strcmp(key, "replace")) {
		tentry *entry;
		LDAPMod **mods;
		int i;
		if (p->entry(data, datapos, 0, &entry, 0) == -1)
			return -1;
		mods = entry2mods(entry);
		for (i = 0; mods[i]; i++) {
			LDAPMod *mod = mods[i];
			mod->mod_op &= LDAP_MOD_BVALUES;
			mod->mod_op |= LDAP_MOD_REPLACE;
		}
		if (handler->change(-1,
				    entry_dn(entry),
				    entry_dn(entry),
				    mods,
				    userdata) == -1) {
			ldap_mods_free(mods, 1);
			entry_free(entry);
			return -2;
		}
		ldap_mods_free(mods, 1);
		entry_free(entry);
		entry = 0;
	} else if (!strcmp(key, "rename")) {
		char *dn1;
		char *dn2;
		int deleteoldrdn;
		int rc;
		if (p->rename(data, datapos, &dn1, &dn2, &deleteoldrdn) ==-1)
			return -1;
		rc = handler->rename0(-1, dn1, dn2, deleteoldrdn, userdata);
		free(dn1);
		free(dn2);
		if (rc)
			return -2;
	} else if (!strcmp(key, "delete")) {
		char *dn;
		int rc;
		if (p->delete(data, datapos, &dn) == -1)
			return -1;
		rc = handler->delete(-1, dn, userdata);
		free(dn);
		if (rc)
			return -2;
	} else if (!strcmp(key, "modify")) {
		char *dn;
		LDAPMod **mods;
		if (p->modify(data, datapos, &dn, &mods) ==-1)
			return -1;
		if (handler->change(-1, dn, dn, mods, userdata) == -1) {
			free(dn);
			ldap_mods_free(mods, 1);
			return -2;
		}
	} else {
		fprintf(stderr, "Error: Invalid key: `%s'.\n", key);
		return -1;
	}
	return 0;
}

/*
 * read the next entry from `data', its clean copy from `clean', process
 * them as described for compare_streams, and return
 *    0 on success
 *   -1 on syntax error
 *   -2 on handler error
 */
static int
process_next_entry(
	tparser *p, thandler *handler, void *userdata, GArray *offsets,
	FILE *clean, FILE *data, char *key, long datapos)
{
	tentry *entry = 0;
	tentry *cleanentry = 0;
	int rc = -1;
	LDAPMod **mods;
	long pos;
	char *ptr;
	int n;
	int rename, deleteoldrdn;

	/* find clean copy */
	n = strtol(key, &ptr, 10);
	if (*ptr)
		return process_immediate(
			p, handler, userdata, data, datapos, key);
	if (n < 0 || n >= offsets->len) {
		fprintf(stderr, "Error: Invalid key: `%s'.\n", key);
		goto cleanup;
	}
	pos = g_array_index(offsets, long, n);
	if (pos < 0) {
		fprintf(stderr, "Error: Duplicate entry %d.\n", n);
		goto cleanup;
	}

	/* find precise position */
	if (p->entry(clean, pos, 0, 0, &pos) == -1) abort();
	/* fast comparison */
	if (n + 1 < offsets->len) {
		long next = g_array_index(offsets, long, n + 1);
		if (next >= 0
		    && !fastcmp(clean, data, pos, datapos, next-pos+1))
		{
			datapos += next - pos;
			long_array_invert(offsets, n);
			if (fseek(data, datapos, SEEK_SET) == -1)
				syserr();
			return 0;
		}
	}

	/* if we get here, a quick scan found a difference in the
	 * files, so we need to read the entries and compare them */
	if (p->entry(data, datapos, 0, &entry, 0) == -1)
		goto cleanup;
	if (p->entry(clean, pos, 0, &cleanentry, 0) == -1) abort();

	/* compare and update */
	if ( (rename = strcmp(entry_dn(cleanentry), entry_dn(entry)))){
		if (validate_rename(cleanentry, entry, &deleteoldrdn)){
			rc = -1;
			goto cleanup;
		}
		if (handler->rename(n, entry_dn(cleanentry), entry, userdata)
		    == -1)
		{
			rc = -2;
			goto cleanup;
		}
		rename_entry(cleanentry, entry_dn(entry), deleteoldrdn);
	}
	if ( (mods = compare_entries(cleanentry, entry))) {
		if (handler->change(n,
				    entry_dn(cleanentry),
				    entry_dn(entry),
				    mods,
				    userdata)
		    == -1)
		{
			if (mods) ldap_mods_free(mods, 1);
			if (rename)
				update_clean_copy(
					offsets, key, clean, cleanentry, p);
			rc = -2;
			goto cleanup;
		}
		ldap_mods_free(mods, 1);
	}

	/* mark as seen */
	long_array_invert(offsets, n);

	entry_free(entry);
	entry = 0;
	entry_free(cleanentry);
	cleanentry = 0;
	return 0;

cleanup:
	if (entry) {
		if (*entry_dn(entry))
			fprintf(stderr, "Error at: %s\n", entry_dn(entry));
		entry_free(entry);
	}
	if (cleanentry) entry_free(cleanentry);
	return rc;
}

static int
nonleaf_action(tentry *entry, GArray *offsets, int n)
{
	int i;

	printf("Error: Cannot delete non-leaf entry: %s\n", entry_dn(entry));

	for (i = n + 1; i < offsets->len; i++) {
		if (g_array_index(offsets, long, n) >= 0)
			goto more_deletions;
	}
	/* no more deletions anyway, so no need to ignore this one */
	return 0;

more_deletions:
	switch (choose("Continue?", "yn!Q?", "(Type '?' for help.)")) {
	case 'y':
		return 1;
	case '!':
		return 2;
	case 'n':
		return 0;
	case 'Q':
		exit(0);
	case '?':
		puts("Commands:\n"
		     "  y -- continue deleting other entries\n"
		     "  ! -- continue and assume 'y' until done\n"
		     "  n -- abort deletions\n"
		     "  Q -- discard changes and quit\n"
		     "  ? -- this help");
		goto more_deletions;
	}

	/* notreached */
	return 0;
}

/*
 * process deletions as described for compare_streams.
 * return 0 on success, -2 else.
 */
static int
process_deletions(tparser *p,
		  thandler *handler,
		  void *userdata,
		  GArray *offsets,
		  FILE *clean)
{
	tentry *cleanentry = 0;
	long pos;
	int n;
	int ignore_nonleaf = 0;
	int n_leaf;
	int n_nonleaf;

	do {
		if (ignore_nonleaf)
			printf("Retrying %d failed deletion%s...\n",
			       n_nonleaf,
			       n_nonleaf == 1 ? "" : "s");
		n_leaf = 0;
		n_nonleaf = 0;
		for (n = 0; n < offsets->len; n++) {
			if ( (pos = g_array_index(offsets, long, n)) < 0)
				continue;
			if (p->entry(clean, pos, 0, &cleanentry, 0) == -1)
				abort();
			switch (handler->delete(
					n, entry_dn(cleanentry), userdata))
			{
			case -1:
				entry_free(cleanentry);
				return -2;
			case -2:
				if (ignore_nonleaf) {
					printf("Skipping non-leaf entry: %s\n",
					       entry_dn(cleanentry));
					n_nonleaf++;
					break;
				}
				switch (nonleaf_action(cleanentry,offsets,n)) {
				case 0:
					entry_free(cleanentry);
					return -2;
				case 2:
					ignore_nonleaf = 1;
					/* fall through */
				case 1:
					n_nonleaf++;
				}
				break;
			default:
				n_leaf++;
				long_array_invert(offsets, n);
			}
			entry_free(cleanentry);
		}
	} while (ignore_nonleaf && n_nonleaf > 0 && n_leaf > 0);

	return n_nonleaf ? -2 : 0;
}

/*
 * The compare_streams loop is the heart of ldapvi.
 *
 * Read two ldapvi data files in streams CLEAN and DATA and compare them.
 *
 * File CLEAN must contain numbered entries with consecutive keys starting at
 * zero.  For each of these entries, array offset must contain a position
 * in the file, such that the entry can be read by seeking to that position
 * and calling read_entry().
 *
 * File DATA, a modified copy of CLEAN may contain entries in any order,
 * which must be numbered or labeled "add", "rename", or "modify".  If a
 * key is a number, the corresponding entry in CLEAN must exist, it is
 * read and compared to the modified copy.
 *
 * For each change, call the appropriate handler method with arguments
 * described below.  Handler methods must return 0 on success, or -1 on
 * failure.  (As a special case, return value -2 on a deletion indicates
 * an attempt to delete a non-leaf entry, which is non-fatal.)
 *
 * For each new entry (labeled with "add"), call
 *   handler->add(dn, mods, USERDATA)
 * where MODS is a LDAPMod structure for the new entry.
 *
 * For each entry present in CLEAN but not DATA, call
 *   handler->delete(dn, USERDATA)
 * (This step can be repeated in the case of non-leaf entries.)
 *
 * For each entry present in both files, handler can be called two times.
 * If the distinguished names of the old and new entry disagree, call
 *   handler->change(old_entry, new_entry, 0, USERDATA)
 * If there are additional changes to the attributes of the entry, call
 *   handler->change(renamed_entry, new_entry, mods, USERDATA)
 * where RENAMED_ENTRY is a copy of the original entry, which accounts
 * for attribute modifications due to a possible RDN change (new RDN
 * component values have to be added, and old RDN values be removed),
 * and MODS describes the changes between RENAMED_ENTRY and NEW_ENTRY.
 *
 * Entries labeled "delete" are changerecords for which the handler is
 * called as described above.
 *
 * Entries labeled "rename" are changerecords with their own method,
 * called as:
 *   handler->rename(olddn, newdn, deleteoldrdn, USERDATA)
 *
 * Return 0 on success, -1 on parse error, -2 on handler failure.
 *
 * If an error occured, *error_position is the offset in DATA after
 * which the erroneous entry can be found.
 */
int
compare_streams(tparser *p,
		thandler *handler,
		void *userdata,
		GArray *offsets,
		FILE *clean,
		FILE *data,
		long *error_position,
		long *syntax_error_position)
{
	char *key = 0;
	int n;
	int rc;

	for (;;) {
		long datapos;

		/* read updated entry */
		if (key) { free(key); key = 0; }
		if (p->peek(data, -1, &key, &datapos) == -1) goto cleanup;
		*error_position = datapos;
		if (!key) break;

		/* and do something with it */
		if ( (rc = process_next_entry(
			      p, handler, userdata, offsets, clean, data,
			      key, datapos)))
			goto cleanup;
	}
	if ( (*error_position = ftell(data)) == -1) syserr();

	rc = process_deletions(p, handler, userdata, offsets, clean);

cleanup:
	if (key) free(key);

	if (syntax_error_position)
		if ( (*syntax_error_position = ftell(data)) == -1) syserr();

	/* on user error, return now and keep state for recovery */
	if (rc == -2) return rc;

	/* else some cleanup: unmark offsets */
	for (n = 0; n < offsets->len; n++)
		if (g_array_index(offsets, long, n) < 0)
			long_array_invert(offsets, n);
	return rc;
}
