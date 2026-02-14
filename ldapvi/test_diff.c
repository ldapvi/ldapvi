/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for diff.c - the stream comparison engine.
 */
#define _GNU_SOURCE
#include "common.h"
#include "config.h"
#include "test_harness.h"

/* Forward declarations for diff.c functions */
void long_array_invert(GArray *array, int i);
int fastcmp(FILE *s, FILE *t, long p, long q, long n);
int frob_ava(tentry *entry, int mode, char *ad, char *data, int n);
int frob_rdn(tentry *entry, char *dn, int mode);
int validate_rename(tentry *clean, tentry *data, int *deleteoldrdn);
int process_immediate(tparser *p, thandler *handler, void *userdata,
		      FILE *data, long datapos, char *key);
int compare_streams(tparser *p, thandler *handler, void *userdata,
		    GArray *offsets, FILE *clean, FILE *data,
		    long *error_position, long *syntax_error_position);


/*
 * Helpers
 */
static tentry *
make_entry(const char *dn)
{
	return entry_new(xdup((char *) dn));
}

static void
add_attr_value(tentry *entry, const char *ad, const char *val)
{
	tattribute *a = entry_find_attribute(entry, (char *) ad, 1);
	attribute_append_value(a, (char *) val, strlen(val));
}

/* Write string data to a tmpfile and rewind */
static FILE *
make_tmpfile(const char *data)
{
	FILE *f = tmpfile();
	if (!f) { perror("tmpfile"); abort(); }
	if (data && *data) {
		fwrite(data, 1, strlen(data), f);
		rewind(f);
	}
	return f;
}

/* Build clean file and offsets array from LDIF string.
 * The LDIF must use ldapvi-key lines with consecutive keys starting at 0. */
static FILE *
make_clean_file(const char *ldif, GArray **offsets_out)
{
	FILE *f = make_tmpfile(ldif);
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	char *key = NULL;
	long pos;

	while (ldif_peek_entry(f, -1, &key, &pos) == 0 && key) {
		char *end;
		long n = strtol(key, &end, 10);
		if (*end) { free(key); break; }
		/* Extend array if needed */
		while (offsets->len <= n) {
			long zero = 0;
			g_array_append_val(offsets, zero);
		}
		g_array_index(offsets, long, n) = pos;
		free(key);
		key = NULL;
		ldif_skip_entry(f, -1, NULL);
	}
	rewind(f);
	*offsets_out = offsets;
	return f;
}


/*
 * Mock handler infrastructure
 */
#define MAX_CALLS 32

typedef enum {
	CALL_CHANGE, CALL_RENAME, CALL_ADD, CALL_DELETE, CALL_RENAME0
} call_type;

typedef struct {
	call_type type;
	int n;
	char *dn;
	char *dn2;       /* new dn for change/rename0 */
	int deleteoldrdn; /* for rename0 */
	int num_mods;
} mock_call;

typedef struct {
	mock_call calls[MAX_CALLS];
	int num_calls;
	int fail_on_call;  /* -1 = never fail */
} mock_state;

static void
mock_init(mock_state *m)
{
	memset(m, 0, sizeof(*m));
	m->fail_on_call = -1;
}

static int
mock_change(int n, char *olddn, char *newdn, LDAPMod **mods, void *userdata)
{
	mock_state *m = userdata;
	mock_call *c;
	if (m->num_calls >= MAX_CALLS) abort();
	c = &m->calls[m->num_calls];
	c->type = CALL_CHANGE;
	c->n = n;
	c->dn = xdup(olddn);
	c->dn2 = xdup(newdn);
	c->num_mods = 0;
	if (mods) for (int i = 0; mods[i]; i++) c->num_mods++;
	if (m->num_calls == m->fail_on_call) { m->num_calls++; return -1; }
	m->num_calls++;
	return 0;
}

static int
mock_rename(int n, char *olddn, tentry *entry, void *userdata)
{
	mock_state *m = userdata;
	mock_call *c;
	if (m->num_calls >= MAX_CALLS) abort();
	c = &m->calls[m->num_calls];
	c->type = CALL_RENAME;
	c->n = n;
	c->dn = xdup(olddn);
	c->dn2 = xdup(entry_dn(entry));
	if (m->num_calls == m->fail_on_call) { m->num_calls++; return -1; }
	m->num_calls++;
	return 0;
}

static int
mock_add(int n, char *dn, LDAPMod **mods, void *userdata)
{
	mock_state *m = userdata;
	mock_call *c;
	if (m->num_calls >= MAX_CALLS) abort();
	c = &m->calls[m->num_calls];
	c->type = CALL_ADD;
	c->n = n;
	c->dn = xdup(dn);
	c->num_mods = 0;
	if (mods) for (int i = 0; mods[i]; i++) c->num_mods++;
	if (m->num_calls == m->fail_on_call) { m->num_calls++; return -1; }
	m->num_calls++;
	return 0;
}

static int
mock_delete(int n, char *dn, void *userdata)
{
	mock_state *m = userdata;
	mock_call *c;
	if (m->num_calls >= MAX_CALLS) abort();
	c = &m->calls[m->num_calls];
	c->type = CALL_DELETE;
	c->n = n;
	c->dn = xdup(dn);
	if (m->num_calls == m->fail_on_call) { m->num_calls++; return -1; }
	m->num_calls++;
	return 0;
}

static int
mock_rename0(int n, char *dn1, char *dn2, int deleteoldrdn, void *userdata)
{
	mock_state *m = userdata;
	mock_call *c;
	if (m->num_calls >= MAX_CALLS) abort();
	c = &m->calls[m->num_calls];
	c->type = CALL_RENAME0;
	c->n = n;
	c->dn = xdup(dn1);
	c->dn2 = xdup(dn2);
	c->deleteoldrdn = deleteoldrdn;
	if (m->num_calls == m->fail_on_call) { m->num_calls++; return -1; }
	m->num_calls++;
	return 0;
}

static void
mock_free(mock_state *m)
{
	for (int i = 0; i < m->num_calls; i++) {
		free(m->calls[i].dn);
		free(m->calls[i].dn2);
	}
}

static thandler mock_handler = {
	mock_change, mock_rename, mock_add, mock_delete, mock_rename0
};


/* ===================================================================
 * Tests for long_array_invert
 * =================================================================== */

static int test_long_array_invert_basic(void)
{
	GArray *a = g_array_new(0, 0, sizeof(long));
	long v = 100;
	g_array_append_val(a, v);
	long_array_invert(a, 0);
	ASSERT_INT_EQ(g_array_index(a, long, 0), -102);
	g_array_free(a, 1);
	return 1;
}

static int test_long_array_invert_double(void)
{
	GArray *a = g_array_new(0, 0, sizeof(long));
	long v = 42;
	g_array_append_val(a, v);
	long_array_invert(a, 0);
	long_array_invert(a, 0);
	ASSERT_INT_EQ(g_array_index(a, long, 0), 42);
	g_array_free(a, 1);
	return 1;
}

static int test_long_array_invert_zero(void)
{
	GArray *a = g_array_new(0, 0, sizeof(long));
	long v = 0;
	g_array_append_val(a, v);
	long_array_invert(a, 0);
	ASSERT_INT_EQ(g_array_index(a, long, 0), -2);
	g_array_free(a, 1);
	return 1;
}


/* ===================================================================
 * Tests for fastcmp
 * =================================================================== */

static int test_fastcmp_equal(void)
{
	FILE *s = make_tmpfile("hello world");
	FILE *t = make_tmpfile("hello world");
	ASSERT_INT_EQ(fastcmp(s, t, 0, 0, 11), 0);
	fclose(s);
	fclose(t);
	return 1;
}

static int test_fastcmp_different(void)
{
	FILE *s = make_tmpfile("hello world");
	FILE *t = make_tmpfile("hello earth");
	ASSERT_INT_EQ(fastcmp(s, t, 0, 0, 11), 1);
	fclose(s);
	fclose(t);
	return 1;
}

static int test_fastcmp_short_read(void)
{
	FILE *s = make_tmpfile("hi");
	FILE *t = make_tmpfile("hello world");
	/* asking to compare 11 bytes when s only has 2 */
	ASSERT_INT_EQ(fastcmp(s, t, 0, 0, 11), -1);
	fclose(s);
	fclose(t);
	return 1;
}

static int test_fastcmp_offset(void)
{
	FILE *s = make_tmpfile("XXXXXhello");
	FILE *t = make_tmpfile("YYhello");
	ASSERT_INT_EQ(fastcmp(s, t, 5, 2, 5), 0);
	fclose(s);
	fclose(t);
	return 1;
}

static int test_fastcmp_restores_position(void)
{
	FILE *s = make_tmpfile("hello world");
	FILE *t = make_tmpfile("hello world");
	fseek(s, 3, SEEK_SET);
	fseek(t, 7, SEEK_SET);
	fastcmp(s, t, 0, 0, 5);
	ASSERT_INT_EQ(ftell(s), 3);
	ASSERT_INT_EQ(ftell(t), 7);
	fclose(s);
	fclose(t);
	return 1;
}


/* ===================================================================
 * Tests for frob_ava
 * =================================================================== */

static int test_frob_ava_check_found(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "test");
	ASSERT_INT_EQ(frob_ava(e, FROB_RDN_CHECK, "cn", "test", 4), 0);
	entry_free(e);
	return 1;
}

static int test_frob_ava_check_not_found(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "test");
	ASSERT_INT_EQ(frob_ava(e, FROB_RDN_CHECK, "cn", "other", 5), -1);
	entry_free(e);
	return 1;
}

static int test_frob_ava_check_no_attr(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	ASSERT_INT_EQ(frob_ava(e, FROB_RDN_CHECK, "cn", "test", 4), -1);
	entry_free(e);
	return 1;
}

static int test_frob_ava_check_none_absent(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "test");
	/* CHECK_NONE: value is NOT absent -> returns -1 */
	ASSERT_INT_EQ(frob_ava(e, FROB_RDN_CHECK_NONE, "cn", "test", 4), -1);
	entry_free(e);
	return 1;
}

static int test_frob_ava_check_none_present(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "test");
	/* CHECK_NONE: value IS absent (different value) -> returns 0 */
	ASSERT_INT_EQ(frob_ava(e, FROB_RDN_CHECK_NONE, "cn", "other", 5), 0);
	entry_free(e);
	return 1;
}

static int test_frob_ava_add(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	frob_ava(e, FROB_RDN_ADD, "cn", "test", 4);
	tattribute *a = entry_find_attribute(e, "cn", 0);
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attribute_find_value(a, "test", 4), 0);
	entry_free(e);
	return 1;
}

static int test_frob_ava_add_idempotent(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "test");
	frob_ava(e, FROB_RDN_ADD, "cn", "test", 4);
	tattribute *a = entry_find_attribute(e, "cn", 0);
	ASSERT_INT_EQ(attribute_values(a)->len, 1);
	entry_free(e);
	return 1;
}

static int test_frob_ava_remove(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "test");
	frob_ava(e, FROB_RDN_REMOVE, "cn", "test", 4);
	tattribute *a = entry_find_attribute(e, "cn", 0);
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attribute_values(a)->len, 0);
	entry_free(e);
	return 1;
}


/* ===================================================================
 * Tests for frob_rdn
 * =================================================================== */

static int test_frob_rdn_check_match(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "test");
	ASSERT_INT_EQ(frob_rdn(e, "cn=test,dc=example,dc=com",
				FROB_RDN_CHECK), 0);
	entry_free(e);
	return 1;
}

static int test_frob_rdn_check_nomatch(void)
{
	tentry *e = make_entry("cn=test,dc=example,dc=com");
	add_attr_value(e, "cn", "other");
	ASSERT_INT_EQ(frob_rdn(e, "cn=test,dc=example,dc=com",
				FROB_RDN_CHECK), -1);
	entry_free(e);
	return 1;
}

static int test_frob_rdn_add(void)
{
	tentry *e = make_entry("cn=new,dc=example,dc=com");
	frob_rdn(e, "cn=new,dc=example,dc=com", FROB_RDN_ADD);
	tattribute *a = entry_find_attribute(e, "cn", 0);
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attribute_find_value(a, "new", 3), 0);
	entry_free(e);
	return 1;
}


/* ===================================================================
 * Tests for validate_rename
 * =================================================================== */

static int test_validate_rename_deleteoldrdn_1(void)
{
	/* old RDN value not in new entry -> deleteoldrdn=1 */
	tentry *clean = make_entry("cn=old,dc=example,dc=com");
	add_attr_value(clean, "cn", "old");

	tentry *data = make_entry("cn=new,dc=example,dc=com");
	add_attr_value(data, "cn", "new");

	int deleteoldrdn = -1;
	ASSERT_INT_EQ(validate_rename(clean, data, &deleteoldrdn), 0);
	ASSERT_INT_EQ(deleteoldrdn, 1);

	entry_free(clean);
	entry_free(data);
	return 1;
}

static int test_validate_rename_deleteoldrdn_0(void)
{
	/* old RDN value still in new entry -> deleteoldrdn=0 */
	tentry *clean = make_entry("cn=old,dc=example,dc=com");
	add_attr_value(clean, "cn", "old");

	tentry *data = make_entry("cn=new,dc=example,dc=com");
	add_attr_value(data, "cn", "new");
	add_attr_value(data, "cn", "old");

	int deleteoldrdn = -1;
	ASSERT_INT_EQ(validate_rename(clean, data, &deleteoldrdn), 0);
	ASSERT_INT_EQ(deleteoldrdn, 0);

	entry_free(clean);
	entry_free(data);
	return 1;
}

static int test_validate_rename_empty_clean_dn(void)
{
	tentry *clean = make_entry("");
	tentry *data = make_entry("cn=new,dc=example,dc=com");
	add_attr_value(data, "cn", "new");

	int deleteoldrdn;
	ASSERT_INT_EQ(validate_rename(clean, data, &deleteoldrdn), -1);

	entry_free(clean);
	entry_free(data);
	return 1;
}

static int test_validate_rename_empty_data_dn(void)
{
	tentry *clean = make_entry("cn=old,dc=example,dc=com");
	add_attr_value(clean, "cn", "old");
	tentry *data = make_entry("");

	int deleteoldrdn;
	ASSERT_INT_EQ(validate_rename(clean, data, &deleteoldrdn), -1);

	entry_free(clean);
	entry_free(data);
	return 1;
}

static int test_validate_rename_old_rdn_missing(void)
{
	/* clean entry missing its own RDN value -> error */
	tentry *clean = make_entry("cn=old,dc=example,dc=com");
	/* no cn attr */
	tentry *data = make_entry("cn=new,dc=example,dc=com");
	add_attr_value(data, "cn", "new");

	int deleteoldrdn;
	ASSERT_INT_EQ(validate_rename(clean, data, &deleteoldrdn), -1);

	entry_free(clean);
	entry_free(data);
	return 1;
}


/* ===================================================================
 * Tests for compare_streams
 * =================================================================== */

static int test_compare_streams_unchanged(void)
{
	const char *ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(ldif, &offsets);
	FILE *data = make_tmpfile(ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 0);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_unchanged_multi(void)
{
	const char *ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n"
		"\ndn: cn=bar,dc=example,dc=com\n"
		"ldapvi-key: 1\n"
		"cn: bar\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(ldif, &offsets);
	FILE *data = make_tmpfile(ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 0);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_modify_attr(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"sn: old\n"
		"\n";

	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"sn: new\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_CHANGE);
	ASSERT_STREQ(m.calls[0].dn, "cn=foo,dc=example,dc=com");
	ASSERT(m.calls[0].num_mods > 0);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_add_attr(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"mail: foo@example.com\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_CHANGE);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_remove_attr(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"sn: bar\n"
		"\n";

	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_CHANGE);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_delete_entry(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	/* data is empty - entry deleted */
	const char *data_ldif = "";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_DELETE);
	ASSERT_STREQ(m.calls[0].dn, "cn=foo,dc=example,dc=com");

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_delete_one_of_two(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n"
		"\ndn: cn=bar,dc=example,dc=com\n"
		"ldapvi-key: 1\n"
		"cn: bar\n"
		"\n";

	/* data keeps only entry 1 */
	const char *data_ldif =
		"\ndn: cn=bar,dc=example,dc=com\n"
		"ldapvi-key: 1\n"
		"cn: bar\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	/* should have exactly one delete for entry 0 */
	int found_delete = 0;
	for (int i = 0; i < m.num_calls; i++) {
		if (m.calls[i].type == CALL_DELETE) {
			ASSERT_STREQ(m.calls[i].dn,
				     "cn=foo,dc=example,dc=com");
			found_delete = 1;
		}
	}
	ASSERT(found_delete);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_add_new_entry(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n"
		"\ndn: cn=new,dc=example,dc=com\n"
		"ldapvi-key: add\n"
		"cn: new\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	/* find the add call */
	int found_add = 0;
	for (int i = 0; i < m.num_calls; i++) {
		if (m.calls[i].type == CALL_ADD) {
			ASSERT_STREQ(m.calls[i].dn,
				     "cn=new,dc=example,dc=com");
			found_add = 1;
		}
	}
	ASSERT(found_add);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_rename(void)
{
	const char *clean_ldif =
		"\ndn: cn=old,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: old\n"
		"\n";

	const char *data_ldif =
		"\ndn: cn=new,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: new\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, 0);
	/* should have a rename call */
	int found_rename = 0;
	for (int i = 0; i < m.num_calls; i++) {
		if (m.calls[i].type == CALL_RENAME) {
			ASSERT_STREQ(m.calls[i].dn,
				     "cn=old,dc=example,dc=com");
			found_rename = 1;
		}
	}
	ASSERT(found_rename);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_offsets_restored(void)
{
	const char *ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(ldif, &offsets);
	FILE *data = make_tmpfile(ldif);

	long orig = g_array_index(offsets, long, 0);
	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	compare_streams(&ldif_parser, &mock_handler, &m,
			offsets, clean, data, &errpos, &synpos);
	/* offsets should be restored after success */
	ASSERT_INT_EQ(g_array_index(offsets, long, 0), orig);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}


/* ===================================================================
 * Tests for process_immediate
 * =================================================================== */

static int test_process_immediate_add(void)
{
	const char *ldif =
		"\ndn: cn=new,dc=example,dc=com\n"
		"ldapvi-key: add\n"
		"cn: new\n"
		"\n";

	FILE *data = make_tmpfile(ldif);
	char *key = NULL;
	long datapos;
	ldif_peek_entry(data, -1, &key, &datapos);

	mock_state m;
	mock_init(&m);

	int rc = process_immediate(&ldif_parser, &mock_handler, &m,
				   data, datapos, "add");
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_ADD);
	ASSERT_STREQ(m.calls[0].dn, "cn=new,dc=example,dc=com");

	free(key);
	mock_free(&m);
	fclose(data);
	return 1;
}

static int test_process_immediate_delete(void)
{
	const char *ldif =
		"\ndn: cn=old,dc=example,dc=com\n"
		"changetype: delete\n"
		"\n";

	FILE *data = make_tmpfile(ldif);
	/* skip past the blank lines at start */
	char *key = NULL;
	long datapos;
	/* manually seek to find DN position */
	ldif_peek_entry(data, -1, &key, &datapos);

	mock_state m;
	mock_init(&m);

	int rc = process_immediate(&ldif_parser, &mock_handler, &m,
				   data, datapos, "delete");
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_DELETE);
	ASSERT_STREQ(m.calls[0].dn, "cn=old,dc=example,dc=com");

	free(key);
	mock_free(&m);
	fclose(data);
	return 1;
}

static int test_process_immediate_modify(void)
{
	const char *ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"replace: sn\n"
		"sn: newval\n"
		"-\n"
		"\n";

	FILE *data = make_tmpfile(ldif);
	char *key = NULL;
	long datapos;
	ldif_peek_entry(data, -1, &key, &datapos);

	mock_state m;
	mock_init(&m);

	int rc = process_immediate(&ldif_parser, &mock_handler, &m,
				   data, datapos, "modify");
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_CHANGE);

	free(key);
	mock_free(&m);
	fclose(data);
	return 1;
}

static int test_process_immediate_invalid_key(void)
{
	const char *ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: bogus\n"
		"cn: foo\n"
		"\n";

	FILE *data = make_tmpfile(ldif);
	char *key = NULL;
	long datapos;
	ldif_peek_entry(data, -1, &key, &datapos);

	mock_state m;
	mock_init(&m);

	int rc = process_immediate(&ldif_parser, &mock_handler, &m,
				   data, datapos, "bogus");
	ASSERT_INT_EQ(rc, -1);
	ASSERT_INT_EQ(m.num_calls, 0);

	free(key);
	mock_free(&m);
	fclose(data);
	return 1;
}

static int test_process_immediate_replace(void)
{
	const char *ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: replace\n"
		"cn: foo\n"
		"sn: bar\n"
		"\n";

	FILE *data = make_tmpfile(ldif);
	char *key = NULL;
	long datapos;
	ldif_peek_entry(data, -1, &key, &datapos);

	mock_state m;
	mock_init(&m);

	int rc = process_immediate(&ldif_parser, &mock_handler, &m,
				   data, datapos, "replace");
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_CHANGE);

	free(key);
	mock_free(&m);
	fclose(data);
	return 1;
}

static int test_process_immediate_rename(void)
{
	const char *ldif =
		"\ndn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 1\n"
		"\n";

	FILE *data = make_tmpfile(ldif);
	char *key = NULL;
	long datapos;
	ldif_peek_entry(data, -1, &key, &datapos);

	mock_state m;
	mock_init(&m);

	int rc = process_immediate(&ldif_parser, &mock_handler, &m,
				   data, datapos, "rename");
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(m.num_calls, 1);
	ASSERT_INT_EQ(m.calls[0].type, CALL_RENAME0);

	free(key);
	mock_free(&m);
	fclose(data);
	return 1;
}


/* ===================================================================
 * Tests for handler failure propagation
 * =================================================================== */

static int test_compare_streams_handler_add_fails(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n"
		"\ndn: cn=new,dc=example,dc=com\n"
		"ldapvi-key: add\n"
		"cn: new\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	m.fail_on_call = 0; /* fail on first handler call */
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, -2);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_handler_change_fails(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"sn: old\n"
		"\n";

	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"sn: new\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	m.fail_on_call = 0; /* fail on first handler call */
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, -2);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}


/* ===================================================================
 * Tests for duplicate key and invalid key
 * =================================================================== */

static int test_compare_streams_invalid_numeric_key(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	/* data references key 5, which doesn't exist */
	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 5\n"
		"cn: foo\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, -1);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}

static int test_compare_streams_duplicate_key(void)
{
	const char *clean_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	/* data uses key 0 twice */
	const char *data_ldif =
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n"
		"\ndn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 0\n"
		"cn: foo\n"
		"\n";

	GArray *offsets;
	FILE *clean = make_clean_file(clean_ldif, &offsets);
	FILE *data = make_tmpfile(data_ldif);

	mock_state m;
	mock_init(&m);
	long errpos = 0, synpos = 0;

	int rc = compare_streams(&ldif_parser, &mock_handler, &m,
				 offsets, clean, data, &errpos, &synpos);
	ASSERT_INT_EQ(rc, -1);

	mock_free(&m);
	fclose(clean);
	fclose(data);
	g_array_free(offsets, 1);
	return 1;
}


/* ===================================================================
 * run_diff_tests
 * =================================================================== */

void run_diff_tests(void)
{
	printf("=== diff.c test suite ===\n\n");

	printf("long_array_invert:\n");
	TEST(long_array_invert_basic);
	TEST(long_array_invert_double);
	TEST(long_array_invert_zero);

	printf("\nfastcmp:\n");
	TEST(fastcmp_equal);
	TEST(fastcmp_different);
	TEST(fastcmp_short_read);
	TEST(fastcmp_offset);
	TEST(fastcmp_restores_position);

	printf("\nfrob_ava:\n");
	TEST(frob_ava_check_found);
	TEST(frob_ava_check_not_found);
	TEST(frob_ava_check_no_attr);
	TEST(frob_ava_check_none_absent);
	TEST(frob_ava_check_none_present);
	TEST(frob_ava_add);
	TEST(frob_ava_add_idempotent);
	TEST(frob_ava_remove);

	printf("\nfrob_rdn:\n");
	TEST(frob_rdn_check_match);
	TEST(frob_rdn_check_nomatch);
	TEST(frob_rdn_add);

	printf("\nvalidate_rename:\n");
	TEST(validate_rename_deleteoldrdn_1);
	TEST(validate_rename_deleteoldrdn_0);
	TEST(validate_rename_empty_clean_dn);
	TEST(validate_rename_empty_data_dn);
	TEST(validate_rename_old_rdn_missing);

	printf("\ncompare_streams:\n");
	TEST(compare_streams_unchanged);
	TEST(compare_streams_unchanged_multi);
	TEST(compare_streams_modify_attr);
	TEST(compare_streams_add_attr);
	TEST(compare_streams_remove_attr);
	TEST(compare_streams_delete_entry);
	TEST(compare_streams_delete_one_of_two);
	TEST(compare_streams_add_new_entry);
	TEST(compare_streams_rename);
	TEST(compare_streams_offsets_restored);

	printf("\nprocess_immediate:\n");
	TEST(process_immediate_add);
	TEST(process_immediate_delete);
	TEST(process_immediate_modify);
	TEST(process_immediate_invalid_key);
	TEST(process_immediate_replace);
	TEST(process_immediate_rename);

	printf("\nhandler failure:\n");
	TEST(compare_streams_handler_add_fails);
	TEST(compare_streams_handler_change_fails);

	printf("\nerror conditions:\n");
	TEST(compare_streams_invalid_numeric_key);
	TEST(compare_streams_duplicate_key);
}
