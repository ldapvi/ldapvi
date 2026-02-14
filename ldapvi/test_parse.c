/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for parse.c - the ldapvi native format parser.
 */
#define _GNU_SOURCE
#include "common.h"
#include "test_harness.h"


/*
 * Helpers
 */
static FILE *
make_input(const char *data)
{
	return fmemopen((void *) data, strlen(data), "r");
}

static tattribute *
find_attr(tentry *entry, const char *name)
{
	GPtrArray *attrs = entry_attributes(entry);
	unsigned int i;
	for (i = 0; i < attrs->len; i++) {
		tattribute *a = g_ptr_array_index(attrs, i);
		if (!strcmp(attribute_ad(a), name))
			return a;
	}
	return 0;
}

static const char *
attr_val_data(tattribute *a, int idx)
{
	GArray *val = g_ptr_array_index(attribute_values(a), idx);
	return val->data;
}

static int
attr_val_len(tattribute *a, int idx)
{
	GArray *val = g_ptr_array_index(attribute_values(a), idx);
	return val->len;
}

static int
attr_val_count(tattribute *a)
{
	return attribute_values(a)->len;
}

static int
entry_attr_count(tentry *entry)
{
	return entry_attributes(entry)->len;
}


/*
 * Group 1: EOF and empty input
 */
static int test_eof_returns_null_key(void)
{
	FILE *f = make_input("");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}

static int test_blank_lines_then_eof(void)
{
	FILE *f = make_input("\n\n\n");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}

static int test_peek_eof_returns_null_key(void)
{
	FILE *f = make_input("");
	char *key = 0;
	int rc = peek_entry(f, -1, &key, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}

static int test_skip_eof_returns_null_key(void)
{
	FILE *f = make_input("");
	char *key = 0;
	int rc = skip_entry(f, -1, &key);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}


/*
 * Group 2: Simple entry read
 */
static int test_read_simple_entry(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"sn bar\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = read_entry(f, -1, &key, &entry, 0);
	tattribute *a;
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_STREQ(entry_dn(entry), "cn=foo,dc=example,dc=com");
	ASSERT_INT_EQ(entry_attr_count(entry), 2);

	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_count(a), 1);
	ASSERT_INT_EQ(attr_val_len(a, 0), 3);
	ASSERT(memcmp(attr_val_data(a, 0), "foo", 3) == 0);

	a = find_attr(entry, "sn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_count(a), 1);
	ASSERT_INT_EQ(attr_val_len(a, 0), 3);
	ASSERT(memcmp(attr_val_data(a, 0), "bar", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_read_entry_multi_valued(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"cn bar\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(entry_attr_count(entry), 1);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_count(a), 2);
	ASSERT(memcmp(attr_val_data(a, 0), "foo", 3) == 0);
	ASSERT(memcmp(attr_val_data(a, 1), "bar", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_read_entry_empty_value(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn \n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_count(a), 1);
	ASSERT_INT_EQ(attr_val_len(a, 0), 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_read_entry_at_offset(void)
{
	FILE *f = make_input(
		"add cn=skip,dc=com\n"
		"cn skip\n"
		"\n"
		"add cn=target,dc=example,dc=com\n"
		"cn target\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	/* read first entry to find offset of second */
	int rc = read_entry(f, -1, &key, &entry, 0);
	long pos;
	ASSERT_INT_EQ(rc, 0);
	free(key); key = 0;
	entry_free(entry); entry = 0;
	pos = ftell(f);

	/* re-read from that offset */
	rc = read_entry(f, pos, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(entry), "cn=target,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_read_entry_sequential(void)
{
	FILE *f = make_input(
		"add cn=first,dc=example,dc=com\n"
		"cn first\n"
		"\n"
		"add cn=second,dc=example,dc=com\n"
		"cn second\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;

	int rc = read_entry(f, -1, &key, &entry, 0);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(entry), "cn=first,dc=example,dc=com");
	free(key); key = 0;
	entry_free(entry); entry = 0;

	rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(entry), "cn=second,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_entry_eof_terminates_record(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT(memcmp(attr_val_data(a, 0), "foo", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 3: Version line
 */
static int test_version_line_skipped(void)
{
	FILE *f = make_input(
		"version ldapvi\n"
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_STREQ(entry_dn(entry), "cn=foo,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_invalid_version(void)
{
	FILE *f = make_input(
		"version 1\n"
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 4: Comments
 */
static int test_comment_lines_skipped(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"# this is a comment\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(entry_attr_count(entry), 1);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_comment_with_folding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"# comment line\n"
		" continued\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(entry_attr_count(entry), 1);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 5: Backslash-escaped values
 */
static int test_backslash_plain_value(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo bar\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 7);
	ASSERT(memcmp(attr_val_data(a, 0), "foo bar", 7) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_backslash_embedded_newline(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"description one\\\ntwo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "description");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 7);
	ASSERT(memcmp(attr_val_data(a, 0), "one\ntwo", 7) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_backslash_embedded_backslash(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\\\\bar\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 7);
	ASSERT(memcmp(attr_val_data(a, 0), "foo\\bar", 7) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_semicolon_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn:; foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 3);
	ASSERT(memcmp(attr_val_data(a, 0), "foo", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 6: Base64 encoding
 */
static int test_base64_value(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn:: Zm9v\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 3);
	ASSERT(memcmp(attr_val_data(a, 0), "foo", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_base64_invalid(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn:: !!!!\n"
		"\n");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 7: File URL encoding
 */
static int test_file_url_read(void)
{
	char path[] = "/tmp/ldapvi_test_XXXXXX";
	int fd = mkstemp(path);
	char buf[256];
	FILE *f;
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc;

	write(fd, "hello world", 11);
	close(fd);

	snprintf(buf, sizeof(buf),
		 "add cn=foo,dc=example,dc=com\n"
		 "cn:< file://%s\n"
		 "\n", path);

	f = make_input(buf);
	rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	unlink(path);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 11);
	ASSERT(memcmp(attr_val_data(a, 0), "hello world", 11) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_file_url_unknown_scheme(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn:< http://example.com/data\n"
		"\n");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 8: Numeric binary encoding
 */
static int test_numeric_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn:3 foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 3);
	ASSERT(memcmp(attr_val_data(a, 0), "foo", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_numeric_encoding_zero(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn:0 \n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 0);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 9: Password hash encodings (stubbed)
 */
static int test_sha_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"userPassword:sha secret\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "userPassword");
	ASSERT_NOT_NULL(a);
	ASSERT(attr_val_len(a, 0) >= 5);
	ASSERT(memcmp(attr_val_data(a, 0), "{SHA}", 5) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_ssha_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"userPassword:ssha secret\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "userPassword");
	ASSERT_NOT_NULL(a);
	ASSERT(attr_val_len(a, 0) >= 6);
	ASSERT(memcmp(attr_val_data(a, 0), "{SSHA}", 6) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_md5_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"userPassword:md5 secret\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "userPassword");
	ASSERT_NOT_NULL(a);
	ASSERT(attr_val_len(a, 0) >= 5);
	ASSERT(memcmp(attr_val_data(a, 0), "{MD5}", 5) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_smd5_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"userPassword:smd5 secret\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "userPassword");
	ASSERT_NOT_NULL(a);
	ASSERT(attr_val_len(a, 0) >= 6);
	ASSERT(memcmp(attr_val_data(a, 0), "{SMD5}", 6) == 0);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 10: Crypt encodings (non-deterministic, verify prefix only)
 */
static int test_crypt_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"userPassword:crypt secret\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	a = find_attr(entry, "userPassword");
	ASSERT_NOT_NULL(a);
	ASSERT(attr_val_len(a, 0) >= 7);
	ASSERT(memcmp(attr_val_data(a, 0), "{CRYPT}", 7) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

/* cryptmd5 test omitted: crypt() with $1$ salt is not universally available */


/*
 * Group 11: Key types
 */
static int test_numeric_key(void)
{
	FILE *f = make_input(
		"42 cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "42");
	ASSERT_STREQ(entry_dn(entry), "cn=foo,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_arbitrary_key(void)
{
	FILE *f = make_input(
		"mykey cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = read_entry(f, -1, &key, &entry, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "mykey");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_invalid_dn(void)
{
	FILE *f = make_input(
		"add notadn\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 12: Delete record
 */
static int test_read_delete_basic(void)
{
	FILE *f = make_input(
		"delete cn=foo,dc=example,dc=com\n"
		"\n");
	char *dn = 0;
	int rc = read_delete(f, -1, &dn);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn, "cn=foo,dc=example,dc=com");

	free(dn);
	return 1;
}

static int test_read_delete_garbage_after(void)
{
	FILE *f = make_input(
		"delete cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *dn = 0;
	int rc = read_delete(f, -1, &dn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_skip_delete(void)
{
	FILE *f = make_input(
		"delete cn=foo,dc=example,dc=com\n"
		"\n");
	char *key = 0;
	int rc = skip_entry(f, -1, &key);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "delete");

	free(key);
	return 1;
}


/*
 * Group 13: Modify record
 */
static int test_read_modify_add_operation(void)
{
	FILE *f = make_input(
		"modify cn=foo,dc=example,dc=com\n"
		"add mail\n"
		" foo@example.com\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = read_modify(f, -1, &dn, &mods);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn, "cn=foo,dc=example,dc=com");
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_INT_EQ(mods[0]->mod_op, LDAP_MOD_ADD | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[0]->mod_type, "mail");
	ASSERT_NOT_NULL(mods[0]->mod_bvalues[0]);
	ASSERT_INT_EQ((int) mods[0]->mod_bvalues[0]->bv_len, 15);
	ASSERT(memcmp(mods[0]->mod_bvalues[0]->bv_val,
		      "foo@example.com", 15) == 0);
	ASSERT_NULL(mods[0]->mod_bvalues[1]);
	ASSERT_NULL(mods[1]);

	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_delete_operation(void)
{
	FILE *f = make_input(
		"modify cn=foo,dc=example,dc=com\n"
		"delete phone\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = read_modify(f, -1, &dn, &mods);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_INT_EQ(mods[0]->mod_op, LDAP_MOD_DELETE | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[0]->mod_type, "phone");
	ASSERT_NULL(mods[0]->mod_bvalues[0]);
	ASSERT_NULL(mods[1]);

	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_replace_operation(void)
{
	FILE *f = make_input(
		"modify cn=foo,dc=example,dc=com\n"
		"replace sn\n"
		" Bar\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = read_modify(f, -1, &dn, &mods);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_INT_EQ(mods[0]->mod_op, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[0]->mod_type, "sn");
	ASSERT_NOT_NULL(mods[0]->mod_bvalues[0]);
	ASSERT_INT_EQ((int) mods[0]->mod_bvalues[0]->bv_len, 3);
	ASSERT(memcmp(mods[0]->mod_bvalues[0]->bv_val, "Bar", 3) == 0);
	ASSERT_NULL(mods[0]->mod_bvalues[1]);
	ASSERT_NULL(mods[1]);

	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_multiple_operations(void)
{
	FILE *f = make_input(
		"modify cn=foo,dc=example,dc=com\n"
		"add mail\n"
		" foo@example.com\n"
		"delete phone\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = read_modify(f, -1, &dn, &mods);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_INT_EQ(mods[0]->mod_op, LDAP_MOD_ADD | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[0]->mod_type, "mail");
	ASSERT_NOT_NULL(mods[1]);
	ASSERT_INT_EQ(mods[1]->mod_op, LDAP_MOD_DELETE | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[1]->mod_type, "phone");
	ASSERT_NULL(mods[2]);

	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_multiple_values(void)
{
	FILE *f = make_input(
		"modify cn=foo,dc=example,dc=com\n"
		"add mail\n"
		" foo@example.com\n"
		" bar@example.com\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = read_modify(f, -1, &dn, &mods);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_NOT_NULL(mods[0]->mod_bvalues[0]);
	ASSERT_NOT_NULL(mods[0]->mod_bvalues[1]);
	ASSERT(memcmp(mods[0]->mod_bvalues[0]->bv_val,
		      "foo@example.com", 15) == 0);
	ASSERT(memcmp(mods[0]->mod_bvalues[1]->bv_val,
		      "bar@example.com", 15) == 0);
	ASSERT_NULL(mods[0]->mod_bvalues[2]);
	ASSERT_NULL(mods[1]);

	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_invalid_marker(void)
{
	FILE *f = make_input(
		"modify cn=foo,dc=example,dc=com\n"
		"bogus mail\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 14: Rename record
 */
static int test_read_rename_add(void)
{
	FILE *f = make_input(
		"rename cn=old,dc=example,dc=com\n"
		"add cn=new,dc=example,dc=com\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn1, "cn=old,dc=example,dc=com");
	ASSERT_STREQ(dn2, "cn=new,dc=example,dc=com");
	ASSERT_INT_EQ(deleteoldrdn, 0);

	free(dn1);
	free(dn2);
	return 1;
}

static int test_read_rename_replace(void)
{
	FILE *f = make_input(
		"rename cn=old,dc=example,dc=com\n"
		"replace cn=new,dc=example,dc=com\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn1, "cn=old,dc=example,dc=com");
	ASSERT_STREQ(dn2, "cn=new,dc=example,dc=com");
	ASSERT_INT_EQ(deleteoldrdn, 1);

	free(dn1);
	free(dn2);
	return 1;
}

static int test_read_rename_missing_dn(void)
{
	FILE *f = make_input(
		"rename cn=old,dc=example,dc=com\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_read_rename_invalid_keyword(void)
{
	FILE *f = make_input(
		"rename cn=old,dc=example,dc=com\n"
		"move cn=new,dc=example,dc=com\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_read_rename_garbage_after(void)
{
	FILE *f = make_input(
		"rename cn=old,dc=example,dc=com\n"
		"add cn=new,dc=example,dc=com\n"
		"extra stuff\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 15: skip_entry
 */
static int test_skip_add_entry(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"sn bar\n"
		"\n");
	char *key = 0;
	int rc = skip_entry(f, -1, &key);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");

	free(key);
	return 1;
}

static int test_skip_modify_entry(void)
{
	FILE *f = make_input(
		"modify cn=foo,dc=example,dc=com\n"
		"add mail\n"
		" foo@example.com\n"
		"\n");
	char *key = 0;
	int rc = skip_entry(f, -1, &key);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "modify");

	free(key);
	return 1;
}

static int test_skip_rename_entry(void)
{
	FILE *f = make_input(
		"rename cn=old,dc=example,dc=com\n"
		"add cn=new,dc=example,dc=com\n"
		"\n");
	char *key = 0;
	int rc = skip_entry(f, -1, &key);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "rename");

	free(key);
	return 1;
}

static int test_skip_delete_entry(void)
{
	FILE *f = make_input(
		"delete cn=foo,dc=example,dc=com\n"
		"\n");
	char *key = 0;
	int rc = skip_entry(f, -1, &key);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "delete");

	free(key);
	return 1;
}


/*
 * Group 16: peek_entry
 */
static int test_peek_basic(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	int rc = peek_entry(f, -1, &key, 0);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");

	free(key);
	return 1;
}

static int test_peek_does_not_consume_body(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;

	int rc = peek_entry(f, 0, &key, 0);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	free(key); key = 0;

	/* re-read from start should still work */
	rc = read_entry(f, 0, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_INT_EQ(entry_attr_count(entry), 1);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 17: read_profile
 */
static int test_read_profile_basic(void)
{
	FILE *f = make_input(
		"profile myprofile\n"
		"host ldap.example.com\n"
		"base dc=example,dc=com\n"
		"\n");
	tentry *entry = 0;
	tattribute *a;
	int rc = read_profile(f, &entry);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(entry);
	ASSERT_STREQ(entry_dn(entry), "myprofile");
	ASSERT_INT_EQ(entry_attr_count(entry), 2);

	a = find_attr(entry, "host");
	ASSERT_NOT_NULL(a);
	ASSERT(memcmp(attr_val_data(a, 0), "ldap.example.com", 16) == 0);

	a = find_attr(entry, "base");
	ASSERT_NOT_NULL(a);
	ASSERT(memcmp(attr_val_data(a, 0), "dc=example,dc=com", 18) == 0);

	entry_free(entry);
	return 1;
}

static int test_read_profile_eof(void)
{
	FILE *f = make_input("");
	tentry *entry = (tentry *) 1; /* sentinel */
	int rc = read_profile(f, &entry);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	/* entry should not be set (name is NULL, so we skip entry_new) */
	return 1;
}

static int test_read_profile_invalid_header(void)
{
	FILE *f = make_input(
		"notprofile myprofile\n"
		"host ldap.example.com\n"
		"\n");
	tentry *entry = 0;
	int rc = read_profile(f, &entry);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 18: Error conditions
 */
static int test_unknown_encoding(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn:bogus val\n"
		"\n");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_null_byte_in_attr_name(void)
{
	const char data[] =
		"add cn=foo,dc=example,dc=com\n"
		"c\0n foo\n"
		"\n";
	FILE *f = fmemopen((void *) data, sizeof(data) - 1, "r");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_unexpected_eof_in_attr_name(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_unexpected_eol_in_attr_name(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn\n"
		"\n");
	char *key = 0;
	int rc = read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 19: pos output
 */
static int test_pos_set_correctly(void)
{
	FILE *f = make_input(
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n");
	char *key = 0;
	long pos = -1;
	int rc = read_entry(f, -1, &key, 0, &pos);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ((int) pos, 0);

	free(key);
	return 1;
}

static int test_pos_with_version(void)
{
	const char *input =
		"version ldapvi\n"
		"add cn=foo,dc=example,dc=com\n"
		"cn foo\n"
		"\n";
	FILE *f = make_input(input);
	char *key = 0;
	long pos = -1;
	int rc = read_entry(f, -1, &key, 0, &pos);
	fclose(f);

	ASSERT_INT_EQ(rc, 0);
	/* pos should point past the version line */
	ASSERT_INT_EQ((int) pos, 15);

	free(key);
	return 1;
}


/*
 * run_parse_tests
 */
void run_parse_tests(void)
{
	printf("=== parse.c test suite ===\n\n");

	printf("Group 1: EOF and empty input\n");
	TEST(eof_returns_null_key);
	TEST(blank_lines_then_eof);
	TEST(peek_eof_returns_null_key);
	TEST(skip_eof_returns_null_key);

	printf("\nGroup 2: Simple entry read\n");
	TEST(read_simple_entry);
	TEST(read_entry_multi_valued);
	TEST(read_entry_empty_value);
	TEST(read_entry_at_offset);
	TEST(read_entry_sequential);
	TEST(entry_eof_terminates_record);

	printf("\nGroup 3: Version line\n");
	TEST(version_line_skipped);
	TEST(invalid_version);

	printf("\nGroup 4: Comments\n");
	TEST(comment_lines_skipped);
	TEST(comment_with_folding);

	printf("\nGroup 5: Backslash-escaped values\n");
	TEST(backslash_plain_value);
	TEST(backslash_embedded_newline);
	TEST(backslash_embedded_backslash);
	TEST(semicolon_encoding);

	printf("\nGroup 6: Base64 encoding\n");
	TEST(base64_value);
	TEST(base64_invalid);

	printf("\nGroup 7: File URL encoding\n");
	TEST(file_url_read);
	TEST(file_url_unknown_scheme);

	printf("\nGroup 8: Numeric binary encoding\n");
	TEST(numeric_encoding);
	TEST(numeric_encoding_zero);

	printf("\nGroup 9: Password hash encodings\n");
	TEST(sha_encoding);
	TEST(ssha_encoding);
	TEST(md5_encoding);
	TEST(smd5_encoding);

	printf("\nGroup 10: Crypt encodings\n");
	TEST(crypt_encoding);

	printf("\nGroup 11: Key types\n");
	TEST(numeric_key);
	TEST(arbitrary_key);
	TEST(invalid_dn);

	printf("\nGroup 12: Delete record\n");
	TEST(read_delete_basic);
	TEST(read_delete_garbage_after);
	TEST(skip_delete);

	printf("\nGroup 13: Modify record\n");
	TEST(read_modify_add_operation);
	TEST(read_modify_delete_operation);
	TEST(read_modify_replace_operation);
	TEST(read_modify_multiple_operations);
	TEST(read_modify_multiple_values);
	TEST(read_modify_invalid_marker);

	printf("\nGroup 14: Rename record\n");
	TEST(read_rename_add);
	TEST(read_rename_replace);
	TEST(read_rename_missing_dn);
	TEST(read_rename_invalid_keyword);
	TEST(read_rename_garbage_after);

	printf("\nGroup 15: skip_entry\n");
	TEST(skip_add_entry);
	TEST(skip_modify_entry);
	TEST(skip_rename_entry);
	TEST(skip_delete_entry);

	printf("\nGroup 16: peek_entry\n");
	TEST(peek_basic);
	TEST(peek_does_not_consume_body);

	printf("\nGroup 17: read_profile\n");
	TEST(read_profile_basic);
	TEST(read_profile_eof);
	TEST(read_profile_invalid_header);

	printf("\nGroup 18: Error conditions\n");
	TEST(unknown_encoding);
	TEST(null_byte_in_attr_name);
	TEST(unexpected_eof_in_attr_name);
	TEST(unexpected_eol_in_attr_name);

	printf("\nGroup 19: pos output\n");
	TEST(pos_set_correctly);
	TEST(pos_with_version);
}
