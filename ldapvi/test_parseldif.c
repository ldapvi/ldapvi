/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for parseldif.c - the extended LDIF parser.
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
	tentry *entry = 0;
	long pos = -1;
	int rc = ldif_read_entry(f, -1, &key, &entry, &pos);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}

static int test_blank_lines_then_eof(void)
{
	FILE *f = make_input("\n\n\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}

static int test_peek_eof_returns_null_key(void)
{
	FILE *f = make_input("");
	char *key = (char *) 1;
	int rc = ldif_peek_entry(f, -1, &key, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}

static int test_skip_eof_returns_null_key(void)
{
	FILE *f = make_input("");
	char *key = 0;
	int rc = ldif_skip_entry(f, -1, &key);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(key);
	return 1;
}


/*
 * Group 2: Simple attrval-record (implicit "add")
 */
static int test_read_simple_entry(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"sn: bar\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	long pos = -1;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, &pos);
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
	ASSERT(memcmp(attr_val_data(a, 0), "bar", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_read_entry_multi_valued_attribute(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"cn: bar\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);

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
		"dn: cn=foo,dc=example,dc=com\n"
		"description:\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);

	a = find_attr(entry, "description");
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
		"XXXXX"
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	long pos = -1;
	int rc = ldif_read_entry(f, 5, &key, &entry, &pos);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_INT_EQ((int) pos, 5);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_read_entry_sequential(void)
{
	FILE *f = make_input(
		"dn: cn=a,dc=example,dc=com\n"
		"cn: a\n"
		"\n"
		"dn: cn=b,dc=example,dc=com\n"
		"cn: b\n"
		"\n");
	char *key1 = 0, *key2 = 0;
	tentry *e1 = 0, *e2 = 0;
	int rc;

	rc = ldif_read_entry(f, -1, &key1, &e1, 0);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(e1), "cn=a,dc=example,dc=com");

	rc = ldif_read_entry(f, -1, &key2, &e2, 0);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(e2), "cn=b,dc=example,dc=com");

	fclose(f);
	free(key1); free(key2);
	entry_free(e1); entry_free(e2);
	return 1;
}

static int test_entry_eof_terminates_record(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_NOT_NULL(find_attr(entry, "cn"));

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 3: version line
 */
static int test_version_line_skipped(void)
{
	FILE *f = make_input(
		"version: 1\n"
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_STREQ(entry_dn(entry), "cn=foo,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_invalid_version_number(void)
{
	FILE *f = make_input(
		"version: 2\n"
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
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
		"# This is a comment\n"
		"dn: cn=foo,dc=example,dc=com\n"
		"# Another comment\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(find_attr(entry, "cn"));

	free(key);
	entry_free(entry);
	return 1;
}

static int test_comment_with_folding(void)
{
	FILE *f = make_input(
		"# This is a long\n"
		" comment that folds\n"
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 5: Line folding
 */
static int test_dn_line_folding(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=exam\n"
		" ple,dc=com\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(entry), "cn=foo,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_value_line_folding(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"description: hello\n"
		" world\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);

	a = find_attr(entry, "description");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 10);
	ASSERT(memcmp(attr_val_data(a, 0), "helloworld", 10) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_attribute_name_folding(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"descr\n"
		" iption: hello\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);

	a = find_attr(entry, "description");
	ASSERT_NOT_NULL(a);
	ASSERT(memcmp(attr_val_data(a, 0), "hello", 5) == 0);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 6: Base64 encoding
 */
static int test_base64_value(void)
{
	/* aGVsbG8= is base64 for "hello" */
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn:: aGVsbG8=\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);

	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT_INT_EQ(attr_val_len(a, 0), 5);
	ASSERT(memcmp(attr_val_data(a, 0), "hello", 5) == 0);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_base64_invalid(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn:: !!!invalid!!!\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_base64_dn(void)
{
	/* Y249Zm9vLGRjPWV4YW1wbGUsZGM9Y29t is base64 for
	 * "cn=foo,dc=example,dc=com" */
	FILE *f = make_input(
		"dn:: Y249Zm9vLGRjPWV4YW1wbGUsZGM9Y29t\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(entry), "cn=foo,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 7: ldapvi-key extension
 */
static int test_ldapvi_key_custom(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"ldapvi-key: 42\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "42");

	a = find_attr(entry, "cn");
	ASSERT_NOT_NULL(a);
	ASSERT(memcmp(attr_val_data(a, 0), "foo", 3) == 0);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 8: changetype: add
 */
static int test_changetype_add(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: add\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_NOT_NULL(find_attr(entry, "cn"));

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 9: changetype: delete
 */
static int test_read_delete_basic(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: delete\n"
		"\n");
	char *dn = 0;
	int rc = ldif_read_delete(f, -1, &dn);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn, "cn=foo,dc=example,dc=com");
	free(dn);
	return 1;
}

static int test_read_delete_garbage_after(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: delete\n"
		"cn: foo\n"
		"\n");
	char *dn = 0;
	int rc = ldif_read_delete(f, -1, &dn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_peek_delete(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: delete\n"
		"\n");
	char *key = 0;
	int rc = ldif_peek_entry(f, -1, &key, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "delete");
	free(key);
	return 1;
}

static int test_skip_delete(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: delete\n"
		"\n");
	char *key = 0;
	int rc = ldif_skip_entry(f, -1, &key);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "delete");
	free(key);
	return 1;
}


/*
 * Group 10: changetype: modify
 */
static int test_read_modify_add_operation(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"add: mail\n"
		"mail: foo@example.com\n"
		"-\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = ldif_read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn, "cn=foo,dc=example,dc=com");
	ASSERT_NOT_NULL(mods);
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
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"delete: mail\n"
		"-\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = ldif_read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_INT_EQ(mods[0]->mod_op, LDAP_MOD_DELETE | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[0]->mod_type, "mail");
	ASSERT_NULL(mods[0]->mod_bvalues[0]);
	ASSERT_NULL(mods[1]);
	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_replace_operation(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"replace: mail\n"
		"mail: new@example.com\n"
		"-\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = ldif_read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_INT_EQ(mods[0]->mod_op, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES);
	ASSERT(memcmp(mods[0]->mod_bvalues[0]->bv_val,
		      "new@example.com", 15) == 0);
	ASSERT_NULL(mods[1]);
	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_multiple_operations(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"add: mail\n"
		"mail: a@example.com\n"
		"-\n"
		"delete: phone\n"
		"-\n"
		"replace: sn\n"
		"sn: Smith\n"
		"-\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = ldif_read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_INT_EQ(mods[0]->mod_op, LDAP_MOD_ADD | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[0]->mod_type, "mail");
	ASSERT_NOT_NULL(mods[1]);
	ASSERT_INT_EQ(mods[1]->mod_op, LDAP_MOD_DELETE | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[1]->mod_type, "phone");
	ASSERT_NOT_NULL(mods[2]);
	ASSERT_INT_EQ(mods[2]->mod_op, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES);
	ASSERT_STREQ(mods[2]->mod_type, "sn");
	ASSERT_NULL(mods[3]);
	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_add_multiple_values(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"add: mail\n"
		"mail: a@example.com\n"
		"mail: b@example.com\n"
		"-\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = ldif_read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NOT_NULL(mods[0]->mod_bvalues[0]);
	ASSERT_NOT_NULL(mods[0]->mod_bvalues[1]);
	ASSERT_NULL(mods[0]->mod_bvalues[2]);
	ASSERT(memcmp(mods[0]->mod_bvalues[0]->bv_val,
		      "a@example.com", 13) == 0);
	ASSERT(memcmp(mods[0]->mod_bvalues[1]->bv_val,
		      "b@example.com", 13) == 0);
	free(dn);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_read_modify_attribute_name_mismatch(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"add: mail\n"
		"phone: 12345\n"
		"-\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = ldif_read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_read_modify_invalid_change_marker(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"frobnicate: mail\n"
		"-\n"
		"\n");
	char *dn = 0;
	LDAPMod **mods = 0;
	int rc = ldif_read_modify(f, -1, &dn, &mods);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_peek_modify(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"add: mail\n"
		"mail: foo@example.com\n"
		"-\n"
		"\n");
	char *key = 0;
	int rc = ldif_peek_entry(f, -1, &key, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "modify");
	free(key);
	return 1;
}


/*
 * Group 11: changetype: modrdn / moddn (rename)
 */
static int test_read_rename_modrdn(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 1\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn1, "cn=old,dc=example,dc=com");
	ASSERT_STREQ(dn2, "cn=new,dc=example,dc=com");
	ASSERT_INT_EQ(deleteoldrdn, 1);
	free(dn1); free(dn2);
	return 1;
}

static int test_read_rename_moddn(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: moddn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 0\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn2, "cn=new,dc=example,dc=com");
	ASSERT_INT_EQ(deleteoldrdn, 0);
	free(dn1); free(dn2);
	return 1;
}

static int test_read_rename_with_newsuperior(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 1\n"
		"newsuperior: dc=other,dc=com\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn2, "cn=new,dc=other,dc=com");
	free(dn1); free(dn2);
	return 1;
}

static int test_read_rename_with_empty_newsuperior(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 1\n"
		"newsuperior:\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn2, "cn=new");
	free(dn1); free(dn2);
	return 1;
}

static int test_read_rename_without_newsuperior(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=moved\n"
		"deleteoldrdn: 0\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn2, "cn=moved,dc=example,dc=com");
	free(dn1); free(dn2);
	return 1;
}

static int test_read_rename_invalid_deleteoldrdn(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 2\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_read_rename_missing_newrdn(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"deleteoldrdn: 1\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_read_rename_missing_deleteoldrdn(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_read_rename_garbage_after(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 1\n"
		"garbage: value\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_peek_rename_modrdn(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: modrdn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 1\n"
		"\n");
	char *key = 0;
	int rc = ldif_peek_entry(f, -1, &key, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "rename");
	free(key);
	return 1;
}

static int test_peek_rename_moddn(void)
{
	FILE *f = make_input(
		"dn: cn=old,dc=example,dc=com\n"
		"changetype: moddn\n"
		"newrdn: cn=new\n"
		"deleteoldrdn: 1\n"
		"\n");
	char *key = 0;
	int rc = ldif_peek_entry(f, -1, &key, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "rename");
	free(key);
	return 1;
}

static int test_rename_root_entry_no_comma(void)
{
	FILE *f = make_input(
		"dn: dc=com\n"
		"changetype: modrdn\n"
		"newrdn: dc=org\n"
		"deleteoldrdn: 0\n"
		"\n");
	char *dn1 = 0, *dn2 = 0;
	int deleteoldrdn = -1;
	int rc = ldif_read_rename(f, -1, &dn1, &dn2, &deleteoldrdn);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(dn2, "dc=org");
	free(dn1); free(dn2);
	return 1;
}


/*
 * Group 12: Error conditions
 */
static int test_invalid_dn(void)
{
	FILE *f = make_input(
		"dn: invalid\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_invalid_changetype(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: bogus\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_control_line_not_supported(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"control: 1.2.3.4 true\n"
		"changetype: add\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_null_byte_in_attr_name(void)
{
	static const char data[] =
		"dn: cn=foo,dc=example,dc=com\n"
		"c\0n: foo\n"
		"\n";
	FILE *f = fmemopen((void *) data, sizeof(data) - 1, "r");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_unexpected_eof_in_attr_name(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_unexpected_eol_in_attr_name(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_unexpected_eof_in_value(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}

static int test_dash_line_in_non_modify_context(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"-\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * Group 13: skip_entry
 */
static int test_skip_simple_entry(void)
{
	FILE *f = make_input(
		"dn: cn=a,dc=example,dc=com\n"
		"cn: a\n"
		"\n"
		"dn: cn=b,dc=example,dc=com\n"
		"cn: b\n"
		"\n");
	char *key = 0, *key2 = 0;
	tentry *entry = 0;
	int rc;

	rc = ldif_skip_entry(f, -1, &key);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");

	rc = ldif_read_entry(f, -1, &key2, &entry, 0);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(entry), "cn=b,dc=example,dc=com");

	fclose(f);
	free(key); free(key2);
	entry_free(entry);
	return 1;
}

static int test_skip_modify_entry(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"changetype: modify\n"
		"add: mail\n"
		"mail: foo@example.com\n"
		"-\n"
		"\n");
	char *key = 0;
	int rc = ldif_skip_entry(f, -1, &key);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "modify");
	free(key);
	return 1;
}


/*
 * Group 14: pos output parameter
 */
static int test_pos_set_correctly(void)
{
	FILE *f = make_input(
		"\n"
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	long pos = -1;
	int rc = ldif_read_entry(f, -1, &key, &entry, &pos);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ((int) pos, 1);

	free(key);
	entry_free(entry);
	return 1;
}

static int test_pos_with_version(void)
{
	FILE *f = make_input(
		"version: 1\n"
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	long pos = -1;
	int rc = ldif_read_entry(f, -1, &key, &entry, &pos);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ((int) pos, 11);

	free(key);
	entry_free(entry);
	return 1;
}


/*
 * Group 15: Edge cases
 */
static int test_multiple_different_attributes(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"sn: bar\n"
		"mail: foo@bar.com\n"
		"description: test\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(entry_attr_count(entry), 4);
	ASSERT_NOT_NULL(find_attr(entry, "cn"));
	ASSERT_NOT_NULL(find_attr(entry, "sn"));
	ASSERT_NOT_NULL(find_attr(entry, "mail"));
	ASSERT_NOT_NULL(find_attr(entry, "description"));

	free(key);
	entry_free(entry);
	return 1;
}

static int test_peek_does_not_consume_body(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"sn: bar\n"
		"\n");
	char *key = 0, *key2 = 0;
	tentry *entry = 0;
	long pos = -1;
	int rc;

	rc = ldif_peek_entry(f, -1, &key, &pos);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");

	rc = ldif_read_entry(f, pos, &key2, &entry, 0);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_INT_EQ(entry_attr_count(entry), 2);
	ASSERT_NOT_NULL(find_attr(entry, "cn"));
	ASSERT_NOT_NULL(find_attr(entry, "sn"));

	fclose(f);
	free(key); free(key2);
	entry_free(entry);
	return 1;
}

static int test_extra_spaces_after_colon(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn:    foo\n"
		"\n");
	char *key = 0;
	tentry *entry = 0;
	tattribute *a;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
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

static int test_crlf_line_endings(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\r\n"
		"cn: foo\r\n"
		"\r\n");
	char *key = 0;
	tentry *entry = 0;
	int rc = ldif_read_entry(f, -1, &key, &entry, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(entry_dn(entry), "cn=foo,dc=example,dc=com");

	free(key);
	entry_free(entry);
	return 1;
}

static int test_file_url_unknown_scheme(void)
{
	FILE *f = make_input(
		"dn: cn=foo,dc=example,dc=com\n"
		"cn:< http://example.com/foo\n"
		"\n");
	char *key = 0;
	int rc = ldif_read_entry(f, -1, &key, 0, 0);
	fclose(f);
	ASSERT_INT_EQ(rc, -1);
	return 1;
}


/*
 * run_parseldif_tests
 */
void run_parseldif_tests(void)
{
	printf("=== parseldif.c test suite ===\n\n");

	printf("Group 1: EOF and empty input\n");
	TEST(eof_returns_null_key);
	TEST(blank_lines_then_eof);
	TEST(peek_eof_returns_null_key);
	TEST(skip_eof_returns_null_key);

	printf("\nGroup 2: Simple attrval-record\n");
	TEST(read_simple_entry);
	TEST(read_entry_multi_valued_attribute);
	TEST(read_entry_empty_value);
	TEST(read_entry_at_offset);
	TEST(read_entry_sequential);
	TEST(entry_eof_terminates_record);

	printf("\nGroup 3: version line\n");
	TEST(version_line_skipped);
	TEST(invalid_version_number);

	printf("\nGroup 4: Comments\n");
	TEST(comment_lines_skipped);
	TEST(comment_with_folding);

	printf("\nGroup 5: Line folding\n");
	TEST(dn_line_folding);
	TEST(value_line_folding);
	TEST(attribute_name_folding);

	printf("\nGroup 6: Base64\n");
	TEST(base64_value);
	TEST(base64_invalid);
	TEST(base64_dn);

	printf("\nGroup 7: ldapvi-key extension\n");
	TEST(ldapvi_key_custom);

	printf("\nGroup 8: changetype: add\n");
	TEST(changetype_add);

	printf("\nGroup 9: changetype: delete\n");
	TEST(read_delete_basic);
	TEST(read_delete_garbage_after);
	TEST(peek_delete);
	TEST(skip_delete);

	printf("\nGroup 10: changetype: modify\n");
	TEST(read_modify_add_operation);
	TEST(read_modify_delete_operation);
	TEST(read_modify_replace_operation);
	TEST(read_modify_multiple_operations);
	TEST(read_modify_add_multiple_values);
	TEST(read_modify_attribute_name_mismatch);
	TEST(read_modify_invalid_change_marker);
	TEST(peek_modify);

	printf("\nGroup 11: changetype: modrdn/moddn\n");
	TEST(read_rename_modrdn);
	TEST(read_rename_moddn);
	TEST(read_rename_with_newsuperior);
	TEST(read_rename_with_empty_newsuperior);
	TEST(read_rename_without_newsuperior);
	TEST(read_rename_invalid_deleteoldrdn);
	TEST(read_rename_missing_newrdn);
	TEST(read_rename_missing_deleteoldrdn);
	TEST(read_rename_garbage_after);
	TEST(peek_rename_modrdn);
	TEST(peek_rename_moddn);
	TEST(rename_root_entry_no_comma);

	printf("\nGroup 12: Error conditions\n");
	TEST(invalid_dn);
	TEST(invalid_changetype);
	TEST(control_line_not_supported);
	TEST(null_byte_in_attr_name);
	TEST(unexpected_eof_in_attr_name);
	TEST(unexpected_eol_in_attr_name);
	TEST(unexpected_eof_in_value);
	TEST(dash_line_in_non_modify_context);

	printf("\nGroup 13: skip_entry\n");
	TEST(skip_simple_entry);
	TEST(skip_modify_entry);

	printf("\nGroup 14: pos output\n");
	TEST(pos_set_correctly);
	TEST(pos_with_version);

	printf("\nGroup 15: Edge cases\n");
	TEST(multiple_different_attributes);
	TEST(peek_does_not_consume_body);
	TEST(extra_spaces_after_colon);
	TEST(crlf_line_endings);
	TEST(file_url_unknown_scheme);
}
