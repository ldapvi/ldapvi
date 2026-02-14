/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for print.c - the output formatting functions.
 */
#define _GNU_SOURCE
#include "common.h"
#include "test_harness.h"

extern t_print_binary_mode print_binary_mode;


/*
 * Helpers
 */
static tentry *
make_entry(const char *dn)
{
	return entry_new(xdup((char *) dn));
}

static void
add_value(tentry *entry, const char *ad, const char *val, int len)
{
	tattribute *a = entry_find_attribute(entry, (char *) ad, 1);
	attribute_append_value(a, (char *) val, len);
}

static LDAPMod *
make_mod(int op, const char *type, struct berval **bvals)
{
	LDAPMod *m = xalloc(sizeof(LDAPMod));
	m->mod_op = op | LDAP_MOD_BVALUES;
	m->mod_type = xdup((char *) type);
	m->mod_bvalues = bvals;
	return m;
}

static struct berval *
make_berval(const char *data, int len)
{
	struct berval *bv = xalloc(sizeof(struct berval));
	bv->bv_val = xalloc(len);
	memcpy(bv->bv_val, data, len);
	bv->bv_len = len;
	return bv;
}

/* Heap-allocate a NULL-terminated berval array (so ldap_mods_free can free it). */
static struct berval **
bvarray1(struct berval *bv)
{
	struct berval **a = xalloc(2 * sizeof(*a));
	a[0] = bv;
	a[1] = 0;
	return a;
}

static struct berval **
bvarray0(void)
{
	struct berval **a = xalloc(sizeof(*a));
	a[0] = 0;
	return a;
}

static LDAPMod **
modarray1(LDAPMod *m)
{
	LDAPMod **a = xalloc(2 * sizeof(*a));
	a[0] = m;
	a[1] = 0;
	return a;
}

static LDAPMod **
modarray2(LDAPMod *m1, LDAPMod *m2)
{
	LDAPMod **a = xalloc(3 * sizeof(*a));
	a[0] = m1;
	a[1] = m2;
	a[2] = 0;
	return a;
}

/* Capture output from a print function into a string.
 * Caller must free the returned buffer. */
static char *
capture(void (*fn)(FILE *), size_t *lenp)
{
	char *buf = 0;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);
	fn(f);
	fclose(f);
	if (lenp) *lenp = len;
	return buf;
}


/*
 * Group 1: print_ldapvi_entry
 */
static tentry *g_entry;
static char *g_key;

static void do_print_ldapvi_entry(FILE *f)
{
	print_ldapvi_entry(f, g_entry, g_key, 0);
}

static int test_ldapvi_entry_simple(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "foo", 3);
	g_entry = e; g_key = "add";
	buf = capture(do_print_ldapvi_entry, 0);
	ASSERT_STREQ(buf,
		"\nadd cn=foo,dc=example,dc=com\n"
		"cn: foo\n");
	free(buf);
	entry_free(e);
	return 1;
}

static int test_ldapvi_entry_multi_valued(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "foo", 3);
	add_value(e, "cn", "bar", 3);
	g_entry = e; g_key = "add";
	buf = capture(do_print_ldapvi_entry, 0);
	ASSERT_STREQ(buf,
		"\nadd cn=foo,dc=example,dc=com\n"
		"cn: foo\n"
		"cn: bar\n");
	free(buf);
	entry_free(e);
	return 1;
}

static int test_ldapvi_entry_null_key(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "foo", 3);
	g_entry = e; g_key = 0;
	buf = capture(do_print_ldapvi_entry, 0);
	/* null key → "entry" */
	ASSERT(strncmp(buf, "\nentry cn=foo,dc=example,dc=com\n", 32) == 0);
	free(buf);
	entry_free(e);
	return 1;
}

static int test_ldapvi_entry_binary_value(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "\x00\x01\x02", 3);
	g_entry = e; g_key = "add";
	print_binary_mode = PRINT_UTF8;
	buf = capture(do_print_ldapvi_entry, 0);
	/* binary data should be base64 encoded */
	ASSERT(strstr(buf, "cn:: ") != 0);
	free(buf);
	entry_free(e);
	return 1;
}

static int test_ldapvi_entry_newline_value(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "description", "line1\nline2", 11);
	g_entry = e; g_key = "add";
	print_binary_mode = PRINT_UTF8;
	buf = capture(do_print_ldapvi_entry, 0);
	/* newlines should be backslash-escaped with :; encoding */
	ASSERT(strstr(buf, "description:; line1\\") != 0);
	free(buf);
	entry_free(e);
	return 1;
}

static int test_ldapvi_entry_space_prefix(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", " leading space", 14);
	g_entry = e; g_key = "add";
	print_binary_mode = PRINT_UTF8;
	buf = capture(do_print_ldapvi_entry, 0);
	/* starts with space → not safe_string_p → :; encoding */
	ASSERT(strstr(buf, "cn:;  leading space\n") != 0);
	free(buf);
	entry_free(e);
	return 1;
}


/*
 * Group 2: print_ldapvi_modify
 */
static char *g_dn;
static LDAPMod **g_mods;

static void do_print_ldapvi_modify(FILE *f)
{
	print_ldapvi_modify(f, g_dn, g_mods);
}

static int test_ldapvi_modify_add(void)
{
	char *buf;
	struct berval *bv = make_berval("foo@example.com", 15);
	LDAPMod *mod = make_mod(LDAP_MOD_ADD, "mail", bvarray1(bv));
	LDAPMod **mods = modarray1(mod);

	g_dn = "cn=foo,dc=example,dc=com";
	g_mods = mods;
	buf = capture(do_print_ldapvi_modify, 0);

	ASSERT_STREQ(buf,
		"\nmodify cn=foo,dc=example,dc=com\n"
		"add: mail\n"
		": foo@example.com\n");
	free(buf);
	ldap_mods_free(mods, 1);
	return 1;
}

static int test_ldapvi_modify_multi_ops(void)
{
	char *buf;
	struct berval *bv1 = make_berval("foo@example.com", 15);
	LDAPMod *mod1 = make_mod(LDAP_MOD_ADD, "mail", bvarray1(bv1));
	LDAPMod *mod2 = make_mod(LDAP_MOD_DELETE, "phone", bvarray0());
	LDAPMod **mods = modarray2(mod1, mod2);

	g_dn = "cn=foo,dc=example,dc=com";
	g_mods = mods;
	buf = capture(do_print_ldapvi_modify, 0);

	ASSERT(strstr(buf, "add: mail\n") != 0);
	ASSERT(strstr(buf, "delete: phone\n") != 0);
	free(buf);
	ldap_mods_free(mods, 1);
	return 1;
}


/*
 * Group 3: print_ldapvi_rename
 */
static char *g_olddn, *g_newdn;
static int g_deleteoldrdn;

static void do_print_ldapvi_rename(FILE *f)
{
	print_ldapvi_rename(f, g_olddn, g_newdn, g_deleteoldrdn);
}

static int test_ldapvi_rename_add(void)
{
	char *buf;
	g_olddn = "cn=old,dc=example,dc=com";
	g_newdn = "cn=new,dc=example,dc=com";
	g_deleteoldrdn = 0;
	buf = capture(do_print_ldapvi_rename, 0);

	ASSERT_STREQ(buf,
		"\nrename cn=old,dc=example,dc=com\n"
		"add: cn=new,dc=example,dc=com\n");
	free(buf);
	return 1;
}

static int test_ldapvi_rename_replace(void)
{
	char *buf;
	g_olddn = "cn=old,dc=example,dc=com";
	g_newdn = "cn=new,dc=example,dc=com";
	g_deleteoldrdn = 1;
	buf = capture(do_print_ldapvi_rename, 0);

	ASSERT_STREQ(buf,
		"\nrename cn=old,dc=example,dc=com\n"
		"replace: cn=new,dc=example,dc=com\n");
	free(buf);
	return 1;
}


/*
 * Group 4: print_ldapvi_modrdn
 */
static char *g_newrdn;

static void do_print_ldapvi_modrdn(FILE *f)
{
	print_ldapvi_modrdn(f, g_olddn, g_newrdn, g_deleteoldrdn);
}

static int test_ldapvi_modrdn(void)
{
	char *buf;
	g_olddn = "cn=old,dc=example,dc=com";
	g_newrdn = "cn=new";
	g_deleteoldrdn = 1;
	buf = capture(do_print_ldapvi_modrdn, 0);

	/* Should construct full DN: cn=new,dc=example,dc=com */
	ASSERT(strstr(buf, "\nrename cn=old,dc=example,dc=com\n") != 0);
	ASSERT(strstr(buf, "replace") != 0);
	ASSERT(strstr(buf, "cn=new,dc=example,dc=com") != 0);
	free(buf);
	return 1;
}


/*
 * Group 5: print_ldapvi_add
 */
static void do_print_ldapvi_add(FILE *f)
{
	print_ldapvi_add(f, g_dn, g_mods);
}

static int test_ldapvi_add(void)
{
	char *buf;
	struct berval *bv = make_berval("foo", 3);
	LDAPMod *mod = make_mod(LDAP_MOD_ADD, "cn", bvarray1(bv));
	LDAPMod **mods = modarray1(mod);

	g_dn = "cn=foo,dc=example,dc=com";
	g_mods = mods;
	buf = capture(do_print_ldapvi_add, 0);

	ASSERT_STREQ(buf,
		"\nadd cn=foo,dc=example,dc=com\n"
		"cn: foo\n");
	free(buf);
	ldap_mods_free(mods, 1);
	return 1;
}


/*
 * Group 6: print_ldapvi_delete
 */
static void do_print_ldapvi_delete(FILE *f)
{
	print_ldapvi_delete(f, g_dn);
}

static int test_ldapvi_delete(void)
{
	char *buf;
	g_dn = "cn=foo,dc=example,dc=com";
	buf = capture(do_print_ldapvi_delete, 0);

	ASSERT_STREQ(buf,
		"\ndelete cn=foo,dc=example,dc=com\n");
	free(buf);
	return 1;
}


/*
 * Group 7: print_ldif_entry
 */
static void do_print_ldif_entry(FILE *f)
{
	print_ldif_entry(f, g_entry, g_key, 0);
}

static int test_ldif_entry_simple(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "foo", 3);
	g_entry = e; g_key = 0;
	buf = capture(do_print_ldif_entry, 0);
	ASSERT_STREQ(buf,
		"\ndn: cn=foo,dc=example,dc=com\n"
		"cn: foo\n");
	free(buf);
	entry_free(e);
	return 1;
}

static int test_ldif_entry_with_key(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "foo", 3);
	g_entry = e; g_key = "42";
	buf = capture(do_print_ldif_entry, 0);
	ASSERT(strstr(buf, "ldapvi-key: 42\n") != 0);
	free(buf);
	entry_free(e);
	return 1;
}

static int test_ldif_entry_binary(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "\x00\x01\x02", 3);
	g_entry = e; g_key = 0;
	buf = capture(do_print_ldif_entry, 0);
	ASSERT(strstr(buf, "cn:: ") != 0);
	free(buf);
	entry_free(e);
	return 1;
}


/*
 * Group 8: print_ldif_modify
 */
static void do_print_ldif_modify(FILE *f)
{
	print_ldif_modify(f, g_dn, g_mods);
}

static int test_ldif_modify(void)
{
	char *buf;
	struct berval *bv = make_berval("foo@example.com", 15);
	LDAPMod *mod = make_mod(LDAP_MOD_ADD, "mail", bvarray1(bv));
	LDAPMod **mods = modarray1(mod);

	g_dn = "cn=foo,dc=example,dc=com";
	g_mods = mods;
	buf = capture(do_print_ldif_modify, 0);

	ASSERT(strstr(buf, "dn: cn=foo,dc=example,dc=com\n") != 0);
	ASSERT(strstr(buf, "changetype: modify\n") != 0);
	ASSERT(strstr(buf, "add: mail\n") != 0);
	ASSERT(strstr(buf, "mail: foo@example.com\n") != 0);
	ASSERT(strstr(buf, "-\n") != 0);
	free(buf);
	ldap_mods_free(mods, 1);
	return 1;
}


/*
 * Group 9: print_ldif_rename
 */
static void do_print_ldif_rename(FILE *f)
{
	print_ldif_rename(f, g_olddn, g_newdn, g_deleteoldrdn);
}

static int test_ldif_rename(void)
{
	char *buf;
	g_olddn = "cn=old,dc=example,dc=com";
	g_newdn = "cn=new,dc=example,dc=com";
	g_deleteoldrdn = 1;
	buf = capture(do_print_ldif_rename, 0);

	ASSERT(strstr(buf, "dn: cn=old,dc=example,dc=com\n") != 0);
	ASSERT(strstr(buf, "changetype: modrdn\n") != 0);
	ASSERT(strstr(buf, "newrdn: cn=new\n") != 0);
	ASSERT(strstr(buf, "deleteoldrdn: 1\n") != 0);
	ASSERT(strstr(buf, "newsuperior: dc=example,dc=com\n") != 0);
	free(buf);
	return 1;
}


/*
 * Group 10: print_ldif_modrdn
 */
static void do_print_ldif_modrdn(FILE *f)
{
	print_ldif_modrdn(f, g_olddn, g_newrdn, g_deleteoldrdn);
}

static int test_ldif_modrdn(void)
{
	char *buf;
	g_olddn = "cn=old,dc=example,dc=com";
	g_newrdn = "cn=new";
	g_deleteoldrdn = 0;
	buf = capture(do_print_ldif_modrdn, 0);

	ASSERT(strstr(buf, "dn: cn=old,dc=example,dc=com\n") != 0);
	ASSERT(strstr(buf, "changetype: modrdn\n") != 0);
	ASSERT(strstr(buf, "newrdn: cn=new\n") != 0);
	ASSERT(strstr(buf, "deleteoldrdn: 0\n") != 0);
	free(buf);
	return 1;
}


/*
 * Group 11: print_ldif_add
 */
static void do_print_ldif_add(FILE *f)
{
	print_ldif_add(f, g_dn, g_mods);
}

static int test_ldif_add(void)
{
	char *buf;
	struct berval *bv = make_berval("foo", 3);
	LDAPMod *mod = make_mod(LDAP_MOD_ADD, "cn", bvarray1(bv));
	LDAPMod **mods = modarray1(mod);

	g_dn = "cn=foo,dc=example,dc=com";
	g_mods = mods;
	buf = capture(do_print_ldif_add, 0);

	ASSERT(strstr(buf, "dn: cn=foo,dc=example,dc=com\n") != 0);
	ASSERT(strstr(buf, "changetype: add\n") != 0);
	ASSERT(strstr(buf, "cn: foo\n") != 0);
	free(buf);
	ldap_mods_free(mods, 1);
	return 1;
}


/*
 * Group 12: print_ldif_delete
 */
static void do_print_ldif_delete(FILE *f)
{
	print_ldif_delete(f, g_dn);
}

static int test_ldif_delete(void)
{
	char *buf;
	g_dn = "cn=foo,dc=example,dc=com";
	buf = capture(do_print_ldif_delete, 0);

	ASSERT(strstr(buf, "dn: cn=foo,dc=example,dc=com\n") != 0);
	ASSERT(strstr(buf, "changetype: delete\n") != 0);
	free(buf);
	return 1;
}


/*
 * Group 13: print_binary_mode
 */
static void do_print_binary_mode_entry(FILE *f)
{
	print_ldapvi_entry(f, g_entry, g_key, 0);
}

static int test_print_mode_utf8(void)
{
	char *buf;
	/* valid UTF-8: U+00E9 (e-acute) = 0xC3 0xA9 */
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "\xc3\xa9", 2);
	g_entry = e; g_key = "add";
	print_binary_mode = PRINT_UTF8;
	buf = capture(do_print_binary_mode_entry, 0);
	/* valid UTF-8 should be readable → :; encoding (not safe but readable) */
	ASSERT(strstr(buf, "cn:: ") == 0); /* NOT base64 */
	free(buf);
	entry_free(e);
	return 1;
}

static int test_print_mode_ascii(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "\xc3\xa9", 2);
	g_entry = e; g_key = "add";
	print_binary_mode = PRINT_ASCII;
	buf = capture(do_print_binary_mode_entry, 0);
	/* non-ASCII → not readable in ASCII mode → base64 */
	ASSERT(strstr(buf, "cn:: ") != 0);
	free(buf);
	entry_free(e);
	return 1;
}

static int test_print_mode_junk(void)
{
	char *buf;
	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "\x00\x01\x02", 3);
	g_entry = e; g_key = "add";
	print_binary_mode = PRINT_JUNK;
	buf = capture(do_print_binary_mode_entry, 0);
	/* JUNK mode: everything is readable → never base64 */
	ASSERT(strstr(buf, "cn:: ") == 0);
	free(buf);
	entry_free(e);
	return 1;
}


/*
 * Group 14: Round-trip tests
 */
static int test_roundtrip_ldapvi(void)
{
	char *buf;
	size_t len;
	FILE *f;
	char *key = 0;
	tentry *result = 0;
	tattribute *a;
	int rc;

	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "foo", 3);
	add_value(e, "sn", "bar", 3);
	g_entry = e; g_key = "add";
	print_binary_mode = PRINT_UTF8;
	buf = capture(do_print_ldapvi_entry, &len);
	entry_free(e);

	/* parse the output back with read_entry (parse.c) */
	f = fmemopen(buf, len, "r");
	rc = read_entry(f, -1, &key, &result, 0);
	fclose(f);
	free(buf);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "add");
	ASSERT_STREQ(entry_dn(result), "cn=foo,dc=example,dc=com");

	a = entry_find_attribute(result, "cn", 0);
	ASSERT_NOT_NULL(a);
	a = entry_find_attribute(result, "sn", 0);
	ASSERT_NOT_NULL(a);

	free(key);
	entry_free(result);
	return 1;
}

static int test_roundtrip_ldif(void)
{
	char *buf;
	size_t len;
	FILE *f;
	char *key = 0;
	tentry *result = 0;
	tattribute *a;
	int rc;

	tentry *e = make_entry("cn=foo,dc=example,dc=com");
	add_value(e, "cn", "foo", 3);
	add_value(e, "sn", "bar", 3);
	g_entry = e; g_key = "42";
	buf = capture(do_print_ldif_entry, &len);
	entry_free(e);

	/* parse the output back with ldif_read_entry (parseldif.c) */
	f = fmemopen(buf, len, "r");
	rc = ldif_read_entry(f, -1, &key, &result, 0);
	fclose(f);
	free(buf);

	ASSERT_INT_EQ(rc, 0);
	ASSERT_STREQ(key, "42");
	ASSERT_STREQ(entry_dn(result), "cn=foo,dc=example,dc=com");

	a = entry_find_attribute(result, "cn", 0);
	ASSERT_NOT_NULL(a);
	a = entry_find_attribute(result, "sn", 0);
	ASSERT_NOT_NULL(a);

	free(key);
	entry_free(result);
	return 1;
}


/*
 * run_print_tests
 */
void run_print_tests(void)
{
	printf("=== print.c test suite ===\n\n");

	printf("Group 1: print_ldapvi_entry\n");
	TEST(ldapvi_entry_simple);
	TEST(ldapvi_entry_multi_valued);
	TEST(ldapvi_entry_null_key);
	TEST(ldapvi_entry_binary_value);
	TEST(ldapvi_entry_newline_value);
	TEST(ldapvi_entry_space_prefix);

	printf("\nGroup 2: print_ldapvi_modify\n");
	TEST(ldapvi_modify_add);
	TEST(ldapvi_modify_multi_ops);

	printf("\nGroup 3: print_ldapvi_rename\n");
	TEST(ldapvi_rename_add);
	TEST(ldapvi_rename_replace);

	printf("\nGroup 4: print_ldapvi_modrdn\n");
	TEST(ldapvi_modrdn);

	printf("\nGroup 5: print_ldapvi_add\n");
	TEST(ldapvi_add);

	printf("\nGroup 6: print_ldapvi_delete\n");
	TEST(ldapvi_delete);

	printf("\nGroup 7: print_ldif_entry\n");
	TEST(ldif_entry_simple);
	TEST(ldif_entry_with_key);
	TEST(ldif_entry_binary);

	printf("\nGroup 8: print_ldif_modify\n");
	TEST(ldif_modify);

	printf("\nGroup 9: print_ldif_rename\n");
	TEST(ldif_rename);

	printf("\nGroup 10: print_ldif_modrdn\n");
	TEST(ldif_modrdn);

	printf("\nGroup 11: print_ldif_add\n");
	TEST(ldif_add);

	printf("\nGroup 12: print_ldif_delete\n");
	TEST(ldif_delete);

	printf("\nGroup 13: print_binary_mode\n");
	TEST(print_mode_utf8);
	TEST(print_mode_ascii);
	TEST(print_mode_junk);

	printf("\nGroup 14: Round-trip\n");
	TEST(roundtrip_ldapvi);
	TEST(roundtrip_ldif);

	/* restore default mode */
	print_binary_mode = PRINT_UTF8;
}
