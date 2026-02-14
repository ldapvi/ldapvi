/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for data.c - entry/attribute data structures and conversions.
 */
#define _GNU_SOURCE
#include "common.h"
#include "test_harness.h"

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


/*
 * Group 1: entry_new and entry_free
 */
static int test_entry_new_sets_dn(void)
{
	tentry *e = entry_new(xdup("cn=foo,dc=example,dc=com"));
	ASSERT_STREQ(entry_dn(e), "cn=foo,dc=example,dc=com");
	ASSERT_INT_EQ(entry_attributes(e)->len, 0);
	entry_free(e);
	return 1;
}

static int test_entry_free_with_attributes(void)
{
	tentry *e = make_entry("cn=test,dc=com");
	add_attr_value(e, "cn", "test");
	add_attr_value(e, "sn", "value");
	entry_free(e);
	/* no crash = pass */
	return 1;
}


/*
 * Group 2: entry_cmp
 */
static int test_entry_cmp_equal(void)
{
	tentry *a = make_entry("cn=foo,dc=com");
	tentry *b = make_entry("cn=foo,dc=com");
	ASSERT_INT_EQ(entry_cmp(a, b), 0);
	entry_free(a);
	entry_free(b);
	return 1;
}

static int test_entry_cmp_less(void)
{
	tentry *a = make_entry("cn=aaa,dc=com");
	tentry *b = make_entry("cn=zzz,dc=com");
	ASSERT(entry_cmp(a, b) < 0);
	entry_free(a);
	entry_free(b);
	return 1;
}

static int test_entry_cmp_greater(void)
{
	tentry *a = make_entry("cn=zzz,dc=com");
	tentry *b = make_entry("cn=aaa,dc=com");
	ASSERT(entry_cmp(a, b) > 0);
	entry_free(a);
	entry_free(b);
	return 1;
}


/*
 * Group 3: attribute_new, attribute_free, attribute_cmp
 */
static int test_attribute_new_sets_ad(void)
{
	tattribute *a = attribute_new(xdup("cn"));
	ASSERT_STREQ(attribute_ad(a), "cn");
	ASSERT_INT_EQ(attribute_values(a)->len, 0);
	attribute_free(a);
	return 1;
}

static int test_attribute_cmp_equal(void)
{
	tattribute *a = attribute_new(xdup("cn"));
	tattribute *b = attribute_new(xdup("cn"));
	ASSERT_INT_EQ(attribute_cmp(a, b), 0);
	attribute_free(a);
	attribute_free(b);
	return 1;
}

static int test_attribute_cmp_different(void)
{
	tattribute *a = attribute_new(xdup("cn"));
	tattribute *b = attribute_new(xdup("sn"));
	ASSERT(attribute_cmp(a, b) != 0);
	attribute_free(a);
	attribute_free(b);
	return 1;
}


/*
 * Group 4: entry_find_attribute
 */
static int test_find_attribute_creates(void)
{
	tentry *e = make_entry("cn=test,dc=com");
	tattribute *a = entry_find_attribute(e, "cn", 1);
	ASSERT_NOT_NULL(a);
	ASSERT_STREQ(attribute_ad(a), "cn");
	ASSERT_INT_EQ(entry_attributes(e)->len, 1);
	entry_free(e);
	return 1;
}

static int test_find_attribute_no_create(void)
{
	tentry *e = make_entry("cn=test,dc=com");
	tattribute *a = entry_find_attribute(e, "cn", 0);
	ASSERT_NULL(a);
	entry_free(e);
	return 1;
}

static int test_find_attribute_existing(void)
{
	tentry *e = make_entry("cn=test,dc=com");
	tattribute *a1 = entry_find_attribute(e, "cn", 1);
	tattribute *a2 = entry_find_attribute(e, "cn", 1);
	ASSERT(a1 == a2);
	ASSERT_INT_EQ(entry_attributes(e)->len, 1);
	entry_free(e);
	return 1;
}


/*
 * Group 5: attribute values
 */
static int test_append_and_find_value(void)
{
	tattribute *a = attribute_new(xdup("cn"));
	attribute_append_value(a, "hello", 5);
	ASSERT_INT_EQ(attribute_values(a)->len, 1);
	ASSERT_INT_EQ(attribute_find_value(a, "hello", 5), 0);
	attribute_free(a);
	return 1;
}

static int test_find_value_not_found(void)
{
	tattribute *a = attribute_new(xdup("cn"));
	attribute_append_value(a, "hello", 5);
	ASSERT_INT_EQ(attribute_find_value(a, "world", 5), -1);
	attribute_free(a);
	return 1;
}

static int test_remove_value_success(void)
{
	tattribute *a = attribute_new(xdup("cn"));
	attribute_append_value(a, "hello", 5);
	ASSERT_INT_EQ(attribute_remove_value(a, "hello", 5), 0);
	ASSERT_INT_EQ(attribute_values(a)->len, 0);
	ASSERT_INT_EQ(attribute_find_value(a, "hello", 5), -1);
	attribute_free(a);
	return 1;
}

static int test_remove_value_not_found(void)
{
	tattribute *a = attribute_new(xdup("cn"));
	attribute_append_value(a, "hello", 5);
	ASSERT_INT_EQ(attribute_remove_value(a, "world", 5), -1);
	ASSERT_INT_EQ(attribute_values(a)->len, 1);
	attribute_free(a);
	return 1;
}


/*
 * Group 6: named_array_ptr_cmp
 */
static int test_named_array_ptr_cmp_sorts(void)
{
	tentry *e1 = make_entry("cn=zzz,dc=com");
	tentry *e2 = make_entry("cn=aaa,dc=com");
	tentry *arr[2];
	arr[0] = e1;
	arr[1] = e2;
	qsort(arr, 2, sizeof(tentry *), named_array_ptr_cmp);
	ASSERT_STREQ(entry_dn(arr[0]), "cn=aaa,dc=com");
	ASSERT_STREQ(entry_dn(arr[1]), "cn=zzz,dc=com");
	entry_free(e1);
	entry_free(e2);
	return 1;
}


/*
 * Group 7: berval and string conversions
 */
static int test_array2string(void)
{
	char *s;
	GArray *a = g_array_new(0, 0, 1);
	g_array_append_vals(a, "hello", 5);
	s = array2string(a);
	ASSERT_STREQ(s, "hello");
	ASSERT_INT_EQ((int) strlen(s), 5);
	free(s);
	g_array_free(a, 1);
	return 1;
}

static int test_string2berval(void)
{
	struct berval *bv;
	GArray *a = g_array_new(0, 0, 1);
	g_array_append_vals(a, "test", 4);
	bv = string2berval(a);
	ASSERT_NOT_NULL(bv);
	ASSERT_INT_EQ((int) bv->bv_len, 4);
	ASSERT(memcmp(bv->bv_val, "test", 4) == 0);
	xfree_berval(bv);
	g_array_free(a, 1);
	return 1;
}

static int test_gstring2berval(void)
{
	struct berval *bv;
	GString *gs = g_string_new("data");
	bv = gstring2berval(gs);
	ASSERT_NOT_NULL(bv);
	ASSERT_INT_EQ((int) bv->bv_len, 4);
	ASSERT(memcmp(bv->bv_val, "data", 4) == 0);
	xfree_berval(bv);
	g_string_free(gs, 1);
	return 1;
}


/*
 * Group 8: attribute2mods and entry2mods
 */
static int test_attribute2mods(void)
{
	LDAPMod *m;
	tattribute *a = attribute_new(xdup("mail"));
	attribute_append_value(a, "a@b.com", 7);
	attribute_append_value(a, "c@d.com", 7);
	m = attribute2mods(a);
	ASSERT_NOT_NULL(m);
	ASSERT_INT_EQ(m->mod_op, LDAP_MOD_BVALUES);
	ASSERT_STREQ(m->mod_type, "mail");
	ASSERT_NOT_NULL(m->mod_bvalues[0]);
	ASSERT_INT_EQ((int) m->mod_bvalues[0]->bv_len, 7);
	ASSERT(memcmp(m->mod_bvalues[0]->bv_val, "a@b.com", 7) == 0);
	ASSERT_NOT_NULL(m->mod_bvalues[1]);
	ASSERT_INT_EQ((int) m->mod_bvalues[1]->bv_len, 7);
	ASSERT_NULL(m->mod_bvalues[2]);
	/* free mod */
	free(m->mod_type);
	xfree_berval(m->mod_bvalues[0]);
	xfree_berval(m->mod_bvalues[1]);
	free(m->mod_bvalues);
	free(m);
	attribute_free(a);
	return 1;
}

static int test_entry2mods(void)
{
	LDAPMod **mods;
	tentry *e = make_entry("cn=test,dc=com");
	add_attr_value(e, "cn", "test");
	add_attr_value(e, "sn", "value");
	mods = entry2mods(e);
	ASSERT_NOT_NULL(mods);
	ASSERT_NOT_NULL(mods[0]);
	ASSERT_NOT_NULL(mods[1]);
	ASSERT_NULL(mods[2]);
	ASSERT_STREQ(mods[0]->mod_type, "cn");
	ASSERT_STREQ(mods[1]->mod_type, "sn");
	ldap_mods_free(mods, 1);
	entry_free(e);
	return 1;
}


/*
 * run_data_tests
 */
void run_data_tests(void)
{
	printf("=== data.c test suite ===\n\n");

	printf("Group 1: entry_new and entry_free\n");
	TEST(entry_new_sets_dn);
	TEST(entry_free_with_attributes);

	printf("\nGroup 2: entry_cmp\n");
	TEST(entry_cmp_equal);
	TEST(entry_cmp_less);
	TEST(entry_cmp_greater);

	printf("\nGroup 3: attribute_new, attribute_free, attribute_cmp\n");
	TEST(attribute_new_sets_ad);
	TEST(attribute_cmp_equal);
	TEST(attribute_cmp_different);

	printf("\nGroup 4: entry_find_attribute\n");
	TEST(find_attribute_creates);
	TEST(find_attribute_no_create);
	TEST(find_attribute_existing);

	printf("\nGroup 5: attribute values\n");
	TEST(append_and_find_value);
	TEST(find_value_not_found);
	TEST(remove_value_success);
	TEST(remove_value_not_found);

	printf("\nGroup 6: named_array_ptr_cmp\n");
	TEST(named_array_ptr_cmp_sorts);

	printf("\nGroup 7: berval and string conversions\n");
	TEST(array2string);
	TEST(string2berval);
	TEST(gstring2berval);

	printf("\nGroup 8: attribute2mods and entry2mods\n");
	TEST(attribute2mods);
	TEST(entry2mods);
}
