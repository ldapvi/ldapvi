/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for schema.c - schema lookups and entroid computation.
 */
#define _GNU_SOURCE
#include "common.h"
#include "test_harness.h"

/*
 * Case-insensitive hash functions (mirrors schema.c's static functions)
 */
static gboolean
test_strcaseequal(gconstpointer v, gconstpointer w)
{
	return strcasecmp((char *) v, (char *) w) == 0;
}

static guint
test_strcasehash(gconstpointer v)
{
	const signed char *p = v;
	guint32 h = tolower(*p);
	if (h)
		for (p += 1; *p != '\0'; p++)
			h = (h << 5) - h + tolower(*p);
	return h;
}

/*
 * Helpers: build a test schema using ldap_str2objectclass/ldap_str2attributetype
 */
static void
add_test_objectclass(GHashTable *classes, const char *def)
{
	int code, i;
	const char *errp;
	LDAPObjectClass *cls = ldap_str2objectclass(def, &code, &errp, 0);
	if (!cls) abort();
	g_hash_table_insert(classes, cls->oc_oid, cls);
	if (cls->oc_names)
		for (i = 0; cls->oc_names[i]; i++)
			g_hash_table_insert(classes, cls->oc_names[i], cls);
}

static void
add_test_attributetype(GHashTable *types, const char *def)
{
	int code, i;
	const char *errp;
	LDAPAttributeType *at = ldap_str2attributetype(def, &code, &errp, 0);
	if (!at) abort();
	g_hash_table_insert(types, at->at_oid, at);
	if (at->at_names)
		for (i = 0; at->at_names[i]; i++)
			g_hash_table_insert(types, at->at_names[i], at);
}

static tschema *
make_test_schema(void)
{
	tschema *s = xalloc(sizeof(tschema));
	s->classes = g_hash_table_new(test_strcasehash, test_strcaseequal);
	s->types = g_hash_table_new(test_strcasehash, test_strcaseequal);

	add_test_attributetype(s->types,
		"( 2.5.4.0 NAME 'objectClass' )");
	add_test_attributetype(s->types,
		"( 2.5.4.3 NAME 'cn' )");
	add_test_attributetype(s->types,
		"( 2.5.4.4 NAME 'sn' )");
	add_test_attributetype(s->types,
		"( 2.5.4.35 NAME 'userPassword' )");
	add_test_attributetype(s->types,
		"( 2.5.4.20 NAME 'telephoneNumber' )");
	add_test_attributetype(s->types,
		"( 2.5.4.34 NAME 'seeAlso' )");
	add_test_attributetype(s->types,
		"( 2.5.4.13 NAME 'description' )");

	add_test_objectclass(s->classes,
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )");
	add_test_objectclass(s->classes,
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL"
		" MUST ( sn $ cn )"
		" MAY ( userPassword $ telephoneNumber"
		" $ seeAlso $ description ) )");
	add_test_objectclass(s->classes,
		"( 2.5.6.7 NAME 'organizationalPerson' SUP person"
		" STRUCTURAL MAY ( telephoneNumber $ seeAlso"
		" $ description ) )");

	return s;
}


/*
 * Group 1: objectclass_name and attributetype_name
 */
static int test_objectclass_name_with_names(void)
{
	int code;
	const char *errp;
	LDAPObjectClass *cls = ldap_str2objectclass(
		"( 1.2.3 NAME 'testClass' )", &code, &errp, 0);
	ASSERT_NOT_NULL(cls);
	ASSERT_STREQ(objectclass_name(cls), "testClass");
	ldap_objectclass_free(cls);
	return 1;
}

static int test_objectclass_name_oid_only(void)
{
	int code;
	const char *errp;
	LDAPObjectClass *cls = ldap_str2objectclass(
		"( 1.2.3.4.5 )", &code, &errp, 0);
	ASSERT_NOT_NULL(cls);
	ASSERT_STREQ(objectclass_name(cls), "1.2.3.4.5");
	ldap_objectclass_free(cls);
	return 1;
}

static int test_attributetype_name_with_names(void)
{
	int code;
	const char *errp;
	LDAPAttributeType *at = ldap_str2attributetype(
		"( 1.2.3 NAME 'testAttr' )", &code, &errp, 0);
	ASSERT_NOT_NULL(at);
	ASSERT_STREQ(attributetype_name(at), "testAttr");
	ldap_attributetype_free(at);
	return 1;
}

static int test_attributetype_name_oid_only(void)
{
	int code;
	const char *errp;
	LDAPAttributeType *at = ldap_str2attributetype(
		"( 9.8.7.6 )", &code, &errp, 0);
	ASSERT_NOT_NULL(at);
	ASSERT_STREQ(attributetype_name(at), "9.8.7.6");
	ldap_attributetype_free(at);
	return 1;
}


/*
 * Group 2: schema_get lookups
 */
static int test_schema_get_objectclass_by_name(void)
{
	tschema *s = make_test_schema();
	LDAPObjectClass *cls = schema_get_objectclass(s, "person");
	ASSERT_NOT_NULL(cls);
	ASSERT_STREQ(objectclass_name(cls), "person");
	schema_free(s);
	return 1;
}

static int test_schema_get_objectclass_case_insensitive(void)
{
	tschema *s = make_test_schema();
	/* Note: the hash function doesn't tolower() the first character,
	 * so only non-first-character case differences are matched. */
	LDAPObjectClass *cls = schema_get_objectclass(s, "perSON");
	ASSERT_NOT_NULL(cls);
	ASSERT_STREQ(objectclass_name(cls), "person");
	schema_free(s);
	return 1;
}

static int test_schema_get_attributetype_by_name(void)
{
	tschema *s = make_test_schema();
	LDAPAttributeType *at = schema_get_attributetype(s, "cn");
	ASSERT_NOT_NULL(at);
	ASSERT_STREQ(attributetype_name(at), "cn");
	schema_free(s);
	return 1;
}

static int test_schema_get_attributetype_not_found(void)
{
	tschema *s = make_test_schema();
	LDAPAttributeType *at = schema_get_attributetype(s, "noSuchAttr");
	ASSERT_NULL(at);
	schema_free(s);
	return 1;
}


/*
 * Group 3: entroid lifecycle
 */
static int test_entroid_new_initializes(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	ASSERT_NOT_NULL(ent);
	ASSERT(ent->schema == s);
	ASSERT_INT_EQ(ent->classes->len, 0);
	ASSERT_INT_EQ(ent->must->len, 0);
	ASSERT_INT_EQ(ent->may->len, 0);
	ASSERT_NULL(ent->structural);
	ASSERT_INT_EQ((int) ent->comment->len, 0);
	ASSERT_INT_EQ((int) ent->error->len, 0);
	entroid_free(ent);
	schema_free(s);
	return 1;
}

static int test_entroid_reset_clears(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	entroid_request_class(ent, "person");
	compute_entroid(ent);
	ASSERT(ent->classes->len > 0);
	ASSERT(ent->must->len > 0);
	ASSERT_NOT_NULL(ent->structural);

	entroid_reset(ent);
	ASSERT_INT_EQ(ent->classes->len, 0);
	ASSERT_INT_EQ(ent->must->len, 0);
	ASSERT_INT_EQ(ent->may->len, 0);
	ASSERT_NULL(ent->structural);
	ASSERT_INT_EQ((int) ent->comment->len, 0);

	entroid_free(ent);
	schema_free(s);
	return 1;
}

static int test_entroid_free_no_crash(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	entroid_free(ent);
	schema_free(s);
	return 1;
}


/*
 * Group 4: entroid_get lookups
 */
static int test_entroid_get_objectclass_found(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	LDAPObjectClass *cls = entroid_get_objectclass(ent, "person");
	ASSERT_NOT_NULL(cls);
	ASSERT_INT_EQ((int) ent->error->len, 0);
	entroid_free(ent);
	schema_free(s);
	return 1;
}

static int test_entroid_get_objectclass_not_found(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	LDAPObjectClass *cls = entroid_get_objectclass(ent, "noSuchClass");
	ASSERT_NULL(cls);
	ASSERT(ent->error->len > 0);
	ASSERT(strstr(ent->error->str, "noSuchClass") != 0);
	entroid_free(ent);
	schema_free(s);
	return 1;
}


/*
 * Group 5: entroid_request_class
 */
static int test_entroid_request_class_dedup(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	entroid_request_class(ent, "person");
	entroid_request_class(ent, "person");
	ASSERT_INT_EQ(ent->classes->len, 1);
	entroid_free(ent);
	schema_free(s);
	return 1;
}


/*
 * Group 6: compute_entroid
 */
static int test_compute_entroid_person(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	int rc;
	entroid_request_class(ent, "person");
	rc = compute_entroid(ent);
	ASSERT_INT_EQ(rc, 0);

	/* "person" SUP top -> classes should include both */
	ASSERT(ent->classes->len >= 2);

	/* structural class should be "person" */
	ASSERT_NOT_NULL(ent->structural);
	ASSERT_STREQ(objectclass_name(ent->structural), "person");

	/* person MUST sn, cn; top MUST objectClass -> must has 3 */
	ASSERT(ent->must->len >= 3);

	/* person MAY userPassword, telephoneNumber, seeAlso, description */
	ASSERT(ent->may->len >= 1);

	/* comment should mention structural class */
	ASSERT(strstr(ent->comment->str, "structural") != 0);

	entroid_free(ent);
	schema_free(s);
	return 1;
}

static int test_compute_entroid_no_structural_warning(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	int rc;
	entroid_request_class(ent, "top");
	rc = compute_entroid(ent);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_NULL(ent->structural);
	ASSERT(strstr(ent->comment->str, "WARNING") != 0);
	ASSERT(strstr(ent->comment->str, "no structural") != 0);
	entroid_free(ent);
	schema_free(s);
	return 1;
}

static int test_compute_entroid_unknown_class(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	LDAPObjectClass *cls = entroid_request_class(ent, "bogusClass");
	ASSERT_NULL(cls);
	ASSERT(ent->error->len > 0);
	entroid_free(ent);
	schema_free(s);
	return 1;
}


/*
 * Group 7: entroid_remove_ad
 */
static int test_entroid_remove_ad_from_must(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	int must_before, found;
	entroid_request_class(ent, "person");
	compute_entroid(ent);

	must_before = ent->must->len;
	found = entroid_remove_ad(ent, "cn");
	ASSERT(found);
	ASSERT_INT_EQ((int) ent->must->len, must_before - 1);

	entroid_free(ent);
	schema_free(s);
	return 1;
}

static int test_entroid_remove_ad_with_option(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	int must_before, found;
	entroid_request_class(ent, "person");
	compute_entroid(ent);

	must_before = ent->must->len;
	found = entroid_remove_ad(ent, "cn;binary");
	ASSERT(found);
	ASSERT_INT_EQ((int) ent->must->len, must_before - 1);

	entroid_free(ent);
	schema_free(s);
	return 1;
}

static int test_entroid_remove_ad_not_found(void)
{
	tschema *s = make_test_schema();
	tentroid *ent = entroid_new(s);
	int found;
	entroid_request_class(ent, "person");
	compute_entroid(ent);

	found = entroid_remove_ad(ent, "nonExistentAttr");
	ASSERT(!found);

	entroid_free(ent);
	schema_free(s);
	return 1;
}


/*
 * Group 8: strcasehash case insensitivity
 */
static int test_strcasehash_case_insensitive(void)
{
	/* The first character must be lowercased too. */
	ASSERT_INT_EQ(test_strcasehash("cn"), test_strcasehash("CN"));
	ASSERT_INT_EQ(test_strcasehash("cn"), test_strcasehash("Cn"));
	ASSERT_INT_EQ(test_strcasehash("objectClass"),
		      test_strcasehash("OBJECTCLASS"));
	ASSERT_INT_EQ(test_strcasehash("a"), test_strcasehash("A"));
	return 1;
}


/*
 * run_schema_tests
 */
void run_schema_tests(void)
{
	printf("=== schema.c test suite ===\n\n");

	printf("Group 1: objectclass_name and attributetype_name\n");
	TEST(objectclass_name_with_names);
	TEST(objectclass_name_oid_only);
	TEST(attributetype_name_with_names);
	TEST(attributetype_name_oid_only);

	printf("\nGroup 2: schema_get lookups\n");
	TEST(schema_get_objectclass_by_name);
	TEST(schema_get_objectclass_case_insensitive);
	TEST(schema_get_attributetype_by_name);
	TEST(schema_get_attributetype_not_found);

	printf("\nGroup 3: entroid lifecycle\n");
	TEST(entroid_new_initializes);
	TEST(entroid_reset_clears);
	TEST(entroid_free_no_crash);

	printf("\nGroup 4: entroid_get lookups\n");
	TEST(entroid_get_objectclass_found);
	TEST(entroid_get_objectclass_not_found);

	printf("\nGroup 5: entroid_request_class\n");
	TEST(entroid_request_class_dedup);

	printf("\nGroup 6: compute_entroid\n");
	TEST(compute_entroid_person);
	TEST(compute_entroid_no_structural_warning);
	TEST(compute_entroid_unknown_class);

	printf("\nGroup 7: entroid_remove_ad\n");
	TEST(entroid_remove_ad_from_must);
	TEST(entroid_remove_ad_with_option);
	TEST(entroid_remove_ad_not_found);

	printf("\nGroup 8: strcasehash\n");
	TEST(strcasehash_case_insensitive);
}
