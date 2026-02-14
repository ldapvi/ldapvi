/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for search.c - get_entry, discover_naming_contexts,
 * handle_result, log_reference, search_subtree.
 *
 * This is a separate test binary that does NOT link -lldap.
 * All LDAP functions are stubbed in test_search_stubs.c.
 */
#define _GNU_SOURCE
#include "common.h"
#include "test_harness.h"

int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

/* Not declared in common.h but have external linkage in search.c */
void handle_result(LDAP *ld, LDAPMessage *result, int start, int n,
		   int progress, int noninteractive);
void log_reference(LDAP *ld, LDAPMessage *reference, FILE *s);
void search_subtree(FILE *s, LDAP *ld, GArray *offsets, char *base,
		    cmdline *cmdline, LDAPControl **ctrls, int notty, int ldif,
		    tschema *schema);

/* Dummy LDAP pointer — never dereferenced */
static int dummy_ld;
#define TEST_LD ((LDAP *) &dummy_ld)

/* Stub globals from test_search_stubs.c */
extern int stub_search_rc;
extern LDAPMessage *stub_result;
extern LDAPMessage *stub_entry;
extern char **stub_values;
extern int stub_parse_result_rc;
extern int stub_parse_result_err;
extern char *stub_parse_result_matcheddn;
extern char *stub_parse_result_text;
extern char **stub_refs;
extern char stub_choose_result;
extern int *stub_result_types;
extern int stub_result_type_idx;


/*
 * Group 1: get_entry
 */
static int test_get_entry_returns_entry(void)
{
	LDAPMessage *result;
	LDAPMessage *entry;
	stub_search_rc = 0;
	entry = get_entry(TEST_LD, "cn=test,dc=example,dc=com", &result);
	ASSERT(entry == stub_entry);
	return 1;
}

static int test_get_entry_sets_result(void)
{
	LDAPMessage *result = 0;
	stub_search_rc = 0;
	get_entry(TEST_LD, "cn=test,dc=example,dc=com", &result);
	ASSERT(result == stub_result);
	return 1;
}


/*
 * Group 2: discover_naming_contexts
 */
static int test_discover_finds_contexts(void)
{
	GPtrArray *basedns = g_ptr_array_new();
	char *vals[] = {"dc=example,dc=com", "dc=test", 0};
	stub_values = vals;

	discover_naming_contexts(TEST_LD, basedns);

	ASSERT_INT_EQ(basedns->len, 2);
	ASSERT_STREQ(g_ptr_array_index(basedns, 0), "dc=example,dc=com");
	ASSERT_STREQ(g_ptr_array_index(basedns, 1), "dc=test");

	free(g_ptr_array_index(basedns, 0));
	free(g_ptr_array_index(basedns, 1));
	g_ptr_array_free(basedns, 1);
	stub_values = 0;
	return 1;
}

static int test_discover_no_contexts(void)
{
	GPtrArray *basedns = g_ptr_array_new();
	stub_values = 0;

	discover_naming_contexts(TEST_LD, basedns);

	ASSERT_INT_EQ(basedns->len, 0);

	g_ptr_array_free(basedns, 1);
	return 1;
}

static int test_discover_single_context(void)
{
	GPtrArray *basedns = g_ptr_array_new();
	char *vals[] = {"dc=one", 0};
	stub_values = vals;

	discover_naming_contexts(TEST_LD, basedns);

	ASSERT_INT_EQ(basedns->len, 1);
	ASSERT_STREQ(g_ptr_array_index(basedns, 0), "dc=one");

	free(g_ptr_array_index(basedns, 0));
	g_ptr_array_free(basedns, 1);
	stub_values = 0;
	return 1;
}


/*
 * Group 3: handle_result
 */
static int test_handle_result_success(void)
{
	stub_parse_result_rc = 0;
	stub_parse_result_err = 0;
	stub_parse_result_matcheddn = 0;
	stub_parse_result_text = 0;

	/* n > start, no "No search results" message */
	handle_result(TEST_LD, stub_result, 0, 5, 1, 0);
	return 1;
}

static int test_handle_result_no_results(void)
{
	stub_parse_result_rc = 0;
	stub_parse_result_err = 0;
	stub_parse_result_matcheddn = 0;
	stub_parse_result_text = 0;

	/* n == start && progress → "No search results" to stderr */
	handle_result(TEST_LD, stub_result, 0, 0, 1, 0);
	return 1;
}

static int test_handle_result_with_matcheddn(void)
{
	stub_parse_result_rc = 0;
	stub_parse_result_err = 0;
	stub_parse_result_matcheddn = "dc=example,dc=com";
	stub_parse_result_text = 0;

	/* n == start && progress, matcheddn set */
	handle_result(TEST_LD, stub_result, 0, 0, 1, 0);

	stub_parse_result_matcheddn = 0;
	return 1;
}

static int test_handle_result_recoverable_no_entries(void)
{
	stub_parse_result_rc = 0;
	stub_parse_result_err = LDAP_NO_SUCH_OBJECT;
	stub_parse_result_matcheddn = 0;
	stub_parse_result_text = 0;

	/* n <= start, noninteractive=0 → choose NOT called, returns */
	handle_result(TEST_LD, stub_result, 0, 0, 1, 0);

	stub_parse_result_err = 0;
	return 1;
}

static int test_handle_result_recoverable_continue(void)
{
	stub_parse_result_rc = 0;
	stub_parse_result_err = LDAP_NO_SUCH_OBJECT;
	stub_parse_result_matcheddn = 0;
	stub_parse_result_text = 0;
	stub_choose_result = 'y';

	/* n > start, noninteractive=0 → choose called, returns 'y' */
	handle_result(TEST_LD, stub_result, 0, 5, 1, 0);

	stub_parse_result_err = 0;
	return 1;
}


/*
 * Group 4: log_reference
 */
static int test_log_reference_single(void)
{
	char *buf = 0;
	size_t bufsz = 0;
	FILE *s = open_memstream(&buf, &bufsz);
	char *refs[] = {"ldap://other.example.com", 0};
	stub_refs = refs;

	log_reference(TEST_LD, stub_result, s);
	fclose(s);

	ASSERT_NOT_NULL(buf);
	ASSERT(strstr(buf, "# reference to: ldap://other.example.com") != 0);

	free(buf);
	stub_refs = 0;
	return 1;
}

static int test_log_reference_multiple(void)
{
	char *buf = 0;
	size_t bufsz = 0;
	FILE *s = open_memstream(&buf, &bufsz);
	char *refs[] = {"ldap://a.example.com", "ldap://b.example.com", 0};
	stub_refs = refs;

	log_reference(TEST_LD, stub_result, s);
	fclose(s);

	ASSERT_NOT_NULL(buf);
	ASSERT(strstr(buf, "# reference to: ldap://a.example.com") != 0);
	ASSERT(strstr(buf, "# reference to: ldap://b.example.com") != 0);

	free(buf);
	stub_refs = 0;
	return 1;
}


/*
 * Group 5: search_subtree
 */
static void
reset_stubs(void)
{
	stub_search_rc = 0;
	stub_parse_result_rc = 0;
	stub_parse_result_err = 0;
	stub_parse_result_matcheddn = 0;
	stub_parse_result_text = 0;
	stub_refs = 0;
	stub_result_types = 0;
	stub_result_type_idx = 0;
	stub_choose_result = 'y';
}

static int test_search_subtree_one_entry(void)
{
	int seq[] = {LDAP_RES_SEARCH_ENTRY, LDAP_RES_SEARCH_RESULT};
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	FILE *s = tmpfile();
	cmdline cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.quiet = 1;

	reset_stubs();
	stub_result_types = seq;

	search_subtree(s, TEST_LD, offsets, "dc=example,dc=com",
		       &cmd, 0, 1, 0, 0);

	ASSERT_INT_EQ(offsets->len, 1);

	fclose(s);
	g_array_free(offsets, 1);
	return 1;
}

static int test_search_subtree_multiple_entries(void)
{
	int seq[] = {LDAP_RES_SEARCH_ENTRY, LDAP_RES_SEARCH_ENTRY,
		     LDAP_RES_SEARCH_ENTRY, LDAP_RES_SEARCH_RESULT};
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	FILE *s = tmpfile();
	cmdline cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.quiet = 1;

	reset_stubs();
	stub_result_types = seq;

	search_subtree(s, TEST_LD, offsets, "dc=example,dc=com",
		       &cmd, 0, 1, 0, 0);

	ASSERT_INT_EQ(offsets->len, 3);

	fclose(s);
	g_array_free(offsets, 1);
	return 1;
}

static int test_search_subtree_no_entries(void)
{
	int seq[] = {LDAP_RES_SEARCH_RESULT};
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	FILE *s = tmpfile();
	cmdline cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.quiet = 1;

	reset_stubs();
	stub_result_types = seq;

	search_subtree(s, TEST_LD, offsets, "dc=example,dc=com",
		       &cmd, 0, 1, 0, 0);

	ASSERT_INT_EQ(offsets->len, 0);

	fclose(s);
	g_array_free(offsets, 1);
	return 1;
}

static int test_search_subtree_with_reference(void)
{
	int seq[] = {LDAP_RES_SEARCH_ENTRY, LDAP_RES_SEARCH_REFERENCE,
		     LDAP_RES_SEARCH_RESULT};
	char *refs[] = {"ldap://other.example.com", 0};
	char *buf = 0;
	size_t bufsz = 0;
	FILE *s = open_memstream(&buf, &bufsz);
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	cmdline cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.quiet = 1;

	reset_stubs();
	stub_result_types = seq;
	stub_refs = refs;

	search_subtree(s, TEST_LD, offsets, "dc=example,dc=com",
		       &cmd, 0, 1, 0, 0);
	fclose(s);

	/* 1 entry, reference doesn't add an offset */
	ASSERT_INT_EQ(offsets->len, 1);

	/* reference was written to stream */
	ASSERT_NOT_NULL(buf);
	ASSERT(strstr(buf, "# reference to: ldap://other.example.com") != 0);

	free(buf);
	g_array_free(offsets, 1);
	return 1;
}

static int test_search_subtree_appends_offsets(void)
{
	int seq[] = {LDAP_RES_SEARCH_ENTRY, LDAP_RES_SEARCH_RESULT};
	GArray *offsets = g_array_new(0, 0, sizeof(long));
	long dummy_offset;
	FILE *s = tmpfile();
	cmdline cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.quiet = 1;

	/* Pre-populate with 2 offsets */
	dummy_offset = 100;
	g_array_append_val(offsets, dummy_offset);
	dummy_offset = 200;
	g_array_append_val(offsets, dummy_offset);

	reset_stubs();
	stub_result_types = seq;

	search_subtree(s, TEST_LD, offsets, "dc=example,dc=com",
		       &cmd, 0, 1, 0, 0);

	/* 2 pre-existing + 1 new = 3 */
	ASSERT_INT_EQ(offsets->len, 3);

	fclose(s);
	g_array_free(offsets, 1);
	return 1;
}


/*
 * main
 */
int
main(void)
{
	printf("=== search.c test suite ===\n\n");

	printf("Group 1: get_entry\n");
	TEST(get_entry_returns_entry);
	TEST(get_entry_sets_result);

	printf("\nGroup 2: discover_naming_contexts\n");
	TEST(discover_finds_contexts);
	TEST(discover_no_contexts);
	TEST(discover_single_context);

	printf("\nGroup 3: handle_result\n");
	TEST(handle_result_success);
	TEST(handle_result_no_results);
	TEST(handle_result_with_matcheddn);
	TEST(handle_result_recoverable_no_entries);
	TEST(handle_result_recoverable_continue);

	printf("\nGroup 4: log_reference\n");
	TEST(log_reference_single);
	TEST(log_reference_multiple);

	printf("\nGroup 5: search_subtree\n");
	TEST(search_subtree_one_entry);
	TEST(search_subtree_multiple_entries);
	TEST(search_subtree_no_entries);
	TEST(search_subtree_with_reference);
	TEST(search_subtree_appends_offsets);

	printf("\n%d tests: %d passed, %d failed\n",
	       tests_run, tests_passed, tests_failed);
	return tests_failed ? 1 : 0;
}
