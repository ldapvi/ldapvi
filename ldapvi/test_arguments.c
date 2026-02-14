/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Tests for arguments.c - command-line and profile argument parsing.
 *
 * Regression tests for the --base override fix: when both a profile
 * and the command line specify --base, the CLI bases should replace
 * (not append to) the profile bases.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "test_harness.h"

/*
 * test_home_dir is defined in test_stubs.c.  Setting it redirects
 * home_filename() to a temporary directory without touching $HOME.
 */
extern char *test_home_dir;

/*
 * Helpers: create a temporary directory with a .ldapvirc profile.
 */
static char tmpdir_template[] = "/tmp/ldapvi-test-XXXXXX";
static char tmpdir[sizeof(tmpdir_template)];

static void
setup_profile(const char *content)
{
	char path[512];
	FILE *f;

	strcpy(tmpdir, tmpdir_template);
	if (!mkdtemp(tmpdir)) abort();
	test_home_dir = tmpdir;

	snprintf(path, sizeof(path), "%s/.ldapvirc", tmpdir);
	f = fopen(path, "w");
	if (f) {
		fputs(content, f);
		fclose(f);
	}
}

static void
setup_no_profile(void)
{
	strcpy(tmpdir, tmpdir_template);
	if (!mkdtemp(tmpdir)) abort();
	test_home_dir = tmpdir;
	/* no .ldapvirc created */
}

static void
teardown(void)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/.ldapvirc", tmpdir);
	unlink(path);
	rmdir(tmpdir);
	test_home_dir = NULL;
}

static void
run_parse(const char **argv, int argc, cmdline *result, GPtrArray *ctrls)
{
	init_cmdline(result);
	parse_arguments(argc, argv, result, ctrls);
}


/*
 * Test 1: CLI --base only, no profile.
 * basedns should contain exactly the CLI base.
 */
static int test_cli_base_no_profile(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", "--base", "dc=cli,dc=com", NULL};

	setup_no_profile();
	run_parse(argv, 3, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 1);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0), "dc=cli,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 2: Profile base only, no CLI --base.
 * basedns should contain the profile base.
 */
static int test_profile_base_no_cli(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", "--profile", "myprofile", NULL};

	setup_profile(
		"profile: myprofile\n"
		"base: dc=profile,dc=com\n"
		"\n"
	);
	run_parse(argv, 3, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 1);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0),
		      "dc=profile,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 3: Profile base AND CLI --base.
 * The CLI base should replace the profile base (regression test).
 */
static int test_cli_base_overrides_profile(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", "--profile", "myprofile",
			      "--base", "dc=cli,dc=com", NULL};

	setup_profile(
		"profile: myprofile\n"
		"base: dc=profile,dc=com\n"
		"\n"
	);
	run_parse(argv, 5, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 1);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0), "dc=cli,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 4: Profile with multiple bases AND CLI --base.
 * All profile bases should be replaced by the CLI base.
 */
static int test_cli_base_overrides_multiple_profile_bases(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", "--profile", "myprofile",
			      "--base", "dc=cli,dc=com", NULL};

	setup_profile(
		"profile: myprofile\n"
		"base: dc=one,dc=com\n"
		"base: dc=two,dc=com\n"
		"base: dc=three,dc=com\n"
		"\n"
	);
	run_parse(argv, 5, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 1);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0), "dc=cli,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 5: Multiple CLI --base options override profile base.
 * All CLI bases should be present; profile bases gone.
 */
static int test_multiple_cli_bases_override_profile(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", "--profile", "myprofile",
			      "--base", "dc=a,dc=com",
			      "--base", "dc=b,dc=com", NULL};

	setup_profile(
		"profile: myprofile\n"
		"base: dc=profile,dc=com\n"
		"\n"
	);
	run_parse(argv, 7, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 2);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0), "dc=a,dc=com");
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 1), "dc=b,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 6: Multiple CLI --base options without a profile.
 * All should be present.
 */
static int test_multiple_cli_bases_no_profile(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi",
			      "--base", "dc=x,dc=com",
			      "--base", "dc=y,dc=com", NULL};

	setup_no_profile();
	run_parse(argv, 5, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 2);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0), "dc=x,dc=com");
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 1), "dc=y,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 7: No base specified anywhere.
 * basedns should be empty.
 */
static int test_no_base_anywhere(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", NULL};

	setup_no_profile();
	run_parse(argv, 1, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 0);

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 8: Default profile (no --profile flag) with base.
 * Should pick up the "default" profile's base.
 */
static int test_default_profile_base(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", NULL};

	setup_profile(
		"profile: default\n"
		"base: dc=default,dc=com\n"
		"\n"
	);
	run_parse(argv, 1, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 1);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0),
		      "dc=default,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * Test 9: CLI --base overrides default profile base.
 */
static int test_cli_base_overrides_default_profile(void)
{
	cmdline result;
	GPtrArray *ctrls = g_ptr_array_new();
	const char *argv[] = {"ldapvi", "--base", "dc=cli,dc=com", NULL};

	setup_profile(
		"profile: default\n"
		"base: dc=default,dc=com\n"
		"\n"
	);
	run_parse(argv, 3, &result, ctrls);

	ASSERT_INT_EQ((int) result.basedns->len, 1);
	ASSERT_STREQ(g_ptr_array_index(result.basedns, 0), "dc=cli,dc=com");

	g_ptr_array_free(ctrls, 1);
	teardown();
	return 1;
}


/*
 * run_arguments_tests
 */
void run_arguments_tests(void)
{
	printf("=== arguments.c test suite ===\n\n");

	printf("Group 1: --base without profiles\n");
	TEST(cli_base_no_profile);
	TEST(multiple_cli_bases_no_profile);
	TEST(no_base_anywhere);

	printf("\nGroup 2: --base from profile only\n");
	TEST(profile_base_no_cli);
	TEST(default_profile_base);

	printf("\nGroup 3: --base override (regression)\n");
	TEST(cli_base_overrides_profile);
	TEST(cli_base_overrides_multiple_profile_bases);
	TEST(multiple_cli_bases_override_profile);
	TEST(cli_base_overrides_default_profile);
}
