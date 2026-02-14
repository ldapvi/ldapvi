/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Test driver - runs all test suites and prints combined report.
 */
#include <stdio.h>
#include "common.h"
#include "test_harness.h"

int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

int main(void)
{
	run_parseldif_tests();
	printf("\n");
	run_diff_tests();
	printf("\n");
	run_parse_tests();
	printf("\n");
	run_print_tests();
	printf("\n");
	run_data_tests();
	printf("\n");
	run_schema_tests();
	printf("\n");
	run_arguments_tests();

	printf("\n=== %d tests: %d passed, %d failed ===\n",
	       tests_run, tests_passed, tests_failed);
	return tests_failed > 0 ? 1 : 0;
}
