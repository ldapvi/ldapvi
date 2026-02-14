/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Shared test harness for ldapvi test suites.
 */
#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <fcntl.h>
#include <unistd.h>

extern int tests_run;
extern int tests_passed;
extern int tests_failed;

#define TEST(name) do {							\
	int _stderr_fd, _devnull, _result;				\
	tests_run++;							\
	fflush(stderr);							\
	_stderr_fd = dup(STDERR_FILENO);				\
	_devnull = open("/dev/null", O_WRONLY);				\
	dup2(_devnull, STDERR_FILENO);					\
	close(_devnull);						\
	printf("  %-60s ", #name);					\
	fflush(stdout);							\
	_result = test_##name();					\
	fflush(stderr);							\
	dup2(_stderr_fd, STDERR_FILENO);				\
	close(_stderr_fd);						\
	if (_result) { tests_passed++; printf("PASS\n"); }		\
	else { tests_failed++; printf("FAIL\n"); }			\
} while (0)

#define ASSERT(cond) do { if (!(cond)) return 0; } while (0)

#define ASSERT_STREQ(a, b) do {						\
	const char *_a = (a), *_b = (b);				\
	if (!_a || !_b || strcmp(_a, _b)) return 0;			\
} while (0)

#define ASSERT_NULL(a) ASSERT((a) == NULL)
#define ASSERT_NOT_NULL(a) ASSERT((a) != NULL)
#define ASSERT_INT_EQ(a, b) do { if ((a) != (b)) return 0; } while (0)

/* Forward declarations for parseldif.c functions */
int ldif_read_entry(FILE *, long, char **, tentry **, long *);
int ldif_peek_entry(FILE *, long, char **, long *);
int ldif_skip_entry(FILE *, long, char **);
int ldif_read_rename(FILE *, long, char **, char **, int *);
int ldif_read_delete(FILE *, long, char **);
int ldif_read_modify(FILE *, long, char **, LDAPMod ***);

/* Test suite entry points */
void run_parseldif_tests(void);
void run_diff_tests(void);
void run_parse_tests(void);
void run_print_tests(void);
void run_data_tests(void);
void run_schema_tests(void);

#endif
