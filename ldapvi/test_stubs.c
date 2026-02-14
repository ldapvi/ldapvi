/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Shared stubs for the test suites.
 * Provides replacements for functions from misc.c, print.c, etc.
 * that would otherwise pull in readline/curses/schema dependencies.
 */
#define _GNU_SOURCE
#include "common.h"
#include "config.h"

void *xalloc(size_t size)
{
	void *p = malloc(size);
	if (!p) { perror("malloc"); abort(); }
	memset(p, 0, size);
	return p;
}

char *xdup(char *str)
{
	char *p;
	if (!str) return 0;
	p = strdup(str);
	if (!p) { perror("strdup"); abort(); }
	return p;
}

int carray_cmp(GArray *a, GArray *b)
{
	int n = a->len < b->len ? a->len : b->len;
	int rc = memcmp(a->data, b->data, n);
	if (rc) return rc;
	if (a->len < b->len) return -1;
	if (a->len > b->len) return 1;
	return 0;
}

int carray_ptr_cmp(const void *aa, const void *bb)
{
	GArray *a = *((GArray **) aa);
	GArray *b = *((GArray **) bb);
	return carray_cmp(a, b);
}

void fdcp(int fdsrc, int fddst) { (void)fdsrc; (void)fddst; }

char choose(char *prompt, char *charbag, char *help)
{
	(void)prompt; (void)charbag; (void)help;
	return 'n';
}

/* Stubs for port.c hash functions (avoids pulling in OpenSSL) */
int g_string_append_sha(GString *string, char *key)
{
	(void)key;
	g_string_append(string, "stubhash");
	return 1;
}

int g_string_append_ssha(GString *string, char *key)
{
	(void)key;
	g_string_append(string, "stubhash");
	return 1;
}

int g_string_append_md5(GString *string, char *key)
{
	(void)key;
	g_string_append(string, "stubhash");
	return 1;
}

int g_string_append_smd5(GString *string, char *key)
{
	(void)key;
	g_string_append(string, "stubhash");
	return 1;
}

/* adjoin_ptr from misc.c (schema.c needs it, misc.c not linked) */
int adjoin_ptr(GPtrArray *a, void *p)
{
	int i;
	for (i = 0; i < a->len; i++)
		if (g_ptr_array_index(a, i) == p)
			return -1;
	g_ptr_array_add(a, p);
	return i;
}

/* Stub for search.c get_entry (schema_new calls it; we never call schema_new) */
LDAPMessage *get_entry(LDAP *ld, char *dn, LDAPMessage **result)
{
	(void)ld; (void)dn; (void)result;
	return 0;
}
