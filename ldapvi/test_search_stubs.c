/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Stubs for the test_search binary.
 * Provides replacements for LDAP library functions, schema, print,
 * error, and misc functions so that search.o can link without -lldap.
 */
#define _GNU_SOURCE
#include "common.h"

/*
 * Configurable stub state — tests set these before calling functions.
 */

/* ldap_search_s / ldap_search_ext */
int stub_search_rc = 0;
static int stub_dummy_result;
static int stub_dummy_entry;
LDAPMessage *stub_result = (LDAPMessage *) &stub_dummy_result;
LDAPMessage *stub_entry = (LDAPMessage *) &stub_dummy_entry;

/* ldap_get_dn */
char *stub_dn = "cn=test,dc=example,dc=com";

/* ldap_get_values */
char **stub_values = 0;

/* ldap_get_values_len */
struct berval **stub_bvalues = 0;

/* ldap_result sequence (NULL = always return SEARCH_RESULT) */
int *stub_result_types = 0;
int stub_result_type_idx = 0;

/* ldap_parse_result */
int stub_parse_result_rc = 0;
int stub_parse_result_err = 0;
char *stub_parse_result_matcheddn = 0;
char *stub_parse_result_text = 0;

/* ldap_parse_reference */
char **stub_refs = 0;

/* ldap_err2string */
char *stub_errstring = "Success";

/* choose */
char stub_choose_result = 'y';


/*
 * LDAP function stubs
 */
int
ldap_search_s(LDAP *ld, const char *base, int scope, const char *filter,
	      char **attrs, int attrsonly, LDAPMessage **res)
{
	(void)ld; (void)base; (void)scope; (void)filter;
	(void)attrs; (void)attrsonly;
	*res = stub_result;
	return stub_search_rc;
}

int
ldap_search_ext(LDAP *ld, const char *base, int scope, const char *filter,
		char **attrs, int attrsonly, LDAPControl **serverctrls,
		LDAPControl **clientctrls, struct timeval *timeout,
		int sizelimit, int *msgidp)
{
	(void)ld; (void)base; (void)scope; (void)filter;
	(void)attrs; (void)attrsonly; (void)serverctrls;
	(void)clientctrls; (void)timeout; (void)sizelimit;
	if (msgidp) *msgidp = 1;
	return 0;
}

int
ldap_result(LDAP *ld, int msgid, int all, struct timeval *timeout,
	    LDAPMessage **result)
{
	(void)ld; (void)msgid; (void)all; (void)timeout;
	*result = stub_result;
	if (stub_result_types)
		return stub_result_types[stub_result_type_idx++];
	return LDAP_RES_SEARCH_RESULT;
}

LDAPMessage *
ldap_first_entry(LDAP *ld, LDAPMessage *chain)
{
	(void)ld; (void)chain;
	return stub_entry;
}

char *
ldap_get_dn(LDAP *ld, LDAPMessage *entry)
{
	(void)ld; (void)entry;
	return xdup(stub_dn);
}

char **
ldap_get_values(LDAP *ld, LDAPMessage *entry, const char *target)
{
	(void)ld; (void)entry; (void)target;
	return stub_values;
}

struct berval **
ldap_get_values_len(LDAP *ld, LDAPMessage *entry, const char *target)
{
	(void)ld; (void)entry; (void)target;
	return stub_bvalues;
}

int
ldap_parse_result(LDAP *ld, LDAPMessage *res, int *errcodep,
		  char **matcheddnp, char **diagmsgp, char ***referralsp,
		  LDAPControl ***serverctrls, int freeit)
{
	(void)ld; (void)res; (void)referralsp; (void)serverctrls;
	(void)freeit;
	if (errcodep) *errcodep = stub_parse_result_err;
	if (matcheddnp) *matcheddnp = stub_parse_result_matcheddn;
	if (diagmsgp) *diagmsgp = stub_parse_result_text;
	return stub_parse_result_rc;
}

int
ldap_parse_reference(LDAP *ld, LDAPMessage *ref, char ***referralsp,
		     LDAPControl ***serverctrls, int freeit)
{
	(void)ld; (void)ref; (void)serverctrls; (void)freeit;
	if (referralsp) *referralsp = stub_refs;
	return 0;
}

void ldap_value_free(char **vals) { (void)vals; }
void ldap_value_free_len(struct berval **vals) { (void)vals; }
int ldap_msgfree(LDAPMessage *lm) { (void)lm; return 0; }
void ldap_memfree(void *p) { (void)p; }

char *
ldap_err2string(int err)
{
	(void)err;
	return stub_errstring;
}


/*
 * Schema function stubs
 */
tschema *schema_new(LDAP *ld) { (void)ld; return 0; }
void schema_free(tschema *schema) { (void)schema; }
tentroid *entroid_new(tschema *schema) { (void)schema; return 0; }
void entroid_reset(tentroid *e) { (void)e; }
void entroid_free(tentroid *e) { (void)e; }
LDAPObjectClass *entroid_request_class(tentroid *e, char *name)
{ (void)e; (void)name; return 0; }
int compute_entroid(tentroid *e) { (void)e; return 0; }


/*
 * Print function stubs
 */
void print_ldif_message(FILE *s, LDAP *ld, LDAPMessage *entry,
			int key, tentroid *e)
{ (void)s; (void)ld; (void)entry; (void)key; (void)e; }

void print_ldapvi_message(FILE *s, LDAP *ld, LDAPMessage *entry,
			  int key, tentroid *e)
{ (void)s; (void)ld; (void)entry; (void)key; (void)e; }


/*
 * Error function stubs — no-ops so tests can avoid exit() paths
 */
void ldaperr(LDAP *ld, char *str) { (void)ld; (void)str; }
void do_syserr(char *file, int line) { (void)file; (void)line; }


/*
 * Misc function stubs / real implementations
 */
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

char choose(char *prompt, char *charbag, char *help)
{
	(void)prompt; (void)charbag; (void)help;
	return stub_choose_result;
}
