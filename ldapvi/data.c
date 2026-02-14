/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Copyright (c) 2003,2004,2005,2006 David Lichteblau
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "common.h"

static named_array *
named_array_new(char *name)
{
	named_array *result = xalloc(sizeof(named_array));
	result->name = name;
	result->array = g_ptr_array_new();
	return result;
}

static void
named_array_free(named_array *na)
{
	free(na->name);
	g_ptr_array_free(na->array, 1);
	free(na);
}

static int
named_array_cmp(named_array *a, named_array *b)
{
	return strcmp(a->name, b->name);
}

int
named_array_ptr_cmp(const void *aa, const void *bb)
{
	named_array *a = *((named_array **) aa);
	named_array *b = *((named_array **) bb);
	return named_array_cmp(a, b);
}

/*
 * entry
 */
tentry *
entry_new(char *dn)
{
	return (tentry *) named_array_new(dn);
}

void
entry_free(tentry *entry)
{
	GPtrArray *attributes = entry_attributes(entry);
	int n = attributes->len;
	int i;

	for (i = 0; i < n; i++)
		attribute_free(g_ptr_array_index(attributes, i));
	named_array_free((named_array *) entry);
}

int
entry_cmp(tentry *e, tentry *f)
{
	return named_array_cmp((named_array *) e, (named_array *) f);
}


/*
 * value
 */
/*
 * attribute
 */
tattribute *
attribute_new(char *ad)
{
	return (tattribute *) named_array_new(ad);
}

void
attribute_free(tattribute *attribute)
{
	GPtrArray *values = attribute_values(attribute);
	int n = values->len;
	int i;

	for (i = 0; i < n; i++)
		g_array_free(g_ptr_array_index(values, i), 1);
	named_array_free((named_array *) attribute);
}

int
attribute_cmp(tattribute *a, tattribute *b)
{
	return named_array_cmp((named_array *) a, (named_array *) b);
}


/*
 * misc
 */
tattribute *
entry_find_attribute(tentry *entry, char *ad, int createp)
{
	GPtrArray *attributes = entry_attributes(entry);
	tattribute *attribute = 0;
	int i;

	for (i = 0; i < attributes->len; i++) {
		tattribute *a = g_ptr_array_index(attributes, i);
		if (!strcmp(attribute_ad(a), ad)) {
			attribute = a;
			break;
		}
	}
	if (!attribute && createp) {
		attribute = attribute_new(xdup(ad));
		g_ptr_array_add(attributes, attribute);
	}

	return attribute;
}

void
attribute_append_value(tattribute *attribute, char *data, int n)
{
	GArray *value = g_array_sized_new(0, 0, 1, n);
	g_array_append_vals(value, data, n);
	g_ptr_array_add(attribute_values(attribute), value);
}

int
attribute_find_value(tattribute *attribute, char *data, int n)
{
	int i;
	GPtrArray *values = attribute_values(attribute);
	for (i = 0; i < values->len; i++) {
		GArray *value = values->pdata[i];
		if (value->len == n && !memcmp(value->data, data, n))
			return i;
	}
	return -1;
}

int
attribute_remove_value(tattribute *a, char *data, int n)
{
	int i = attribute_find_value(a, data, n);
	if (i == -1) return i;
	g_array_free(g_ptr_array_remove_index_fast(attribute_values(a), i), 1);
	return 0;
}

/*
 * Convert a GArray of chars to a null-terminated string.
 */
char *
array2string(GArray *av)
{
	int n = av->len;
	char *str = xalloc(n + 1);
	memcpy(str, av->data, n);
	str[n] = 0;
	return str;
}

/*
 * allocate a new berval and copy LEN bytes of DATA into it
 */
static struct berval *
dup2berval(char *data, int len)
{
	struct berval *bv = xalloc(sizeof(struct berval));
	bv->bv_val = xalloc(len);
	memcpy(bv->bv_val, data, len);
	bv->bv_len = len;
	return bv;
}

void
xfree_berval(struct berval *bv)
{
	free(bv->bv_val);
	free(bv);
}

struct berval *
string2berval(GArray *s)
{
	return dup2berval(s->data, s->len);
}

struct berval *
gstring2berval(GString *s)
{
	return dup2berval(s->str, s->len);
}

LDAPMod *
attribute2mods(tattribute *attribute)
{
	GPtrArray *values = attribute_values(attribute);
	LDAPMod *m = xalloc(sizeof(LDAPMod));
	int j;

	m->mod_op = LDAP_MOD_BVALUES;
	m->mod_type = xdup(attribute_ad(attribute));
	m->mod_bvalues = xalloc(
		(1 + values->len) * sizeof(struct berval *));

	for (j = 0; j < values->len; j++)
		m->mod_bvalues[j]
			= string2berval(g_ptr_array_index(values, j));
	m->mod_bvalues[j] = 0;
	return m;
}

LDAPMod **
entry2mods(tentry *entry)
{
	GPtrArray *attributes = entry_attributes(entry);
	LDAPMod **result = xalloc((attributes->len + 1) * sizeof(LDAPMod *));
	int i;

	for (i = 0; i < attributes->len; i++)
		result[i] = attribute2mods(g_ptr_array_index(attributes, i));
	result[i] = 0;
	return result;
}
