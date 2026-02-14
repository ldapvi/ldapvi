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

LDAPObjectClass *
schema_get_objectclass(tschema *schema, char *name)
{
	return g_hash_table_lookup(schema->classes, name);
}

LDAPAttributeType *
schema_get_attributetype(tschema *schema, char *name)
{
	return g_hash_table_lookup(schema->types, name);
}

char *
objectclass_name(LDAPObjectClass *cls)
{
	char **names = cls->oc_names;
	if (names && *names)
		return *names;
	return cls->oc_oid;
}

char *
attributetype_name(LDAPAttributeType *at)
{
	char **names = at->at_names;
	if (names && *names)
		return *names;
	return at->at_oid;
}

static void
add_objectclass(GHashTable *classes, LDAPObjectClass *cls)
{
	int i;
	char **names = cls->oc_names;

	g_hash_table_insert(classes, cls->oc_oid, cls);
	if (names)
		for (i = 0; names[i]; i++)
			g_hash_table_insert(classes, names[i], cls);
}

static void
add_attributetype(GHashTable *types, LDAPAttributeType *at)
{
	int i;
	char **names = at->at_names;

	g_hash_table_insert(types, at->at_oid, at);
	if (names)
		for (i = 0; names[i]; i++)
			g_hash_table_insert(types, names[i], at);
}

static gboolean
strcaseequal(gconstpointer v, gconstpointer w)
{
	return strcasecmp((char *) v, (char *) w) == 0;
}

/* From GLIB - Library of useful routines for C programming, g_str_hash()
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 */
static guint
strcasehash(gconstpointer v)
{
	const signed char *p = v;
	guint32 h = tolower(*p);

	if (h)
		for (p += 1; *p != '\0'; p++)
			h = (h << 5) - h + tolower(*p);

	return h;
}

static gboolean
aux_class_entry_p(gpointer key, gpointer value, gpointer data)
{
	LDAPObjectClass *class = value;
	return !!strcmp(key, class->oc_oid);
}

static gboolean
aux_type_entry_p(gpointer key, gpointer value, gpointer data)
{
	LDAPAttributeType *at = value;
	return !!strcmp(key, at->at_oid);
}

static void
free_class(gpointer key, gpointer value, gpointer data)
{
	ldap_objectclass_free(value);
}

static void
free_type(gpointer key, gpointer value, gpointer data)
{
	ldap_attributetype_free(value);
}

void
schema_free(tschema *schema)
{
	g_hash_table_foreach_steal(schema->classes, aux_class_entry_p, 0);
	g_hash_table_foreach_steal(schema->types, aux_type_entry_p, 0);

	g_hash_table_foreach(schema->classes, free_class, 0);
	g_hash_table_foreach(schema->types, free_type, 0);

	g_hash_table_destroy(schema->classes);
	g_hash_table_destroy(schema->types);
	free(schema);
}

tschema *
schema_new(LDAP *ld)
{
	LDAPMessage *result, *entry;
	char **values;
	char *subschema_dn;
	int code;
	const char *errp;
	char *attrs[2] = {"subschemaSubentry", 0};
	tschema *schema;

	if (ldap_search_s(ld, "", LDAP_SCOPE_BASE, 0, attrs, 0, &result)) {
		ldap_perror(ld, "ldap_search");
		return 0;
	}
	if ( !(entry = ldap_first_entry(ld, result))) {
		ldap_perror(ld, "ldap_first_entry");
		return 0;
	}
	values = ldap_get_values(ld, entry, "subschemaSubentry");
	if (!values) {
		fputs("subschemaSubentry attribute not found.", stderr);
		ldap_msgfree(result);
		return 0;
	}
	subschema_dn = xdup(*values);
	ldap_value_free(values);
	ldap_msgfree(result);

	entry = get_entry(ld, subschema_dn, &result);
	free(subschema_dn);
	values = ldap_get_values(ld, entry, "objectClasses");

	schema = xalloc(sizeof(tschema));
	schema->classes = g_hash_table_new(strcasehash, strcaseequal);
	schema->types = g_hash_table_new(strcasehash, strcaseequal);

	if (values) {
		char **ptr = values;
		for (ptr = values; *ptr; ptr++) {
			LDAPObjectClass *cls
				= ldap_str2objectclass(*ptr, &code, &errp, 0);
			if (cls)
				add_objectclass(schema->classes, cls);
                        else
                                fprintf(stderr,
                                        "Warning: Cannot parse class: %s\n",
                                        ldap_scherr2str(code));
		}
		ldap_value_free(values);
	}
	values = ldap_get_values(ld, entry, "attributeTypes");
	if (values) {
		char **ptr = values;
		for (ptr = values; *ptr; ptr++) {
			LDAPAttributeType *at
				= ldap_str2attributetype(
					*ptr, &code, &errp, 0);
			if (at)
                                add_attributetype(schema->types, at);
                        else
                                fprintf(stderr,
                                        "Warning: Cannot parse type: %s\n",
                                        ldap_scherr2str(code));
		}
		ldap_value_free(values);
	}
	ldap_msgfree(result);
	return schema;
}

tentroid *
entroid_new(tschema *schema)
{
	tentroid *result = xalloc(sizeof(tentroid));
	result->schema = schema;
	result->classes = g_ptr_array_new();
	result->must = g_ptr_array_new();
	result->may = g_ptr_array_new();
	result->structural = 0;
	result->comment = g_string_sized_new(0);
	result->error = g_string_sized_new(0);
	return result;
}

void
entroid_reset(tentroid *entroid)
{
	g_ptr_array_set_size(entroid->classes, 0);
	g_ptr_array_set_size(entroid->must, 0);
	g_ptr_array_set_size(entroid->may, 0);
	entroid->structural = 0;
	g_string_truncate(entroid->comment, 0);
	g_string_truncate(entroid->error, 0);
}

void
entroid_free(tentroid *entroid)
{
	g_ptr_array_free(entroid->classes, 1);
	g_ptr_array_free(entroid->must, 1);
	g_ptr_array_free(entroid->may, 1);
	g_string_free(entroid->comment, 1);
	g_string_free(entroid->error, 1);
	free(entroid);
}

LDAPObjectClass *
entroid_get_objectclass(tentroid *entroid, char *name)
{
	LDAPObjectClass *cls = schema_get_objectclass(entroid->schema, name);
	if (!cls) {
		g_string_assign(entroid->error,
				"Error: Object class not found: ");
		g_string_append(entroid->error, name);
		g_string_append_c(entroid->error, '\n');
	}
	return cls;
}

LDAPAttributeType *
entroid_get_attributetype(tentroid *entroid, char *name)
{
	LDAPAttributeType *at
		= schema_get_attributetype(entroid->schema, name);
	if (!at) {
		g_string_assign(entroid->error,
				"Error: Attribute type not found: ");
		g_string_append(entroid->error, name);
		g_string_append_c(entroid->error, '\n');
	}
	return at;
}

LDAPObjectClass *
entroid_request_class(tentroid *entroid, char *name)
{
	LDAPObjectClass *cls = entroid_get_objectclass(entroid, name);
	if (cls)
		adjoin_ptr(entroid->classes, cls);
	return cls;
}

int
entroid_remove_ad(tentroid *entroid, char *ad)
{
	LDAPAttributeType *at;
	char *name;
	char *s = strchr(ad, ';');
	int found;

	if (s) {
		int n = s - ad;
		name = xalloc(n + 1);
		memcpy(name, ad, n);
	} else
		name = ad;

	if ( !(at = entroid_get_attributetype(entroid, name)))
		return 0;
	found = g_ptr_array_remove(entroid->must, at);
	found |= g_ptr_array_remove(entroid->may, at);

	if (name != ad)
		free(name);
	return found;
}

static int
compute_entroid_1(tentroid *entroid, LDAPObjectClass *cls)
{
	char **ptr;

	for (ptr = cls->oc_sup_oids; ptr && *ptr; ptr++)
		if (!entroid_request_class(entroid, *ptr))
			return -1;
	if (cls->oc_kind == LDAP_SCHEMA_STRUCTURAL) {
		char *str;
		if (entroid->structural)
			str = "### WARNING: extra structural object class: ";
		else {
			str = "# structural object class: ";
			entroid->structural = cls;
		}
		g_string_append(entroid->comment, str);
		g_string_append(entroid->comment, objectclass_name(cls));
		g_string_append_c(entroid->comment, '\n');
	}
	for (ptr = cls->oc_at_oids_must; ptr && *ptr; ptr++) {
		LDAPAttributeType *at
			= entroid_get_attributetype(entroid, *ptr);
		if (!at) return -1;
		g_ptr_array_remove(entroid->may, at);
		adjoin_ptr(entroid->must, at);
	}
	for (ptr = cls->oc_at_oids_may; ptr && *ptr; ptr++) {
		int i;
		LDAPAttributeType *at
			= entroid_get_attributetype(entroid, *ptr);
		if (!at) return -1;
		for (i = 0; i < entroid->must->len; i++)
			if (at == g_ptr_array_index(entroid->must, i))
				break;
		if (i >= entroid->must->len)
			g_ptr_array_add(entroid->may, at);
	}
	return 0;
}

/*
 * Add all superclasses to entroid->classes; add required and optional
 * attributes to entroid->must, entroid->may.  Set entroid->structural
 * to the structural objectclass, if any.  Extra trace output for user
 * display in entroid->comment;
 *
 * Return 0 on success, -1 else.
 * Error message, if any, in entroid->error.
 */
int
compute_entroid(tentroid *entroid)
{
	int i;
	for (i = 0; i < entroid->classes->len; i++) {
		LDAPObjectClass *cls = g_ptr_array_index(entroid->classes, i);
		if (compute_entroid_1(entroid, cls) == -1)
			return -1;
	}
	if (!entroid->structural)
		g_string_append(entroid->comment,
				"### WARNING:"
				" no structural object class specified!\n");
	return 0;
}
