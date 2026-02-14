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

t_print_binary_mode print_binary_mode = PRINT_UTF8;

static void
write_backslashed(FILE *s, char *ptr, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		char c = ptr[i];
		if (c == '\n' || c == '\\') fputc('\\', s);
		fputc(c, s);
	}
	if (ferror(s)) syserr();
}

static int
utf8_string_p(unsigned char *str, int n)
{
	int i = 0;
	while (i < n) {
		unsigned char c = str[i++];
		if (c >= 0xfe)
			return 0;
		if (c >= 0xfc) {
			unsigned char d;
			if ((n - i < 5)
			    || ((d=str[i++]) ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (c < 0xfd && d < 0x84))
				return 0;
		} else if (c >= 0xf8) {
			unsigned char d;
			if ((n - i < 4)
			    || ((d=str[i++]) ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (c < 0xf9 && d < 0x88))
				return 0;
		} else if (c >= 0xf0) {
			unsigned char d;
			if ((n - i < 3)
			    || ((d=str[i++]) ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (str[i++] ^ 0x80) >= 0x40
			    || (c < 0xf1 && d < 0x90))
				return 0;
		} else if (c >= 0xe0) {
			unsigned char d, e;
			unsigned code;
			if ((n - i < 2)
			    || ((d=str[i++]) ^ 0x80) >= 0x40
			    || ((e=str[i++]) ^ 0x80) >= 0x40
			    || (c < 0xe1 && d < 0xa0))
				return 0;
			code = ((int) c & 0x0f) << 12
				| ((int) d ^ 0x80) << 6
				| ((int) e ^ 0x80);
			if ((0xd800 <= code) && (code <= 0xdfff)
			    || code == 0xfffe || code == 0xffff)
				return 0;
		} else if (c >= 0x80) {
			unsigned char d;
			if ((n - i < 1)
			    || ((d=str[i++]) ^ 0x80) >= 0x40
			    || (c < 0xc2))
				return 0;
		} else if (c == 0)
			return 0;
	}
	return 1;
}

static int
readable_string_p(char *str, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		char c = str[i];
		if (c < 32 && c != '\n' && c != '\t')
			return 0;
	}
	return 1;
}

static int
safe_string_p(char *str, int n)
{
	unsigned char c;
	int i;

	if (n == 0) return 1;

	c = str[0];
	if ((c == ' ') || (c == ':') || (c == '<'))
		return 0;

	for (i = 0; i < n; i++) {
		c = str[i];
		if ((c == '\0') || (c == '\r') || (c == '\n') || (c >= 0x80))
			return 0;
	}
	return 1;
}

static void
print_attrval(FILE *s, char *str, int len, int prefernocolon)
{
	int readablep;
	switch (print_binary_mode) {
	case PRINT_ASCII:
		readablep = readable_string_p(str, len);
		break;
	case PRINT_UTF8:
		readablep = utf8_string_p((unsigned char *) str, len);
		break;
	case PRINT_JUNK:
		readablep = 1;
		break;
	default:
		abort();
	}

	if (!readablep) {
		fputs(":: ", s);
		print_base64((unsigned char *) str, len, s);
	} else if (prefernocolon) {
		fputc(' ', s);
		write_backslashed(s, str, len);
	} else if (!safe_string_p(str, len)) {
		fputs(":; ", s);
		write_backslashed(s, str, len);
	} else {
		fputs(": ", s);
		fwrite(str, 1, len, s);
	}
}

static void
print_attribute(FILE *s, tattribute *attribute)
{
	GPtrArray *values = attribute_values(attribute);
	int j;

	for (j = 0; j < values->len; j++) {
		GArray *av = g_ptr_array_index(values, j);
		fputs(attribute_ad(attribute), s);
		print_attrval(s, av->data, av->len, 0);
		fputc('\n', s);
	}
	if (ferror(s)) syserr();
}

static void
print_entroid_bottom(FILE *s, tentroid *entroid)
{
	int i;
	LDAPAttributeType *at;
	for (i = 0; i < entroid->must->len; i++) {
		at = g_ptr_array_index(entroid->must, i);
		fprintf(s, "# required attribute not shown: %s\n",
			attributetype_name(at));
	}
	for (i = 0; i < entroid->may->len; i++) {
		at = g_ptr_array_index(entroid->may, i);
		fprintf(s, "#%s: \n", attributetype_name(at));
	}
}

void
print_ldapvi_entry(FILE *s, tentry *entry, char *key, tentroid *entroid)
{
	GPtrArray *attributes = entry_attributes(entry);
	int i;

	fputc('\n', s);
	fputs(key ? key : "entry", s);
	fputc(' ', s);
	fputs(entry_dn(entry), s);
	fputc('\n', s);
	if (ferror(s)) syserr();

	if (entroid)
		fputs(entroid->comment->str, s);
	for (i = 0; i < attributes->len; i++) {
		tattribute *attribute = g_ptr_array_index(attributes, i);
		char *ad = attribute_ad(attribute);
		if ( entroid && !entroid_remove_ad(entroid, ad))
			fprintf(s, "# WARNING: %s not allowed by schema\n",
				ad);
		print_attribute(s, attribute);
	}
	if (entroid)
		print_entroid_bottom(s, entroid);
}

static void
print_ldapvi_ldapmod(FILE *s, LDAPMod *mod)
{
	struct berval **values = mod->mod_bvalues;

	switch (mod->mod_op & ~LDAP_MOD_BVALUES) {
	case LDAP_MOD_ADD: fputs("add", s); break;
	case LDAP_MOD_DELETE: fputs("delete", s); break;
	case LDAP_MOD_REPLACE: fputs("replace", s); break;
	default: abort();
	}
	print_attrval(s, mod->mod_type, strlen(mod->mod_type), 0);
	fputc('\n', s);
	for (; *values; values++) {
		struct berval *value = *values;
		print_attrval(s, value->bv_val, value->bv_len, 0);
		fputc('\n', s);
	}
	if (ferror(s)) syserr();
}

void
print_ldapvi_modify(FILE *s, char *dn, LDAPMod **mods)
{
	fputs("\nmodify", s);
	print_attrval(s, dn, strlen(dn), 1);
	fputc('\n', s);

	for (; *mods; mods++)
		print_ldapvi_ldapmod(s, *mods);
	if (ferror(s)) syserr();
}

void
print_ldapvi_rename(FILE *s, char *olddn, char *newdn, int deleteoldrdn)
{
	fputs("\nrename", s);
	print_attrval(s, olddn, strlen(olddn), 1);
	fputs(deleteoldrdn ? "\nreplace" : "\nadd", s);
	print_attrval(s, newdn, strlen(newdn), 0);
	fputc('\n', s);
	if (ferror(s)) syserr();
}

static GString *
rdns2gstring(char **ptr)
{
	GString *result = g_string_new("");
	if (*ptr)
		g_string_append(result, *ptr);
	ptr++;
	for (; *ptr; ptr++) {
		g_string_append_c(result, ',');
		g_string_append(result, *ptr);
	}
	return result;
}

/* simple version of _rename without new superior */
void
print_ldapvi_modrdn(FILE *s, char *olddn, char *newrdn, int deleteoldrdn)
{
	char **newrdns = ldap_explode_dn(olddn, 0);
	GString *newdn;
	char *tmp;

	fputs("\nrename", s);
	print_attrval(s, olddn, strlen(olddn), 1);
	fputs(deleteoldrdn ? "\nreplace" : "\nadd", s);

	/* fixme: see notes */
	tmp = *newrdns;
	*newrdns = newrdn;
	newdn = rdns2gstring(newrdns);
	print_attrval(s, newdn->str, newdn->len, 0);
	fputc('\n', s);
	g_string_free(newdn, 1);
	*newrdns = tmp;

	if (ferror(s)) syserr();
	ldap_value_free(newrdns);
}

void
print_ldapvi_add(FILE *s, char *dn, LDAPMod **mods)
{
	fputs("\nadd", s);
	print_attrval(s, dn, strlen(dn), 1);
	fputc('\n', s);

	for (; *mods; mods++) {
		LDAPMod *mod = *mods;
		struct berval **values = mod->mod_bvalues;
		for (; *values; values++) {
			struct berval *value = *values;
			fputs(mod->mod_type, s);
			print_attrval(s, value->bv_val, value->bv_len, 0);
			fputc('\n', s);
		}
	}
	if (ferror(s)) syserr();
}

void
print_ldapvi_delete(FILE *s, char *dn)
{
	fputs("\ndelete", s);
	print_attrval(s, dn, strlen(dn), 1);
	fputc('\n', s);
	if (ferror(s)) syserr();
}

static void
print_ldif_line(FILE *s, char *ad, char *str, int len)
{
	if (len == -1)
		len = strlen(str);
	fputs(ad, s);
	if (safe_string_p(str, len)) {
		fputs(": ", s);
		fwrite(str, len, 1, s);
	} else {
		fputs(":: ", s);
		print_base64((unsigned char *) str, len, s);
	}
	fputs("\n", s);
}

static void
print_ldif_bervals(FILE *s, char *ad, struct berval **values)
{
	for (; *values; values++) {
		struct berval *value = *values;
		print_ldif_line(s, ad, value->bv_val, value->bv_len);
	}
	if (ferror(s)) syserr();
}

void
print_ldif_modify(FILE *s, char *dn, LDAPMod **mods)
{
	fputc('\n', s);
	print_ldif_line(s, "dn", dn, -1);
	fputs("changetype: modify\n", s);

	for (; *mods; mods++) {
		LDAPMod *mod = *mods;

		switch (mod->mod_op & ~LDAP_MOD_BVALUES) {
		case LDAP_MOD_ADD: fputs("add: ", s); break;
		case LDAP_MOD_DELETE: fputs("delete: ", s); break;
		case LDAP_MOD_REPLACE: fputs("replace: ", s); break;
		default: abort();
		}
		fputs(mod->mod_type, s);
		fputc('\n', s);

		print_ldif_bervals(s, mod->mod_type, mod->mod_bvalues);
		fputs("-\n", s);
	}
	if (ferror(s)) syserr();
}

void
print_ldif_add(FILE *s, char *dn, LDAPMod **mods)
{
	fputc('\n', s);
	print_ldif_line(s, "dn", dn, -1);
	fputs("changetype: add\n", s);

	for (; *mods; mods++) {
		LDAPMod *mod = *mods;
		print_ldif_bervals(s, mod->mod_type, mod->mod_bvalues);
	}
	if (ferror(s)) syserr();
}

void
print_ldif_rename(FILE *s, char *olddn, char *newdn, int deleteoldrdn)
{
	char **newrdns = ldap_explode_dn(newdn, 0);
	int isRootDSE = !*newrdns;
	GString *sup;

	fputc('\n', s);
	print_ldif_line(s, "dn", olddn, -1);
	fputs("changetype: modrdn\n", s);

	print_ldif_line(s, "newrdn", isRootDSE ? "" : *newrdns, -1);

	fprintf(s, "deleteoldrdn: %d\n", !!deleteoldrdn);

	if (isRootDSE || !newrdns[1])
		fputs("newsuperior:\n", s);
	else {
		sup = rdns2gstring(newrdns + 1);
		print_ldif_line(s, "newsuperior", sup->str, sup->len);
		g_string_free(sup, 1);
	}

	if (ferror(s)) syserr();
	ldap_value_free(newrdns);
}

/* simple version of _rename without new superior */
void
print_ldif_modrdn(FILE *s, char *olddn, char *newrdn, int deleteoldrdn)
{
	fputc('\n', s);
	print_ldif_line(s, "dn", olddn, -1);
	fputs("changetype: modrdn\n", s);
	print_ldif_line(s, "newrdn", newrdn, -1);
	fprintf(s, "deleteoldrdn: %d\n", !!deleteoldrdn);
	if (ferror(s)) syserr();
}

void
print_ldif_delete(FILE *s, char *dn)
{
	fputc('\n', s);
	print_ldif_line(s, "dn", dn, -1);
	fputs("changetype: delete\n", s);
	if (ferror(s)) syserr();
}

void
print_ldapvi_message(FILE *s, LDAP *ld, LDAPMessage *entry, int key,
		    tentroid *entroid)
{
	char *dn, *ad;
	BerElement *ber;

	fprintf(s, "\n%d", key);
	dn = ldap_get_dn(ld, entry);
	print_attrval(s, dn, strlen(dn), 1);
	ldap_memfree(dn);
	fputc('\n', s);
	if (entroid)
		fputs(entroid->comment->str, s);

	for (ad = ldap_first_attribute(ld, entry, &ber);
	     ad;
	     ad = ldap_next_attribute(ld, entry, ber))
	{
		struct berval **values = ldap_get_values_len(ld, entry, ad);
		struct berval **ptr;

		if (!values) continue;
		if (entroid)
			entroid_remove_ad(entroid, ad);

		for (ptr = values; *ptr; ptr++) {
			fputs(ad, s);
			print_attrval(s, (*ptr)->bv_val, (*ptr)->bv_len, 0);
			fputc('\n', s);
		}
		ldap_memfree(ad);
		ldap_value_free_len(values);
	}
	ber_free(ber, 0);

	if (entroid)
		print_entroid_bottom(s, entroid);
	if (ferror(s)) syserr();
}

void
print_ldif_entry(FILE *s, tentry *entry, char *key, tentroid *entroid)
{
	int i;
	GPtrArray *attributes = entry_attributes(entry);

	fputc('\n', s);
	print_ldif_line(s, "dn", entry_dn(entry), -1);
	if (key)
		fprintf(s, "ldapvi-key: %s\n", key);
	if (entroid)
		fputs(entroid->comment->str, s);
	for (i = 0; i < attributes->len; i++) {
		tattribute *attribute = g_ptr_array_index(attributes, i);
		char *ad = attribute_ad(attribute);
		GPtrArray *values = attribute_values(attribute);
		int j;

		if ( entroid && !entroid_remove_ad(entroid, ad))
			fprintf(s, "# WARNING: %s not allowed by schema\n",
				ad);

		for (j = 0; j < values->len; j++) {
			GArray *av = g_ptr_array_index(values, j);
			print_ldif_line(s, ad, av->data, av->len);
		}
	}
	if (entroid)
		print_entroid_bottom(s, entroid);
}

void
print_ldif_message(FILE *s, LDAP *ld, LDAPMessage *entry, int key,
		   tentroid *entroid)
{
	char *dn, *ad;
	BerElement *ber;

	fputc('\n', s);
	if (entroid)
		fputs(entroid->comment->str, s);

	dn = ldap_get_dn(ld, entry);
	print_ldif_line(s, "dn", dn, -1);
	ldap_memfree(dn);

	if (key != -1)
		fprintf(s, "ldapvi-key: %d\n", key);

	for (ad = ldap_first_attribute(ld, entry, &ber);
	     ad;
	     ad = ldap_next_attribute(ld, entry, ber))
	{
		struct berval **values = ldap_get_values_len(ld, entry, ad);
		if (entroid) entroid_remove_ad(entroid, ad);
		print_ldif_bervals(s, ad, values);
		ldap_memfree(ad);
		ldap_value_free_len(values);
	}
	ber_free(ber, 0);

	if (entroid)
		print_entroid_bottom(s, entroid);
	if (ferror(s)) syserr();
}
