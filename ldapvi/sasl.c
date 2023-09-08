/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 *
 * Copyright (c) 2006 David Lichteblau
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
#include <curses.h>
#include <signal.h>
#include <term.h>
#include "config.h"
#ifdef HAVE_SASL
#include <sasl/sasl.h>
#endif
#include "common.h"

tsasl_defaults *
sasl_defaults_new(bind_options *bind_options)
{
	struct sasl_defaults *result = xalloc(sizeof(tsasl_defaults));
	result->bind_options = bind_options;
	result->scratch = g_ptr_array_new();
	result->fd = -1;
	return result;
}

void
sasl_defaults_free(tsasl_defaults *sd)
{
	GPtrArray *scratch = sd->scratch;
	int i;

	for (i = 0; i < scratch->len; i++)
		free(g_ptr_array_index(scratch, i));
	g_ptr_array_free(sd->scratch, 1);
	free(sd);
}

void
init_sasl_redirection(tsasl_defaults *defaults, char *pathname)
{
	int fd = open(pathname, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) syserr();
	fflush(stdout);
	defaults->out = dup(1);
	defaults->err = dup(2);
	defaults->fd = fd;
	defaults->pathname = pathname;
	dup2(defaults->fd, 1);
	dup2(defaults->fd, 2);
}

void
finish_sasl_redirection(tsasl_defaults *defaults)
{
	dup2(defaults->out, 1);
	dup2(defaults->err, 2);
	close(defaults->out);
	close(defaults->err);
	if (lseek(defaults->fd, 0, SEEK_SET) != 0) syserr();
	fdcp(defaults->fd, 2);
	close(defaults->fd);
	defaults->fd = -1;
}

#ifndef HAVE_SASL

#warning SASL support disabled

int
ldapvi_sasl_interact(LDAP *ld, unsigned flags, void *de, void *in)
{
	fputs("Error: ldapvi compiled without SASL support.\n", stderr);
        return LDAP_OTHER;
}

#else

static int
process_default(sasl_interact_t *interact, tsasl_defaults *defaults)
{
	char *result;

	switch (interact->id) {
	case SASL_CB_GETREALM:
		result = defaults->bind_options->sasl_realm;
		break;
	case SASL_CB_AUTHNAME:
		result = defaults->bind_options->sasl_authcid;
		break;
	case SASL_CB_PASS:
		result = defaults->bind_options->password;
		break;
	case SASL_CB_USER:
		result = defaults->bind_options->sasl_authzid;
		break;
	default:
		result = (char *) interact->defresult;
		break;
	}

	if (result && *result) {
		interact->result = result;
		interact->len = strlen(result);
		return 1;
	} else {
		interact->result = "";
		return interact->id == SASL_CB_USER;
	}
}

static void
process_result(int id, char *result, tsasl_defaults *defaults)
{
	switch (id) {
	case SASL_CB_GETREALM:
		defaults->bind_options->sasl_realm = result;
		break;
	case SASL_CB_AUTHNAME:
		defaults->bind_options->sasl_authcid = result;
		break;
	case SASL_CB_PASS:
		defaults->bind_options->password = result;
		break;
	case SASL_CB_USER:
		defaults->bind_options->sasl_authzid = result;
		break;
	default:
		g_ptr_array_add(defaults->scratch, result);
	}
}

static int
challengep(int id)
{
	return id == SASL_CB_ECHOPROMPT || id == SASL_CB_NOECHOPROMPT;
}

static int
interact_mode(int id)
{
	if (id == SASL_CB_PASS || id == SASL_CB_NOECHOPROMPT)
		return DIALOG_PASSWORD;
	return DIALOG_DEFAULT;
}

int
ldapvi_sasl_interact(LDAP *ld, unsigned flags, void *de, void *in)
{
	tsasl_defaults *defaults = de;
	sasl_interact_t *interact = in;
	tdialog *d;
	int redirected = defaults->fd != -1;
	int force_interactive = 0;
	int i, j, start;
	int n = 0, m = 0;

	while (interact[n].id != SASL_CB_LIST_END) {
		n++;
		if (challengep(interact[n].id))
			m++;
	}

	for (i = 0; i < n; i++)
		if (!process_default(&interact[i], defaults))
			force_interactive = 1;

	if (force_interactive) {
		if (flags == LDAP_SASL_QUIET)
			return LDAP_OTHER;
	} else
		if (flags != LDAP_SASL_INTERACTIVE)
			return LDAP_SUCCESS;

	if (redirected)
		finish_sasl_redirection(defaults);

	d = xalloc(sizeof(tdialog) * (n + m));
	start = -1; /* authcid if unset, else password if any, else first */
	j = 0;
	for (i = 0; i < n; i++) {
		char *value = (char *) interact[i].result;
		char *prompt = (char *) interact[i].prompt;
		if (!strncmp(prompt, "Please enter your ", 18))
			prompt += 18;
		if (challengep(interact[i].id))
			init_dialog(&d[j++],
				    DIALOG_CHALLENGE,
				    "Challenge",
				    (char *) interact[i].challenge);
		switch (interact[i].id) {
		case SASL_CB_AUTHNAME: if (!value || !*value) start = j; break;
		case SASL_CB_PASS: if (start == -1) start = j; break;
		}
		init_dialog(&d[j++],
			    interact_mode(interact[i].id),
			    prompt,
			    value);
	}

	dialog("--- SASL login", d, n + m, start == -1 ? 0 : start);
	j = 0;
	for (i = 0; i < n; i++) {
		char *value;

		while (d[j].mode == DIALOG_CHALLENGE) j++;
		if ( (value = d[j++].value))
			process_result(interact[i].id, value, defaults);
		else
			value = "";
		interact[i].result = value;
		interact[i].len = strlen(value);
	}
	free(d);

	if (redirected)
		init_sasl_redirection(defaults, defaults->pathname);
	return LDAP_SUCCESS;
}

#endif
