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
#include <curses.h>
#include <term.h>
#include "common.h"
#include <readline/readline.h>
#include <readline/history.h>

int
carray_cmp(GArray *a, GArray *b)
{
	int d = memcmp(a->data, b->data, MIN(a->len, b->len));
	if (d) return d;
	if (a->len < b->len)
		return -1;
	else if (a->len == b->len)
		return 0;
	else
		return 1;
}

int
carray_ptr_cmp(const void *aa, const void *bb)
{
	GArray *a = *((GArray **) aa);
	GArray *b = *((GArray **) bb);
	return carray_cmp(a ,b);
}

void
fdcp(int fdsrc, int fddst)
{
	int n;
	char buf[4096];

	do {
		if ( (n = read(fdsrc, buf, sizeof(buf))) == -1) syserr();
		if (write(fddst, buf, n) != n) syserr();
	} while (n);
}

void
cp(char *src, char *dst, off_t skip, int append)
{
	int fdsrc, fddst;
	int flags = append ? O_WRONLY | O_APPEND : O_CREAT | O_EXCL | O_WRONLY;

	if ( (fdsrc = open(src, O_RDONLY)) == -1) syserr();
	if (lseek(fdsrc, skip, SEEK_SET) == -1) syserr();
	if ( (fddst = open(dst, flags, 0600)) == -1) syserr();
	fdcp(fdsrc, fddst);
	if (close(fdsrc) == -1) syserr();
	if (close(fddst) == -1) syserr();
}

void
fcopy(FILE *src, FILE *dst)
{
	int n;
	char buf[4096];

	for (;;) {
		if ( (n = fread(buf, 1, sizeof(buf), src)) == 0) {
			if (feof(src)) break;
			syserr();
		}
		if (fwrite(buf, 1, n, dst) != n) syserr();
	}
}

static int
invalidp(char *ti)
{
	return ti == 0 || ti == (char *) -1;
}

int
pipeview(int *fd)
{
	int childpid;
	char *pg;
	char *clear = tigetstr("clear");
	int fds[2];

	pg = getenv("PAGER");
	if (!pg) pg = "less";

	if (!invalidp(clear))
		putp(clear);

	if (pipe(fds) == -1) syserr();

	switch ( (childpid = fork())) {
	case -1:
		syserr();
	case 0:
		close(fds[1]);
		dup2(fds[0], 0);
		close(fds[0]);
		execl("/bin/sh", "sh", "-c", "exec $0", pg, (char *) NULL);
		syserr();
	}

	close(fds[0]);
	*fd = fds[1];
	return childpid;
}

void
pipeview_wait(int childpid)
{
	int status;

	if (waitpid(childpid, &status, 0) == -1) syserr();
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		puts("pager died");
}

char *
home_filename(char *name)
{
	char *home = getenv("HOME");
	int n;
	char *result;

	if (!home) {
		fputs("Warning: You don't have a $HOME.\n", stderr);
		return 0;
	}

	n = strlen(home);
	result = xalloc(n + 1 + strlen(name) + 1);
	strcpy(result, home);
	result[n] = '/';
	strcpy(result + n + 1, name);
	return result;
}


static char *
history_filename()
{
	return home_filename(".ldapvi_history");
}

void
read_ldapvi_history()
{
	char *filename = history_filename();
	using_history();
	if (!filename)
		return;
	if (read_history(filename) && errno != ENOENT)
		perror("Oops, couldn't read history");
	free(filename);
}

void
write_ldapvi_history()
{
	char *filename = history_filename();
	if (!filename)
		return;
	if (write_history(filename))
		perror("Oops, couldn't write history");
	free(filename);
}

char *
ldapvi_getline(char *prompt, char *value)
{
	tdialog d;
	init_dialog(&d, DIALOG_DEFAULT, prompt, value);
	dialog(0, &d, 1, 0);
	return d.value ? d.value : xdup("");
}

char *
get_password()
{
	tdialog d;
	init_dialog(&d, DIALOG_PASSWORD, "Password: ", "");
	dialog(0, &d, 1, 0);
	return d.value ? d.value : xdup("");
}

static char *readline_default;

static int
cb_set_readline_default()
{
	rl_insert_text(readline_default);
	return 0;
}

void
display_password(void)
{
	int i;
	char *backup = xalloc(rl_end + 1);
	strncpy(backup, rl_line_buffer, rl_end);
	for (i = 0; i < rl_end; i++)
		rl_line_buffer[i] = '*';
	rl_redisplay();
	strncpy(rl_line_buffer, backup, rl_end);
}

static char *
getline2(char *prompt, char *value, int password, int history)
{
	char *str;

	if (password)
		rl_redisplay_function = display_password;

	readline_default = value;
	rl_startup_hook = cb_set_readline_default;
	str = readline(prompt);
	rl_startup_hook = 0;

	if (password)
		rl_redisplay_function = rl_redisplay;

	if (str && *str && history)
		add_history(str);
	return str;
}

void
init_dialog(tdialog *d, enum dialog_mode mode, char *prompt, char *value)
{
	d->mode = mode;
	d->prompt = prompt;
	d->value = value;
}

char *
append(char *a, char *b)
{
	int k = strlen(a);
	char *result = xalloc(k + strlen(b) + 1);
	strcpy(result, a);
	strcpy(result + k, b);
	return result;
}

void *
xalloc(size_t size)
{
	void *result = malloc(size);
	if (!result) {
		write(2, "\nmalloc error\n", sizeof("\nmalloc error\n") - 1);
		_exit(2);
	}
	return result;
}

char *
xdup(char *str)
{
	char *result;

	if (!str)
		return str;
	if (!(result = strdup(str))) {
		write(2, "\nstrdup error\n", sizeof("\nstrdup error\n") - 1);
		_exit(2);
	}
	return result;
}

int
adjoin_str(GPtrArray *strs, char *str)
{
	int i;
	for (i = 0; i < strs->len; i++)
		if (!strcmp(str, g_ptr_array_index(strs, i)))
			return -1;
	g_ptr_array_add(strs, str);
	return i;
}

int
adjoin_ptr(GPtrArray *a, void *p)
{
	int i;
	for (i = 0; i < a->len; i++)
		if (g_ptr_array_index(a, i) == p)
			return -1;
	g_ptr_array_add(a, p);
	return i;
}

void
dumb_dialog(tdialog *d, int n)
{
	GString *prompt = g_string_new("");
	int i;

	for (i = 0; i < n; i++) {
		g_string_assign(prompt, d[i].prompt);
		g_string_append(prompt, ": ");
		switch (d[i].mode) {
		case DIALOG_DEFAULT:
			d[i].value = getline2(prompt->str, d[i].value, 0, 1);
			break;
		case DIALOG_PASSWORD:
			d[i].value = getline2(prompt->str, d[i].value, 1, 0);
			break;
		case DIALOG_CHALLENGE:
			printf("%s: %s\n", prompt->str, d[i].value);
			break;
		}
	}
	g_string_free(prompt, 1);
}

enum dialog_rc {
	dialog_continue, dialog_done, dialog_goto, dialog_relative,
	dialog_help, dialog_clear
};

static Keymap dialog_keymap = 0;
static Keymap dialog_empty_keymap = 0;
static enum dialog_rc dialog_action;
static int dialog_next;

static int
cb_view_pre_input()
{
	rl_done = 1;
	return 0;
}

static int
cb_dialog_done(int a, int b)
{
	rl_done = 1;
	dialog_action = dialog_done;
	return 42;
}

static int
cb_dialog_goto(int a, int b)
{
	rl_done = 1;
	dialog_action = dialog_goto;
	dialog_next = a - 1;
	return 42;
}

static int
cb_dialog_prev(int a, int b)
{
	rl_done = 1;
	dialog_action = dialog_relative;
	dialog_next = - 1;
	return 42;
}

static int
cb_dialog_next(int a, int b)
{
	rl_done = 1;
	dialog_action = dialog_relative;
	dialog_next = 1;
	return 42;
}

static int
cb_dialog_help(int a, int b)
{
	rl_done = 1;
	dialog_action = dialog_help;
	return 42;
}

static int
cb_dialog_clear(int a, int b)
{
	rl_done = 1;
	dialog_action = dialog_clear;
	return 42;
}

#define DIALOG_HELP							\
"\nEdit the lines above using standard readline commands.\n"		\
"Use RET to edit each line in turn.\n"					\
"\n"									\
"Special keys:\n"							\
"  M-RET       Finish the dialog immediately.\n"			\
"  C-p         Go back to the previous line.\n"				\
"  C-n         Go to the next line (alias for RET).\n"			\
"  M-g         With numeric prefix, go to the specified line.\n"	\
"\n"									\
"Non-password lines are saved in the history.  Standard readline\n"	\
"bindings for history access include:\n"				\
"  C-r         Incremental search through history.\n"			\
"  <up>/<down> Previous/next history entry.\n"

static void
dialog_rebuild(char *up, char *clreos,
	       char *header, char **prompts, tdialog *d, int n,
	       int target, int help)
{
	int i;

	putp(clreos);
	if (header) {
		putchar('\n');
		fputs(header, stdout);
		putchar('\n');
		fputs("Type M-h for help on key bindings.", stdout);
		putchar('\n');
		putchar('\n');
	}

	rl_pre_input_hook = cb_view_pre_input;
	for (i = 0; i < n; i++) {
		int passwordp = d[i].mode == DIALOG_PASSWORD;
		free(getline2(prompts[i], d[i].value, passwordp, 0));
		putchar('\n');
	}
	rl_pre_input_hook = 0;

	if (help) {
		fputs(DIALOG_HELP, stdout);
		for (i = 0; DIALOG_HELP[i]; i++)
			if (DIALOG_HELP[i] == '\n')
				putp(up);
	}

	for (i = 0; i < n - target; i++)
		putp(up);
}

static Keymap
set_meta_keymap(Keymap keymap, Keymap meta_keymap)
{
	if (!meta_keymap)
		meta_keymap = rl_copy_keymap((Keymap) keymap[27].function);
	keymap[27].type = ISKMAP;
	keymap[27].function = (rl_command_func_t *) meta_keymap;
}


static void
init_dialog_keymap(Keymap keymap)
{
	Keymap meta_keymap = (Keymap) keymap[27].function;
	rl_bind_key_in_map('L' - '@', cb_dialog_clear, keymap);
	rl_bind_key_in_map('P' - '@', cb_dialog_prev, keymap);
	rl_bind_key_in_map('N' - '@', cb_dialog_next, keymap);
	rl_bind_key_in_map('\r', cb_dialog_done, meta_keymap);
	rl_bind_key_in_map('g', cb_dialog_goto, meta_keymap);
	rl_bind_key_in_map('h', cb_dialog_help, meta_keymap);
}


void
dialog(char *header, tdialog *d, int n, int start)
{
	int i;
	char *up = tigetstr("cuu1");
	char *clreos = tigetstr("ed");
	char *clear = tigetstr("clear");
#if 0
	char *hsm = rl_variable_value("horizontal-scroll-mode");
#endif
	char *hsm = "off";
	Keymap original_keymap = rl_get_keymap();
	int max = 0;
	char **prompts;

	if (n == 0)
		return;

	if (invalidp(up) || invalidp(clreos) || invalidp(clear)) {
		puts("Dumb terminal.  Using fallback dialog.");
		dumb_dialog(d, n);
		return;
	}

	if (!dialog_keymap) {
		rl_initialize();
		dialog_keymap = rl_copy_keymap(original_keymap);
		dialog_empty_keymap = rl_make_bare_keymap();
		set_meta_keymap(dialog_keymap, 0);
		set_meta_keymap(dialog_empty_keymap, rl_make_bare_keymap());
		init_dialog_keymap(dialog_keymap);
		init_dialog_keymap(dialog_empty_keymap);
	}

	rl_variable_bind("horizontal-scroll-mode", "on");
	rl_inhibit_completion = 1; /* fixme */

	for (i = 0; i < n; i++)
		max = MAX(max, strlen(d[i].prompt));
	prompts = xalloc(sizeof(char *) * n);

	for (i = 0; i < n; i++) {
		char *prompt = d[i].prompt;
		int len = strlen(prompt);
		char *str = xalloc(max + 3);
		memset(str, ' ', max);
		strcpy(str + max - len, prompt);
		strcpy(str + max, ": ");
		prompts[i] = str;

		if (d[i].value)
			d[i].value = xdup(d[i].value);
	}

	dialog_rebuild(up, clreos, header, prompts, d, n, start, 0);

	i = start;
	for (;;) {
		char *orig = d[i].value;
		int passwordp = d[i].mode == DIALOG_PASSWORD;

		dialog_action = dialog_continue;
		if (d[i].mode == DIALOG_CHALLENGE)
			rl_set_keymap(dialog_empty_keymap);
		else
			rl_set_keymap(dialog_keymap);
		d[i].value = getline2(prompts[i], orig, passwordp, !passwordp);
		if (orig)
			free(orig);

		switch (dialog_action) {
		case dialog_continue:
			dialog_next = i + 1;
			break;
		case dialog_clear: /* fall through */
		case dialog_help:
			dialog_next = i;
			break;
		case dialog_relative:
			dialog_next += i;
			/* fall through */
		case dialog_goto:
			if (dialog_next < 0 || dialog_next >= n)
				dialog_next = i;
			break;
		case dialog_done:
			dialog_next = n;
			break;
		}

		if (dialog_action == dialog_clear)
			putp(clear);
		else {
			if (header)
				i += 4;
			if (dialog_action != dialog_continue)
				i--;
			do putp(up); while (i--);
		}

		dialog_rebuild(up, clreos, header, prompts, d, n, dialog_next,
			       dialog_action == dialog_help);
		if (dialog_next >= n)
			break;
		i = dialog_next;
	}

	for (i = 0; i < n; i++)
		free(prompts[i]);
	free(prompts);

	rl_set_keymap(original_keymap);
	rl_variable_bind("horizontal-scroll-mode", hsm);
	rl_inhibit_completion = 0;
}
