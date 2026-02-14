/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Interactive user interaction — production version.
 * Extracted from misc.c so that test binaries can link a test version.
 */
#include "common.h"
#include <curses.h>
#include <term.h>

static void
print_charbag(char *charbag)
{
	int i;
	putchar('[');
	for (i = 0; charbag[i]; i++) {
		char c = charbag[i];
		if (c > 32)
			putchar(c);
	}
	putchar(']');
}

char
choose(char *prompt, char *charbag, char *help)
{
	struct termios term;
	int c;

	if (tcgetattr(0, &term) == -1) syserr();
	term.c_lflag &= ~ICANON;
        term.c_cc[VMIN] = 1;
        term.c_cc[VTIME] = 0;
	for (;;) {
		if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
		fputs(prompt, stdout);
		putchar(' ');
		print_charbag(charbag);
		putchar(' ');
		if (strchr(charbag, c = getchar()))
			break;
		fputs("\nPlease enter one of ", stdout);
		print_charbag(charbag);
		putchar('\n');
		if (help) printf("  %s", help);
		putchar('\n');
	}
	term.c_lflag |= ICANON;
	if (tcsetattr(0, TCSANOW, &term) == -1) syserr();
	putchar('\n');
	return c;
}

static long
line_number(char *pathname, long pos)
{
	FILE *f;
	long line = 1;
	int c;

	if ( !(f = fopen(pathname, "r+"))) syserr();
	while (pos > 0) {
		switch ( c = getc_unlocked(f)) {
		case EOF:
			goto done;
		case '\n':
			if ( (c = getc_unlocked(f)) != EOF) {
				ungetc(c, f);
				line++;
			}
			/* fall through */
		default:
			pos--;
		}
	}
done:
	if (fclose(f) == EOF) syserr();
	return line;
}

void
edit(char *pathname, long line)
{
	int childpid;
	int status;
	char *vi;

	vi = getenv("VISUAL");
	if (!vi) vi = getenv("EDITOR");
	if (!vi) vi = "vi";

	switch ( (childpid = fork())) {
	case -1:
		syserr();
	case 0:
		if (line > 0) {
			char buf[20];
			snprintf(buf, 20, "+%ld", line);
			execl("/bin/sh", "sh", "-c", "exec $0 \"$@\"", vi,
			      buf, pathname, (char *) NULL);
		} else
			execl("/bin/sh", "sh", "-c", "exec $0 \"$@\"", vi,
			      pathname, (char *) NULL);
		syserr();
	}

	if (waitpid(childpid, &status, 0) == -1) syserr();
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		yourfault("editor died");
}

void
edit_pos(char *pathname, long pos)
{
	edit(pathname, pos > 0 ? line_number(pathname, pos) : -1);
}

static int
invalidp(char *ti)
{
	return ti == 0 || ti == (char *) -1;
}

void
view(char *pathname)
{
	int childpid;
	int status;
	char *pg;
	char *clear = tigetstr("clear");

	pg = getenv("PAGER");
	if (!pg) pg = "less";

	if (!invalidp(clear))
		putp(clear);

	switch ( (childpid = fork())) {
	case -1:
		syserr();
	case 0:
		execl("/bin/sh", "sh", "-c", "exec $0 \"$@\"", pg,
		      pathname, (char *) NULL);
		syserr();
	}

	if (waitpid(childpid, &status, 0) == -1) syserr();
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		puts("pager died");
}
