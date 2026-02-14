/* -*- show-trailing-whitespace: t; indent-tabs: t -*-
 * Interactive user interaction — test version.
 * Communicates with the test driver via fd 3 using a simple protocol:
 *   test-ldapvi → driver:  CHOOSE <charbag>\n
 *   driver → test-ldapvi:  CHOSE <char>\n
 *   test-ldapvi → driver:  EDIT <pathname>\n
 *   driver → test-ldapvi:  EDITED\n
 *   test-ldapvi → driver:  VIEW <pathname>\n
 *   driver → test-ldapvi:  VIEWED\n
 */
#include "common.h"

#define CONTROL_FD 3

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

static int
read_line(int fd, char *buf, int size)
{
	int i = 0;
	while (i < size - 1) {
		char c;
		int n = read(fd, &c, 1);
		if (n <= 0) break;
		if (c == '\n') break;
		buf[i++] = c;
	}
	buf[i] = '\0';
	return i;
}

char
choose(char *prompt, char *charbag, char *help)
{
	char buf[256];
	char c;
	(void)help;

	/* Echo prompt to stdout for observability */
	fputs(prompt, stdout);
	putchar(' ');
	print_charbag(charbag);
	putchar(' ');
	fflush(stdout);

	/* Send structured request on control fd */
	dprintf(CONTROL_FD, "CHOOSE %s\n", charbag);

	/* Read response */
	if (read_line(CONTROL_FD, buf, sizeof(buf)) < 7
	    || strncmp(buf, "CHOSE ", 6) != 0)
	{
		fprintf(stderr,
			"test_interactive: protocol error: "
			"expected 'CHOSE x', got '%s'\n", buf);
		abort();
	}

	c = buf[6];
	if (!strchr(charbag, c)) {
		fprintf(stderr,
			"test_interactive: '%c' not in charbag '%s'\n",
			c, charbag);
		abort();
	}

	putchar(c);
	putchar('\n');
	fflush(stdout);
	return c;
}

void
edit(char *pathname, long line)
{
	char buf[256];
	(void)line;

	fprintf(stdout, "[edit %s]\n", pathname);
	fflush(stdout);

	/* Send structured request on control fd */
	dprintf(CONTROL_FD, "EDIT %s\n", pathname);

	/* Read response */
	if (read_line(CONTROL_FD, buf, sizeof(buf)) < 6
	    || strcmp(buf, "EDITED") != 0)
	{
		fprintf(stderr,
			"test_interactive: protocol error: "
			"expected 'EDITED', got '%s'\n", buf);
		abort();
	}
}

void
edit_pos(char *pathname, long pos)
{
	edit(pathname, pos > 0 ? pos : -1);
}

void
view(char *pathname)
{
	char buf[256];

	fprintf(stdout, "[view %s]\n", pathname);
	fflush(stdout);

	/* Send structured request on control fd */
	dprintf(CONTROL_FD, "VIEW %s\n", pathname);

	/* Read response */
	if (read_line(CONTROL_FD, buf, sizeof(buf)) < 6
	    || strcmp(buf, "VIEWED") != 0)
	{
		fprintf(stderr,
			"test_interactive: protocol error: "
			"expected 'VIEWED', got '%s'\n", buf);
		abort();
	}
}
