/* Copyright (c) 2003,2004,2005 David Lichteblau
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void
do_syserr(char *file, int line)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "error (%s line %d)", file, line);
	perror(buf);
	exit(1);
}

void
yourfault(char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(1);
}

void
ldaperr(LDAP *ld, char *str)
{
	int err;
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &err);
	fprintf(stderr, "%s: %s\n", str, ldap_err2string(err));
	exit(1);
}
