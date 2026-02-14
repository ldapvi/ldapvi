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
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

#if defined(HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/rand.h>
#elif defined(HAVE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/openssl.h>
#else
/* No crypto library; password hashing functions will be unavailable. */
#endif

#ifndef HAVE_MKDTEMP
char *
mkdtemp(char *template)
{
	int l = strlen(template);
	int i = l - 6;
	int fd;
	int n;

	if (i < 0) { errno = EINVAL; return 0; }

	fd = open("/dev/random", O_RDONLY);
	if (fd == -1) {
		fputs("Do you have /dev/random?\n", stderr);
		return 0;
	}
	while (i < l) {
		if ( (n = read(fd, template + i, l - i)) == -1) {
			close(fd);
			return 0;
		}
		while (n--) {
			unsigned char c = template[i];
			c &= 63;
			if (c < 10)		c += '0';
			else if (c < 38)	c += '?' - 10;
			else			c += 'a' - 38;
			template[i] = c;
			i++;
		}
	}
	close(fd);

	if (mkdir(template, 0700) == -1) return 0;
	return template;
}
#endif

#ifndef HAVE_ON_EXIT
static void (*onexitfunction)(int , void *) = 0;
static void *onexitarg;

static void
atexitfunction(void)
{
	onexitfunction(-1, onexitarg);
}

int
on_exit(void (*function)(int, void *), void *arg)
{
	if (onexitfunction) yourfault("on_exit called twice");
	onexitfunction = function;
	onexitarg = arg;
	return atexit(atexitfunction);
}
#endif

void g_string_append_base64(
	GString *string, unsigned char const *src, size_t srclength);

int
g_string_append_sha(GString *string, char *key)
{
#ifdef HAVE_SHA1
#if defined(HAVE_OPENSSL)
	unsigned char tmp[EVP_MAX_MD_SIZE];
	unsigned int len;
	EVP_Digest(key, strlen(key), tmp, &len, EVP_sha1(), NULL);
	g_string_append_base64(string, tmp, len);
#else
	unsigned char tmp[SHA_DIGEST_LENGTH];
	SHA1((unsigned char *) key, strlen(key), tmp);
	g_string_append_base64(string, tmp, sizeof(tmp));
#endif
	return 1;
#else
	puts("Sorry, SHA1 support not linked into ldapvi.");
	return 0;
#endif
}

int
g_string_append_ssha(GString *string, char *key)
{
#ifdef HAVE_SHA1
#if defined(HAVE_OPENSSL)
	unsigned char rand[4];
	unsigned char tmp[EVP_MAX_MD_SIZE + sizeof(rand)];
	unsigned int digest_len;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	RAND_bytes(rand, sizeof(rand));

	EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(ctx, key, strlen(key));
	EVP_DigestUpdate(ctx, rand, sizeof(rand));
	EVP_DigestFinal_ex(ctx, tmp, &digest_len);
	EVP_MD_CTX_free(ctx);

	memcpy(tmp + digest_len, rand, sizeof(rand));
	g_string_append_base64(string, tmp, digest_len + sizeof(rand));
#else
	char rand[4];
	unsigned char tmp[SHA_DIGEST_LENGTH + sizeof(rand)];
	SHA_CTX SHA1context;

	RAND_pseudo_bytes(rand, sizeof(rand));

	SHA1_Init(&SHA1context);
	SHA1_Update(&SHA1context, key, strlen(key));
	SHA1_Update(&SHA1context, rand, sizeof(rand));
	SHA1_Final(tmp, &SHA1context);

	memcpy(tmp + SHA_DIGEST_LENGTH, rand, sizeof(rand));
	g_string_append_base64(string, tmp, sizeof(tmp));
#endif
	return 1;
#else
	puts("Sorry, SHA1 support not linked into ldapvi.");
	return 0;
#endif
}

int
g_string_append_md5(GString *string, char *key)
{
#ifdef HAVE_MD5
#if defined(HAVE_OPENSSL)
	unsigned char tmp[EVP_MAX_MD_SIZE];
	unsigned int len;
	EVP_Digest(key, strlen(key), tmp, &len, EVP_md5(), NULL);
	g_string_append_base64(string, tmp, len);
#else
	unsigned char tmp[MD5_DIGEST_LENGTH];
	MD5((unsigned char *) key, strlen(key), tmp);
	g_string_append_base64(string, tmp, sizeof(tmp));
#endif
	return 1;
#else
	puts("Sorry, MD5 support not linked into ldapvi.");
	return 0;
#endif
}

int
g_string_append_smd5(GString *string, char *key)
{
#ifdef HAVE_MD5
#if defined(HAVE_OPENSSL)
	unsigned char rand[4];
	unsigned char tmp[EVP_MAX_MD_SIZE + sizeof(rand)];
	unsigned int digest_len;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	RAND_bytes(rand, sizeof(rand));

	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx, key, strlen(key));
	EVP_DigestUpdate(ctx, rand, sizeof(rand));
	EVP_DigestFinal_ex(ctx, tmp, &digest_len);
	EVP_MD_CTX_free(ctx);

	memcpy(tmp + digest_len, rand, sizeof(rand));
	g_string_append_base64(string, tmp, digest_len + sizeof(rand));
#else
	unsigned char rand[4];
	unsigned char tmp[MD5_DIGEST_LENGTH + sizeof(rand)];
	MD5_CTX MD5context;

	RAND_pseudo_bytes(rand, sizeof(rand));

	MD5_Init(&MD5context);
	MD5_Update(&MD5context, key, strlen(key));
	MD5_Update(&MD5context, rand, sizeof(rand));
	MD5_Final(tmp, &MD5context);

	memcpy(tmp + MD5_DIGEST_LENGTH, rand, sizeof(rand));
	g_string_append_base64(string, tmp, sizeof(tmp));
#endif
	return 1;
#else
	puts("Sorry, SMD5 support not linked into ldapvi.");
	return 0;
#endif
}
