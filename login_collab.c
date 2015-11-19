/*	$OpenBSD: login_passwd.c,v 1.10 2014/09/16 22:07:02 tedu Exp $	*/

/*-
 * Copyright (c) 2001 Hans Insulander <hin@openbsd.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"

int
pwd_login(char *htpasswd, char *username, char *password, char *wheel,
	  int lastchance, char *class)
{
	struct passwd *pwd;
	char goodhash[HASH_LEN_MAX];
	char salt[SALT_LEN_MAX];
	char *hash = NULL;
	FILE *fp = NULL;
	int passok = 0;
	int userfound = 0;

	char *line = NULL, *origline = NULL;
	size_t linesize = 0;
	ssize_t linelen = 0;

	goodhash[0] = salt[0] = '\0';

	if (wheel != NULL && strcmp(wheel, "yes") != 0) {
		fprintf(back, BI_VALUE " errormsg %s\n",
		    auth_mkvalue("you are not in group wheel"));
		fprintf(back, BI_REJECT "\n");
		return (AUTH_FAILED);
	}
	if (password == NULL)
		return (AUTH_FAILED);

	/* Check if username is valid and not expired */
	pwd = getpwnam(username);
	if (!pwd)
		return (AUTH_FAILED);
	if (login_check_expire(back, pwd, class, lastchance) != 0)
		return (AUTH_FAILED);

	/* after this point we have valid and not expired username */

	if ((fp = fopen(htpasswd, "r")) == NULL)
		err(1, "%s", htpasswd);

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		origline = line;

		/* minimum valid length:
		 *     1 byte username
		 *     1 byte ':'
		 *     5 byte salt ("$6$n$")
		 *    86 bytes hash
		 *   ----------------------------
		 * =  93 bytes
		 */
		if (linelen < 93)
			continue;

		/* if getline() left '\n' in place, make it NULL */
		if (line[linelen-1] == '\n')
			line[linelen-1] = '\0';

		if (strncmp(line, username, strlen(username)) != 0)
			continue;

		if (userfound != 0) {
			userfound++;
			break; /* User found second time. FAIL */
		}

		line += strlen(username);
		if ((line[0] != ':') || (line[1] != '$') ||
		    (line[2] != '6') || (line[3] != '$'))
			continue;

		/* at this point we have found correct user */
		userfound = 1;

		line += 1;
		strlcpy(goodhash, line, HASH_LEN_MAX);

		line += 3;
		strlcpy(salt, sha512_salt_prefix, SALT_LEN_MAX);
		strlcat(salt, strsep(&line, "$"), SALT_LEN_MAX);

		break;
	}

	fclose(fp);

	if (origline) {
		explicit_bzero(origline, linesize);
		free(origline);
	}

	setpriority(PRIO_PROCESS, 0, -4);

	hash = crypt_sha512(password, salt);
	if (!hash)
		goto end;

	if (userfound > 1)
		goto end;

	if (strnlen(goodhash, HASH_LEN_MAX) < 86)
		goto end;

	if (strcmp(goodhash, hash) == 0)
		passok = 1;

end:
	explicit_bzero(salt, SALT_LEN_MAX);
	explicit_bzero(password, strlen(password));
	explicit_bzero(goodhash, HASH_LEN_MAX);

	if (hash)
		explicit_bzero(hash, strlen(hash));

	if (!passok)
		return (AUTH_FAILED);

	fprintf(back, BI_AUTH "\n");
	return (AUTH_OK);
}
