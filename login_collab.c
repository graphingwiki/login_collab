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
#include <sha2.h>

int
check_sha512_pass(const char *password, const char *salt,
		  const char *goodhash)
{
	char newhash[SHA512_DIGEST_STRING_LENGTH];
	char salted[_PW_BUF_LEN];

	salted[0] = '\0';
	strlcpy(salted, salt, _PW_BUF_LEN);
	strlcat(salted, password, _PW_BUF_LEN);

	SHA512Data((u_int8_t *)salted, strnlen(salted, _PW_BUF_LEN), newhash);

	if (strncmp(goodhash, newhash,
		    SHA512_DIGEST_STRING_LENGTH) == 0)
	    return 0;

	return -1;
}

int
pwd_login(char *htpasswd, char *username, char *password, char *wheel,
	  int lastchance, char *class)
{
	struct passwd *pwd;
	char *goodhash = NULL;
	char *salt = NULL;
	int passok = 0;
	FILE *fp;

	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	if (wheel != NULL && strcmp(wheel, "yes") != 0) {
		fprintf(back, BI_VALUE " errormsg %s\n",
		    auth_mkvalue("you are not in group wheel"));
		fprintf(back, BI_REJECT "\n");
		return (AUTH_FAILED);
	}
	if (password == NULL)
		return (AUTH_FAILED);

	if ((fp = fopen(htpasswd, "r")) == NULL)
		err(1, "%s", htpasswd);

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		if (strncmp(line, username, strlen(username)) != 0)
			continue;

		line[linelen-1] = '\0';
		line += strlen(username);
		if ((line[0] != ':') || (line[1] != '$') ||
		    (line[2] != '6') || (line[3] != '$'))
			continue;
		line += 4;
		salt = strsep(&line, "$");
		goodhash = line;
		break;
	}

	fclose(fp);

	if (!salt || !goodhash)
		return (AUTH_FAILED);

	setpriority(PRIO_PROCESS, 0, -4);
	if (check_sha512_pass(password, salt, goodhash) == 0)
		passok = 1;

	/* FIXME: zero password data here */

	if (!passok)
		return (AUTH_FAILED);

	pwd = getpwnam(username);
	if (login_check_expire(back, pwd, class, lastchance) == 0)
		fprintf(back, BI_AUTH "\n");
	else
		return (AUTH_FAILED);

	return (AUTH_OK);
}
