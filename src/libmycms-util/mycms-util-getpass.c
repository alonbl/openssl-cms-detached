#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BUILD_WINDOWS
#include <unistd.h>
#endif

#include <mycms/mycms-util-getpass.h>

#include "mycms-system-driver-util.h"
#include "mycms-util-pinentry.h"

static
void
__chop(const char *s) {
	if (s != NULL) {
		char *p;
		if ((p = strchr(s, '\n')) != NULL) {
			*p = '\0';
		}
		if ((p = strchr(s, '\r')) != NULL) {
			*p = '\0';
		}
	}
}

const char *
mycms_util_getpass_usage(void) {
	return (
		"PASSPHRASE EXPRESSION ATTRIBUTES\n"
		"pass=string: read passphrase from string\n"
		"env=key: read the passphrase from environment\n"
		"file=name: read the passphrase from file\n"
#ifndef BUILD_WINDOWS
		"fd=n: read the passphrase from file descriptor\n"
#endif
#ifdef ENABLE_PINENTRY
		"pinentry=/path/to/program: read the passphrase from gpg pinentry\n"
#endif
		""
	);
}

int
mycms_util_getpass(
	const mycms mycms,
	const char * const title
#ifndef ENABLE_PINENTRY
		__attribute__((unused))
#endif
	,
	const char * const prompt
#ifndef ENABLE_PINENTRY
		__attribute__((unused))
#endif
	,
	const char * const exp,
	char * const pass,
	const size_t size
) {
	static const char PASS_PASS[] = "pass=";
	static const char PASS_ENV[] = "env=";
	static const char PASS_FILE[] = "file=";
#ifndef BUILD_WINDOWS
	static const char PASS_FD[] = "fd=";
#endif
#ifdef ENABLE_PINENTRY
	static const char PASS_PINENTRY[] = "pinentry=";
#endif
	mycms_system system = NULL;
	int ret = 0;

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	if (pass == NULL) {
		goto cleanup;
	}

	if (exp == NULL) {
		*pass = '\0';
		ret = 1;
	} else if (!strncmp(exp, PASS_PASS, sizeof(PASS_PASS)-1)) {
		const char *p = exp + strlen(PASS_PASS);
		if (strlen(p) >= size) {
			goto cleanup;
		}
		strcpy(pass, p);
		ret = 1;
	} else if (!strncmp(exp, PASS_ENV, sizeof(PASS_ENV)-1)) {
		const char *p = exp + strlen(PASS_ENV);
		char *x = mycms_system_driver_util_getenv(system)(system, p);
		if (x == NULL || strlen(x) >= size) {
			goto cleanup;
		}
		strcpy(pass, x);
		ret = 1;
	} else if (!strncmp(exp, PASS_FILE, sizeof(PASS_FILE)-1)) {
		const char *p = exp + strlen(PASS_FILE);
		FILE *fp;

		if ((fp = mycms_system_driver_util_fopen(system)(system, p, "r")) != NULL) {
			char *x = mycms_system_driver_util_fgets(system)(system, pass, size, fp);
			mycms_system_driver_util_fclose(system)(system, fp);
			if (x == NULL) {
				goto cleanup;
			}
			pass[size-1] = '\0';
			__chop(pass);
		}
		ret = 1;
#ifndef BUILD_WINDOWS
	} else if (!strncmp(exp, PASS_FD, sizeof(PASS_FD)-1)) {
		const char *p = exp + strlen(PASS_FD);
		int fd = atoi(p);
		ssize_t s;

		if ((s = mycms_system_driver_util_read(system)(system, fd, pass, size - 1)) == -1) {
			goto cleanup;
		}

		pass[s] = '\0';
		__chop(pass);
		ret = 1;
#endif
#ifdef ENABLE_PINENTRY
	} else if (!strncmp(exp, PASS_PINENTRY, sizeof(PASS_PINENTRY)-1)) {
		const char *p = exp + strlen(PASS_PINENTRY);
		_mycms_pinentry pinentry = NULL;

		if ((pinentry = _mycms_util_pinentry_new(mycms)) == NULL) {
			goto cleanup1;
		}

		if (!_mycms_util_pinentry_construct(pinentry, p)) {
			goto cleanup1;
		}

		if (!_mycms_util_pinentry_exec(pinentry, title, prompt, pass, size)) {
			goto cleanup1;
		}

		ret = 1;

cleanup1:
		_mycms_util_pinentry_destruct(pinentry);

#endif
	} else {
		goto cleanup;
	}

cleanup:

	return ret;
}
