#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BUILD_WINDOWS
#include <unistd.h>
#endif

#include "pinentry.h"
#include "util.h"

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

void
util_getpass_usage(
	FILE *fp,
	const char * const prefix
) {
	static const struct pass_s {
		const char *k;
		const char *u;
	} PASS_USAGE[] = {
		{"pass=string", "read passphrase from string"},
		{"env=key", "read the passphrase from environment"},
		{"file=name", "read the passphrase from file"},
#ifndef BUILD_WINDOWS
		{"fd=n", "read the passphrase from file descriptor"},
#endif
		{"pinentry=/path/to/program", "read the passphrase from gpg pinentry"},
		{NULL, NULL}
	};
	const struct pass_s *pu;

	for (pu = PASS_USAGE; pu->k != NULL; pu++) {
		fprintf(fp, "%s%-16s- %s\n", prefix, pu->k, pu->u);
	}
}

int
util_getpass(
	const char * const title,
	const char * const prompt,
	const char * const exp,
	char * const pass,
	const size_t size
) {
	static const char PASS_PASS[] = "pass=";
	static const char PASS_ENV[] = "env=";
	static const char PASS_FILE[] = "file=";
	static const char PASS_PINENTRY[] = "pinentry=";
#ifndef BUILD_WINDOWS
	static const char PASS_FD[] = "fd=";
#endif

	int ret = 0;

	if (pass == NULL) {
		goto cleanup;
	}

	if (exp == NULL) {
		*pass = '\0';
	} else if (!strncmp(exp, PASS_PASS, sizeof(PASS_PASS)-1)) {
		const char *p = exp + strlen(PASS_PASS);
		if (strlen(p) >= size) {
			goto cleanup;
		}
		strcpy(pass, p);
	} else if (!strncmp(exp, PASS_ENV, sizeof(PASS_ENV)-1)) {
		const char *p = exp + strlen(PASS_ENV);
		char *x = getenv(p);
		if (x == NULL || strlen(x) >= size) {
			goto cleanup;
		}
		strcpy(pass, x);
	} else if (!strncmp(exp, PASS_FILE, sizeof(PASS_FILE)-1)) {
		const char *p = exp + strlen(PASS_FILE);
		FILE *fp;

		if ((fp = fopen(p, "r")) != NULL) {
			char *x = fgets(pass, size, fp);
			fclose(fp);
			if (x == NULL) {
				goto cleanup;
			}
			pass[size-1] = '\0';
			__chop(pass);
		}
#ifndef BUILD_WINDOWS
	} else if (!strncmp(exp, PASS_FD, sizeof(PASS_FD)-1)) {
		const char *p = exp + strlen(PASS_FD);
		int fd = atoi(p);
		ssize_t s;

		if ((s = read(fd, pass, size - 1)) == -1) {
			goto cleanup;
		}

		pass[s] = '\0';
		__chop(pass);
#endif
	} else if (!strncmp(exp, PASS_PINENTRY, sizeof(PASS_PINENTRY)-1)) {
		const char *p = exp + strlen(PASS_PINENTRY);

		if (!pinentry_exec(p, title, prompt, pass, size)) {
			goto cleanup;
		}
	} else {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

char *
util_strchr_escape(
	const char * const s,
	const char c
) {
	const char * p = s;
	int escape = 0;

	while (*p != '\0' && (escape || *p != c)) {
		if (escape) {
			escape = 0;
		} else {
			if (*p == '\\') {
				escape = 1;
			}
		}
		p++;
	}

	return *p == '\0' ? NULL : (char *)p;
}

int
util_split_string(
	const mycms_dict dict,
	const char * const str
) {
	char *s = NULL;
	char *p0;
	char *p1;
	char *p2;
	int ret = 0;

	if (str == NULL) {
		return 1;
	}

	if ((s = strdup(str)) == NULL) {
		goto cleanup;
	}

	p0 = s;

	while (p0 != NULL) {
		if ((p1 = util_strchr_escape(p0, ':')) != NULL) {
			*p1 = '\0';
			p1++;
		}

		if ((p2 = strchr(p0, '=')) != NULL) {
			*p2 = '\0';
			p2++;

			if (!mycms_dict_entry_put(dict, p0, p2)) {
				goto cleanup;
			}
		}

		p0 = p1;
	}

	ret = 1;

cleanup:

	free(s);
	s = NULL;

	return ret;
}
