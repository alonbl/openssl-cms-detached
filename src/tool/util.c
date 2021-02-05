#ifdef __HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int
util_getpass(
	const char * const exp,
	char * const pass,
	const size_t size
) {
	static const char PASS_PASS[] = "pass:";
	static const char PASS_ENV[] = "env:";
	static const char PASS_FILE[] = "file:";
	static const char PASS_FD[] = "fd:";

	char *p;
	int ret = 0;

	if (exp == NULL || pass == NULL) {
		goto cleanup;
	}

	if ((p = strchr(exp, ':')) == NULL) {
		goto cleanup;
	}
	p++;

	if (!strncmp(exp, PASS_PASS, sizeof(PASS_PASS)-1)) {
		if (strlen(p) >= size) {
			goto cleanup;
		}
		strcpy(pass, p);
	} else if (!strncmp(exp, PASS_ENV, sizeof(PASS_ENV)-1)) {
		char *x = getenv(p);
		if (x == NULL || strlen(x) >= size) {
			goto cleanup;
		}
		strcpy(pass, x);
	} else if (!strncmp(exp, PASS_FILE, sizeof(PASS_FILE)-1)) {
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
	} else if (!strncmp(exp, PASS_FD, sizeof(PASS_FD)-1)) {
		int fd = atoi(p);
		ssize_t s;

		if ((s = read(fd, pass, size - 1)) == -1) {
			goto cleanup;
		}

		pass[s] = '\0';
		__chop(pass);
	} else {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
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

	if ((s = strdup(str)) == NULL) {
		goto cleanup;
	}

	p0 = s;

	while (p0 != NULL) {
		if ((p1 = strchr(p0, ':')) != NULL) {
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

