#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

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
