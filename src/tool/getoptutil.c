/**
 * @file
 * @brief getopt_long utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "getoptutil.h"

void
getoptutil_usage(
	FILE *out,
	const char * const argv0,
	const char * const extra_usage,
	const struct option * const options
) {
	const struct option *option;

	fprintf(out, "Usage: %s [options] %s\n", argv0, extra_usage);
	for (
		option = options;
		option->name != NULL;
		option++
	) {
		const char *h = option->name+strlen(option->name)+1;
		const char *k = NULL;
		char key[1024];
		const char *p;

		if ((p = strchr(h, '|')) != NULL) {
			if (p-h < (off_t)sizeof(key) - 1) {
				strncpy(key, h, p-h);
				key[p-h] = '\0';
				k = key;
				h = p+1;
			}
		}

		fprintf(out, "%2s", "");
		if (option->val < 0x100) {
			fprintf(out, "-%c, ", option->val);
		}
		else {
			fprintf(out, "%4s", "");
		}

		fprintf(out, " --%s", option->name);
		if (
			k != NULL &&
			(option->has_arg == required_argument || option->has_arg == optional_argument)
		) {
			fprintf(out, "=%s", k);
		}
		fprintf(
			out,
			"\n%12s%s\n",
			"",
			h
		);
	}
}

int
getoptutil_short_from_long(
	const struct option * const options,
	const char * const prefix,
	char * const optstring,
	size_t optstring_size
) {
	const struct option *option;

	memset(optstring, 0, optstring_size);

	if (strlen(prefix) >= optstring_size) {
		return 0;
	}
	strcpy(optstring, prefix);

	for (
		option = options;
		(
			option->name != NULL &&
			strlen(optstring) < optstring_size-4
		);
		option++
	) {
		if (option->val < 0x100) {
			optstring[strlen(optstring)] = option->val;
			switch (option->has_arg) {
				case optional_argument:
					optstring[strlen(optstring)] = ':';
					/* NO BREAK */
					__attribute__ ((fallthrough));
				case required_argument:
					optstring[strlen(optstring)] = ':';
					break;
			}
		}
	}

	return option->name == NULL;
}
