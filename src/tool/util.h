#ifndef __UTIL_H
#define __UTIL_H

#include  <mycms/mycms-dict.h>

int
util_getpass(
	const char * const exp,
	char * const pass,
	const size_t size
);

char *
util_strchr_escape(
	const char * const s,
	const char c
);

int
util_split_string(
	const mycms_dict dict,
	const char * const str
);

#endif
