#ifndef __UTIL_H
#define __UTIL_H

#include  <mycms/mycms-dict.h>

char *
util_strchr_escape(
	char * const s,
	const char c
);

int
util_split_string(
	const mycms_dict dict,
	const char * const str
);

#endif
