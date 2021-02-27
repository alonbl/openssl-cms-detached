#ifndef __MYCMS_GETPASS_H
#define __MYCMS_GETPASS_H

#include <mycms/mycms.h>

const char *
mycms_getpass_usage(void);

int
mycms_getpass(
	const mycms mycms,
	const char * const title,
	const char * const prompt,
	const char * const exp,
	char * const pass,
	const size_t size
);

#endif
