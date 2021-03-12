#ifndef __MYCMS_PINENTRY_H
#define __MYCMS_PINENTRY_H

#include <mycms/mycms.h>

struct _mycms_util_pinentry_s;
typedef struct _mycms_util_pinentry_s *_mycms_pinentry;


_mycms_pinentry
_mycms_util_pinentry_new(
	const mycms mycms
);

int
_mycms_util_pinentry_construct(
	const _mycms_pinentry pinentry,
	const char * const prog
);

int
_mycms_util_pinentry_destruct(
	const _mycms_pinentry pinentry
);

mycms
_mycms_util_pinentry_get_mycms(
	const _mycms_pinentry pinentry
);

int
_mycms_util_pinentry_exec(
	const _mycms_pinentry pinentry,
	const char * const title,
	const char * const prompt,
	char * const pin,
	const size_t pin_size
);

#endif
