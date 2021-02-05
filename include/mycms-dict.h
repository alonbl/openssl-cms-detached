#ifndef __MYCMS_DICT_H
#define __MYCMS_DICT_H

#include "mycms-base.h"

struct mycms_dict_s;
typedef struct mycms_dict_s *mycms_dict;
typedef void (*mycms_dict_free_callback)(
	const mycms_dict dict,
	const void *p
);

mycms_dict
mycms_dict_new(
	const mycms mycms
);

int
mycms_dict_construct(
	const mycms_dict dict
);

int
mycms_dict_destroy(
	const mycms_dict dict
);

mycms
mycms_dict_get_mycms(
	const mycms_dict dict
);

int
mycms_dict_entry_clear(
	const mycms_dict dict
);

int
mycms_dict_entry_put(
	const mycms_dict dict,
	const char * const k,
	const char * const v
);

const char *
mycms_dict_entry_get(
	const mycms_dict dict,
	const char * const k,
	int * const found
);

int
mycms_dict_entry_del(
	const mycms_dict dict,
	const char * const k
);

#endif
