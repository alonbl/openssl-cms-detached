#ifndef __MYCMS_SYSTEM_H
#define __MYCMS_SYSTEM_H

#include <stdlib.h>

#define MYCMS_SYSTEM_CONTEXT_SIZE 1024

struct mycms_system_s;
typedef struct mycms_system_s *mycms_system;

typedef int (*mycms_system_driver_cleanse)(
	const mycms_system system,
	void * const p,
	const size_t size
);

typedef void *(*mycms_system_driver_malloc)(
	const mycms_system system,
	const size_t size
);

typedef void *(*mycms_system_driver_realloc)(
	const mycms_system system,
	void * const p,
	const size_t size
);

typedef int (*mycms_system_driver_free)(
	const mycms_system system,
	void * const p
);

size_t
mycms_system_get_context_size(void);

int
mycms_system_init(
	const mycms_system system,
	const size_t size
);

int
mycms_system_clean(
	const mycms_system system
);

const void *
mycms_system_get_userdata(
	const mycms_system system
);

int
mycms_system_set_userdata(
	const mycms_system system,
	const void *userdata
);

mycms_system_driver_cleanse
mycms_system_get_cleanse(
	const mycms_system system
);

int
mycms_system_set_cleanse(
	const mycms_system system,
	const mycms_system_driver_cleanse cleanse
);

mycms_system_driver_malloc
mycms_system_get_malloc(
	const mycms_system system
);

int
mycms_system_set_malloc(
	const mycms_system system,
	const mycms_system_driver_malloc malloc
);

mycms_system_driver_realloc
mycms_system_get_realloc(
	const mycms_system system
);

int
mycms_system_set_realloc(
	const mycms_system system,
	const mycms_system_driver_realloc realloc
);

mycms_system_driver_free
mycms_system_get_free(
	const mycms_system system
);

int
mycms_system_set_free(
	const mycms_system system,
	const mycms_system_driver_free free
);

int
mycms_system_cleanse(
	const mycms_system system,
	void * const p,
	const size_t size
);

void *
mycms_system_malloc(
	const mycms_system system,
	const size_t size
);

void *
mycms_system_realloc(
	const mycms_system system,
	void * const p,
	const size_t size
);

int
mycms_system_free(
	const mycms_system system,
	void * const p
);

void *
mycms_system_zalloc(
	const mycms_system system,
	const size_t size
);

char *
mycms_system_strdup(
	const mycms_system system,
	const char * const s
);

#endif
