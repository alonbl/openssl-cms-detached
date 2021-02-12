#ifndef __MYCMS_IO_H
#define __MYCMS_IO_H

#include "mycms-base.h"

struct mycms_io_s;
typedef struct mycms_io_s *mycms_io;
typedef void (*mycms_io_free_callback)(
	const mycms_io io,
	const void *p
);

mycms_io
mycms_io_new(
	const mycms mycms
);

int
mycms_io_construct(
	const mycms_io io
);

int
mycms_io_destruct(
	const mycms_io io
);

mycms
mycms_io_get_mycms(
	const mycms_io io
);

int
mycms_io_open_file(
	const mycms_io io,
	const char * const file,
	const char * const mode
);

int
mycms_io_map_mem(
	const mycms_io io,
	const void *p,
	const size_t s
);

int
mycms_io_open_mem(
	const mycms_io io
);

int
mycms_io_get_mem_ptr(
	const mycms_io io,
	char **p
);

#endif
