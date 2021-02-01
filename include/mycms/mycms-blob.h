#ifndef __MYCMS_BLOB_H
#define __MYCMS_BLOB_H

#include "mycms-list.h"

struct mycms_blob_s {
	unsigned char * data;
	size_t size;
};
typedef struct mycms_blob_s mycms_blob;

MYCMS_LIST_DECLARE(blob, mycms_blob, blob)

#endif
