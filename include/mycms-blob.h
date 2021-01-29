#ifndef __MYCMS_BLOB_H
#define __MYCMS_BLOB_H

struct mycms_blob_s {
	unsigned char * data;
	size_t size;
};
typedef struct mycms_blob_s mycms_blob;

struct mycms_blob_list_s;
typedef struct mycms_blob_list_s *mycms_blob_list;
struct mycms_blob_list_s {
	mycms_blob_list next;
	mycms_blob blob;
};

#endif
