#ifndef __MYCMS_LIST_H
#define __MYCMS_LIST_H

#define MYCMS_LIST_DECLARE(name, type, element) \
struct mycms_list_ ## name ## _s; \
typedef struct mycms_list_ ## name ## _s *mycms_list_ ## name; \
struct mycms_list_ ## name ## _s { \
	mycms_list_ ## name next; \
	type element; \
};

#endif
