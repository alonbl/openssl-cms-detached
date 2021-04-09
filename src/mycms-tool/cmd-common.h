#ifndef __MYCMS_CMD_COMMON_H
#define __MYCMS_CMD_COMMON_H

#include <mycms/mycms.h>

typedef int (*_cmd_common_certificate_driver_apply)(const mycms_certificate c);

_cmd_common_certificate_driver_apply
_cmd_common_get_certificate_driver(
	const char ** what
);

void
_cmd_common_extra_usage();

int
_cmd_common_load_cert(
	const mycms_system system,
	const char * const file,
	mycms_blob *blob
);

int
_cmd_common_passphrase_callback(
	const mycms_certificate certificate,
	const char * const what,
	char **p,
	const size_t size
);

#endif
