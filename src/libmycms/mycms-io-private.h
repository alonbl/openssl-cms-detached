#ifndef __MYCMS_IO_PRIVATE_H
#define __MYCMS_IO_PRIVATE_H

#include <openssl/bio.h>

#include <mycms/mycms-io.h>

BIO *
_mycms_io_get_BIO(
	const mycms_io io
);

#endif
