#ifndef __MYCMS_CERTIFICATE_DRIVER_FILE_H
#define __MYCMS_CERTIFICATE_DRIVER_FILE_H

#include <mycms/mycms-certificate.h>

const char *
mycms_certificate_driver_file_usage(void);

int
mycms_certificate_driver_file_apply(
	const mycms_certificate certificate
);

#endif
