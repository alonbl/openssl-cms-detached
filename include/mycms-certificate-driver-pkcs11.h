#ifndef __MYCMS_CERTIFICATE_DRIVER_PKCS11_H
#define __MYCMS_CERTIFICATE_DRIVER_PKCS11_H

#include <mycms-certificate.h>

const char *
mycms_certificate_driver_pkcs11_usage(void);

int
mycms_certificate_driver_pkcs11_apply(
	const mycms_certificate certificate
);

#endif
