#ifndef __MYCMS_CERTIFICATE_PRIVATE_H
#define __MYCMS_CERTIFICATE_PRIVATE_H

#include <openssl/x509.h>
#include <openssl/evp.h>

#include <mycms-certificate.h>

int
_mycms_certificate_static_init(void);

int
_mycms_certificate_static_free(void);

X509 *
_mycms_certificate_get_X509(
	const mycms_certificate certificate
);

EVP_PKEY *
_mycms_certificate_get_EVP_PKEY(
	const mycms_certificate certificate
);

#endif
