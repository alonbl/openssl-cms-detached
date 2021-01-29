#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/err.h>

#include "mycms-certificate-private.h"

int
mycms_static_init(void) {
	int ret = 0;

#if defined(ENABLE_OPENSSL_ERR_STRINGS)
	ERR_load_crypto_strings();
#endif

	if (!_mycms_certificate_static_init()) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_static_free(void) {
	int ret = 1;
	ret = _mycms_certificate_static_free() && ret;
	ERR_free_strings();
	return ret;
}
