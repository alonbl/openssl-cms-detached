#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/cms.h>

#include <mycms/mycms.h>

#include "mycms-certificate-private.h"

int mycms_decrypt(
	mycms mycms __attribute__((unused)),
	const mycms_certificate certificate,
	BIO *cms_in,
	BIO *data_pt,
	BIO *data_ct
) {
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED;
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (certificate == NULL) {
		goto cleanup;
	}

	if (cms_in == NULL) {
		goto cleanup;
	}

	if (data_pt == NULL) {
		goto cleanup;
	}

	if (data_ct == NULL) {
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(cms_in, NULL)) == NULL) {
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, _mycms_certificate_get_EVP_PKEY(certificate), _mycms_certificate_get_X509(certificate))) {
		goto cleanup;
	}

	if (!CMS_decrypt(cms, NULL, NULL, data_ct, data_pt, flags)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}
