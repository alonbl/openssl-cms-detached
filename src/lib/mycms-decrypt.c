#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(ENABLE_CMS_DECRYPT)

#include <openssl/cms.h>

#include <mycms.h>

#include "mycms-certificate-private.h"

int mycms_decrypt(
	const mycms_certificate certificate,
	BIO *cms_in,
	BIO *data_pt,
	BIO *data_ct
) {
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED;

	int ret = 1;

	if ((cms = d2i_CMS_bio(cms_in, NULL)) == NULL) {
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, _mycms_certificate_get_EVP_PKEY(certificate), _mycms_certificate_get_X509(certificate))) {
		goto cleanup;
	}

	if (!CMS_decrypt(cms, NULL, NULL, data_ct, data_pt, flags)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (cms != NULL ) {
		CMS_ContentInfo_free(cms);
		cms = NULL;
	}

	return ret;
}

#endif
