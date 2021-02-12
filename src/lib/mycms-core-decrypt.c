#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/cms.h>

#include <mycms/mycms.h>

#include "mycms-certificate-private.h"
#include "mycms-io-private.h"

int
mycms_decrypt(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_io cms_in,
	const mycms_io data_pt,
	const mycms_io data_ct
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

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, _mycms_certificate_get_EVP_PKEY(certificate), _mycms_certificate_get_X509(certificate))) {
		goto cleanup;
	}

	if (!CMS_decrypt(cms, NULL, NULL, _mycms_io_get_BIO(data_ct), _mycms_io_get_BIO(data_pt), flags)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}
