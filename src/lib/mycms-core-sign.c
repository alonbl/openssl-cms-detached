#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/cms.h>

#include <mycms/mycms.h>

#include "mycms-certificate-private.h"
#include "mycms-io-private.h"

int
mycms_sign(
	const mycms mycms,
	const mycms_certificate certificate,
	const char * const digest_name,
	const mycms_io cms_in,
	const mycms_io cms_out,
	const mycms_io data_in
) {
	CMS_ContentInfo *cms = NULL;
	CMS_SignerInfo *signer = NULL;
#if 0
	EVP_PKEY_CTX *ctx = NULL;
#endif
	const EVP_MD *digest = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_USE_KEYID | CMS_NOCERTS | CMS_NOSMIMECAP;
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (certificate == NULL) {
		goto cleanup;
	}

	if (digest_name == NULL) {
		goto cleanup;
	}

	if ((digest = EVP_get_digestbyname(digest_name)) == NULL) {
		goto cleanup;
	}

	if (cms_in == NULL) {
		flags |= CMS_PARTIAL;
		if ((cms = CMS_sign(NULL, NULL, NULL, NULL, flags)) == NULL) {
			goto cleanup;
		}
	} else {
		flags |= CMS_REUSE_DIGEST;
		if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
			goto cleanup;
		}
	}

	if ((signer = CMS_add1_signer(
		cms,
		_mycms_certificate_get_X509(certificate),
		_mycms_certificate_get_EVP_PKEY(certificate),
		digest,
		flags /*| CMS_KEY_PARAM */
	)) == NULL) {
		goto cleanup;
	}

	/* Does not work, see https://mta.openssl.org/pipermail/openssl-users/2021-February/013443.html */

#if 0
	if ((ctx = CMS_SignerInfo_get0_pkey_ctx(signer)) == NULL) {
		goto cleanup;
	}

	if (!EVP_PKEY_CTX_set_rsa_padding(ctx, /*RSA_PKCS1_PSS_PADDING*/ RSA_PKCS1_PADDING)) {
		goto cleanup;
	}
#endif

	if (cms_in != NULL) {
		if (!i2d_CMS_bio_stream(_mycms_io_get_BIO(cms_out), cms, _mycms_io_get_BIO(cms_in), flags)) {
			goto cleanup;
		}
	} else {
		if (!CMS_final(cms, _mycms_io_get_BIO(data_in), NULL, flags)) {
			goto cleanup;
		}
		if (i2d_CMS_bio(_mycms_io_get_BIO(cms_out), cms) <= 0) {
			goto cleanup;
		}
	}

	ret = 1;

cleanup:

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}
