#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/cms.h>
#include <openssl/x509.h>

#include <mycms/mycms.h>

#include "mycms-certificate-private.h"
#include "mycms-io-private.h"

static
STACK_OF(CMS_RecipientInfo) *
__add_recepients(
	CMS_ContentInfo *cms,
	const mycms_list_blob to,
	int flags
) {
	STACK_OF(CMS_RecipientInfo) *ret = NULL;
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	X509 *x509 = NULL;
	mycms_list_blob t;

	if ((added = sk_CMS_RecipientInfo_new_null()) == NULL) {
		goto cleanup;
	}

	for (t = to;t != NULL;t = t->next) {
		CMS_RecipientInfo *ri;
		EVP_PKEY_CTX *ctx;
		unsigned const char * p;

		p = t->blob.data;
		if ((x509 = d2i_X509(NULL, &p, t->blob.size)) == NULL) {
			goto cleanup;
		}

		if ((ri = CMS_add1_recipient_cert(cms, x509, flags | CMS_KEY_PARAM)) == NULL) {
			goto cleanup;
		}

		X509_free(x509);
		x509 = NULL;

		if ((ctx = CMS_RecipientInfo_get0_pkey_ctx(ri)) == NULL) {
			goto cleanup;
		}

		if (!EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)) {
			goto cleanup;
		}

		sk_CMS_RecipientInfo_push(added, ri);
	}

	ret = added;
	added = NULL;

cleanup:
	X509_free(x509);
	x509 = NULL;

	sk_CMS_RecipientInfo_free(added);
	added = NULL;

	return ret;
}

int
mycms_encrypt(
	const mycms mycms,
	const char * const cipher_name,
	const mycms_list_blob to,
	const mycms_io cms_out,
	const mycms_io data_pt,
	const mycms_io data_ct
) {
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	const EVP_CIPHER *c = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (cipher_name == NULL) {
		goto cleanup;
	}

	if (to == NULL) {
		goto cleanup;
	}

	if (cms_out == NULL) {
		goto cleanup;
	}

	if (data_pt == NULL) {
		goto cleanup;
	}

	if (data_ct == NULL) {
		goto cleanup;
	}

	if ((c = EVP_get_cipherbyname(cipher_name)) == NULL) {
		goto cleanup;
	}

	if ((cms = CMS_encrypt(NULL, NULL, c, flags)) == NULL) {
		goto cleanup;
	}

	if ((added = __add_recepients(cms, to, flags)) == NULL) {
		goto cleanup;
	}

	if (!CMS_final(cms, _mycms_io_get_BIO(data_pt), _mycms_io_get_BIO(data_ct), flags)) {
		goto cleanup;
	}

	if (i2d_CMS_bio(_mycms_io_get_BIO(cms_out), cms)  <= 0) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	sk_CMS_RecipientInfo_free(added);
	added = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

int
mycms_encrypt_add(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_list_blob to,
	const mycms_io cms_in,
	const mycms_io cms_out
) {
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;
	int ret = 0;
	int i;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (certificate == NULL) {
		goto cleanup;
	}

	if (to == NULL) {
		goto cleanup;
	}

	if (cms_in == NULL) {
		goto cleanup;
	}

	if (cms_out == NULL) {
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, _mycms_certificate_get_EVP_PKEY(certificate), _mycms_certificate_get_X509(certificate))) {
		goto cleanup;
	}

	if ((added = __add_recepients(cms, to, flags)) == NULL) {
		goto cleanup;
	}

	for (i = 0; i < sk_CMS_RecipientInfo_num(added); i++) {
		CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(added, i);

		if (!CMS_RecipientInfo_encrypt(cms, ri)) {
			goto cleanup;
		}
	}

	if (!CMS_final(cms, NULL, NULL, flags)) {
		goto cleanup;
	}

	if (i2d_CMS_bio(_mycms_io_get_BIO(cms_out), cms)  <= 0) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	sk_CMS_RecipientInfo_free(added);
	added = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}
