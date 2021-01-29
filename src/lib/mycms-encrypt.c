#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(ENABLE_CMS_ENCRYPT)

#include <openssl/cms.h>
#include <openssl/x509.h>

#include <mycms.h>
#include <mycms-certificate-private.h>

static
STACK_OF(CMS_RecipientInfo) *
__add_recepients(
	CMS_ContentInfo *cms,
	const mycms_blob_list to,
	int flags
) {
	STACK_OF(CMS_RecipientInfo) *ret = NULL;
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	X509 *x509 = NULL;
	mycms_blob_list t;

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
	if (x509 != NULL) {
		X509_free(x509);
	}

	if (added != NULL) {
		sk_CMS_RecipientInfo_free(added);
		added = NULL;
	}

	return ret;
}

int mycms_encrypt(
	const EVP_CIPHER *cipher,
	const mycms_blob_list to,
	BIO *cms_out,
	BIO *data_pt,
	BIO *data_ct
) {
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;

	int ret = 1;

	if ((cms = CMS_encrypt(NULL, NULL, cipher, flags)) == NULL) {
		goto cleanup;
	}

	if ((added = __add_recepients(cms, to, flags)) == NULL) {
		goto cleanup;
	}

	if (CMS_final(cms, data_pt, data_ct, flags) <= 0) {
		goto cleanup;
	}

	if (i2d_CMS_bio(cms_out, cms)  <= 0) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (added != NULL) {
		sk_CMS_RecipientInfo_free(added);
		added = NULL;
	}

	if (cms != NULL ) {
		CMS_ContentInfo_free(cms);
		cms = NULL;
	}

	return ret;
}

int mycms_encrypt_add(
	const mycms_certificate certificate,
	const mycms_blob_list to,
	BIO *cms_in,
	BIO *cms_out
) {
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;

	int ret = 1;
	int i;

	if ((cms = d2i_CMS_bio(cms_in, NULL)) == NULL) {
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

	if (CMS_final(cms, NULL, NULL, flags) <= 0) {
		goto cleanup;
	}

	if (i2d_CMS_bio(cms_out, cms)  <= 0) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (added != NULL) {
		sk_CMS_RecipientInfo_free(added);
		added = NULL;
	}

	if (cms != NULL ) {
		CMS_ContentInfo_free(cms);
		cms = NULL;
	}

	return ret;
}

#endif
