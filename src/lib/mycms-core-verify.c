#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/cms.h>

#include <mycms/mycms.h>

#include "mycms-io-private.h"

static
STACK_OF(X509) *
__blob_to_x509(
	const mycms_list_blob l
) {
	mycms_list_blob t;
	STACK_OF(X509) *ret = NULL;
	STACK_OF(X509) *certs = NULL;

	if ((certs = sk_X509_new_null()) == NULL) {
		goto cleanup;
	}

	for (t = l;t != NULL;t = t->next) {
		X509 *x509;
		unsigned const char * p;

		p = t->blob.data;
		if ((x509 = d2i_X509(NULL, &p, t->blob.size)) == NULL) {
			goto cleanup;
		}

		sk_X509_push(certs, x509);
	}

	ret = certs;
	certs = NULL;

cleanup:

	sk_X509_pop_free(certs, X509_free);
	certs = NULL;

	return ret;
}

int
mycms_verify_list_free(
	const mycms mycms,
	const mycms_list_blob l
) {
	mycms_system system = NULL;
	mycms_list_blob t;
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	t = l;
	while(t != NULL) {
		mycms_list_blob x = t;
		t = x->next;
		mycms_system_free(system, x->blob.data);
		mycms_system_free(system, x);
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_verify_list(
	const mycms mycms,
	const mycms_io cms_in,
	mycms_list_blob * const keyids
) {
	mycms_system system = NULL;
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_SignerInfo) *signers = NULL;
	mycms_list_blob _keyids = NULL;
	int i;
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (cms_in == NULL) {
		goto cleanup;
	}

	if (keyids == NULL) {
		goto cleanup;
	}

	*keyids = NULL;

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		goto cleanup;
	}

	if ((signers = CMS_get0_SignerInfos(cms)) == NULL) {
		goto cleanup;
	}

	for (i = 0; i < sk_CMS_SignerInfo_num(signers); i++) {
		CMS_SignerInfo *signer = sk_CMS_SignerInfo_value(signers, i);
		ASN1_OCTET_STRING *keyid = NULL;

		if (CMS_SignerInfo_get0_signer_id(signer, &keyid, NULL, NULL)) {
			mycms_list_blob t = NULL;

			if ((t = mycms_system_zalloc(system, sizeof(*t))) == NULL) {
				goto cleanup;
			}

			t->next = _keyids;
			_keyids = t;

			_keyids->blob.size = keyid->length;
			if ((_keyids->blob.data = mycms_system_zalloc(system, _keyids->blob.size)) == NULL) {
				goto cleanup;
			}

			memcpy(_keyids->blob.data, keyid->data, _keyids->blob.size);
		}
	}

	*keyids = _keyids;
	_keyids = NULL;

	ret = 1;

cleanup:

	mycms_verify_list_free(mycms, _keyids);
	_keyids = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

int
mycms_verify(
	const mycms mycms,
	mycms_io cms_in,
	mycms_io data_in,
	const mycms_list_blob certs,
	int * const verified
) {
#if 0
	const int flags = CMS_DETACHED | CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_CONTENT_VERIFY;
	CMS_verify(cms, _certs, NULL, _mycms_io_get_BIO(data_in), NULL, flags);
#endif
	CMS_ContentInfo *cms = NULL;
	STACK_OF(X509) *_certs = NULL;
	STACK_OF(CMS_SignerInfo) *signers = NULL;
	BIO *cmsbio = NULL;
	unsigned char buf[4096];
	int i;
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (cms_in == NULL) {
		goto cleanup;
	}

	if (data_in == NULL) {
		goto cleanup;
	}

	if (verified == NULL) {
		goto cleanup;
	}

	*verified = 0;

	if ((_certs = __blob_to_x509(certs)) == NULL) {
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		goto cleanup;
	}

	if ((signers = CMS_get0_SignerInfos(cms)) == NULL) {
		goto cleanup;
	}

	if (sk_CMS_SignerInfo_num(signers) <= 0) {
		goto cleanup;
	}

	/*
	 * Do not use CMS_verify:
	 * 1. It iterates all certificates and verify signature (resources)
	 * 2. It must have access to all signer certificates
         */
	if ((cmsbio = CMS_dataInit(cms, _mycms_io_get_BIO(data_in))) == NULL) {
		goto cleanup;
	}

	{
		/*
		 * Run through input and update digest
		 */
		int x;
		while ((x = BIO_read(cmsbio, buf, sizeof(buf))) > 0);
		if (x < 0) {
			goto cleanup;
		}
	}

	ret = 1;

	for (i = 0; i < sk_X509_num(_certs); i++) {
		X509 *x509 = sk_X509_value(_certs, i);
		int f;
		int j;

		for (f = 0, j = 0; !f && j < sk_CMS_SignerInfo_num(signers); j++) {
			CMS_SignerInfo *signer = sk_CMS_SignerInfo_value(signers, j);

			if (!CMS_SignerInfo_cert_cmp(signer, x509)) {
				f = 1;
				if (CMS_SignerInfo_verify_content(signer, cmsbio) <= 0) {
					goto cleanup;
				}
			}
		}

		if (!f) {
			goto cleanup;
		}
	}

	*verified = 1;

cleanup:

	sk_X509_pop_free(_certs, X509_free);
	_certs = NULL;

	{
		BIO *tbio;
		do {
			tbio = BIO_pop(cmsbio);
			BIO_free(cmsbio);
			cmsbio = tbio;
		} while (cmsbio != NULL && cmsbio != _mycms_io_get_BIO(data_in));
	}
	cmsbio = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

