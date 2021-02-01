#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_CERTIFICATE_DRIVER_PKCS11

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms-certificate-driver-pkcs11.h>

struct mycms_certificate_pkcs11_s {
#ifndef OPENSSL_NO_RSA
	RSA *rsa;
#endif
};
typedef struct mycms_certificate_pkcs11_s *mycms_certificate_pkcs11;

static int __convert_padding(const int padding) {
	int ret;
	switch (padding) {
#ifndef OPENSSL_NO_RSA
		case MYCMS_PADDING_PKCS1:
			ret = RSA_PKCS1_PADDING;
		break;
		case MYCMS_PADDING_OEAP:
			ret = RSA_PKCS1_OAEP_PADDING;
		break;
		case MYCMS_PADDING_NONE:
			ret = RSA_NO_PADDING;
		break;
#endif
		default:
			ret = -1;
		break;
	}
	return ret;
}

static
EVP_PKEY *
__load_pkey(const char *pkcs11) {
	EVP_PKEY *k = NULL;
	BIO *bio = NULL;

	if ((bio = BIO_new_file(pkcs11, "rb")) == NULL) {
		goto cleanup;
	}

	if ((k = d2i_PrivateKey_bio(bio, NULL)) == NULL) {
		goto cleanup;
	}

cleanup:

	if (bio != NULL) {
		BIO_free(bio);
		bio = NULL;
	}

	return k;
}

#ifndef OPENSSL_NO_RSA
static
int
__driver_pkcs11_rsa_private_op(
	const mycms_certificate certificate,
	const int op,
	const unsigned char * const from,
	const size_t from_size,
	unsigned char * const to,
	const size_t to_size __attribute__((unused)),
	const int padding
) {
	mycms_certificate_pkcs11 certificate_pkcs11 = (mycms_certificate_pkcs11)mycms_certificate_get_userdata(certificate);
	int cpadding;
	const RSA_METHOD *rsa_method = NULL;
	int ret = -1;

	if ((cpadding = __convert_padding(padding)) == -1) {
		goto cleanup;
	}

	if ((rsa_method = RSA_get_method(certificate_pkcs11->rsa)) == NULL) {
		goto cleanup;
	}

	switch (op) {
		case MYCMS_PRIVATE_OP_ENCRYPT:
			ret = RSA_meth_get_priv_enc(rsa_method)(from_size, from, to, certificate_pkcs11->rsa, cpadding);
		break;
		case MYCMS_PRIVATE_OP_DECRYPT:
			ret = RSA_meth_get_priv_dec(rsa_method)(from_size, from, to, certificate_pkcs11->rsa, cpadding);
		break;
		default:
			goto cleanup;
	}

cleanup:

	return ret;
}
#endif

int
__driver_pkcs11_free(
	const mycms_certificate certificate
) {
	mycms_certificate_pkcs11 certificate_pkcs11 = (mycms_certificate_pkcs11)mycms_certificate_get_userdata(certificate);

	int ret = 1;

	if (certificate_pkcs11 != NULL) {
		#ifndef OPENSSL_NO_RSA
			if (certificate_pkcs11->rsa != NULL) {
				RSA_free(certificate_pkcs11->rsa);
				certificate_pkcs11->rsa = NULL;
			}
		#endif
		OPENSSL_free(certificate_pkcs11);
	}

	return ret;
}

static
int
__driver_pkcs11_load(
	const mycms_certificate certificate,
	const char * const what
) {
	mycms_certificate_pkcs11 certificate_pkcs11 = NULL;

	EVP_PKEY *evp = NULL;

	int ret = 0;
	char *work = NULL;
	char *p;
	char *cert_pkcs11;
	char *key_pkcs11;
	FILE *fp = NULL;
	mycms_blob blob = {NULL, 0};

	if ((work = OPENSSL_strdup(what)) == NULL) {
		goto cleanup;
	}

	p = work;
	cert_pkcs11 = p;
	if ((p = strchr(p, ':')) == NULL) {
		goto cleanup;
	}
	*p = '\0';
	p++;
	key_pkcs11 = p;
	if ((p = strchr(p, ':')) != NULL) {
		*p = '\0';
	}

	if ((fp = fopen(cert_pkcs11, "rb")) == NULL) {
		goto cleanup;
	}

	if (fseek(fp, 0L, SEEK_END) != 0) {
		goto cleanup;
	}
	{
		long l;
		if ((l = ftell(fp)) == -1) {
			goto cleanup;
		}
		blob.size = l;
	}
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		goto cleanup;
	}

	if ((blob.data = OPENSSL_zalloc(blob.size)) == NULL) {
		goto cleanup;
	}

	if (fread(blob.data, blob.size, 1, fp) != 1) {
		goto cleanup;
	}

	if ((evp = __load_pkey(key_pkcs11)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = OPENSSL_zalloc(sizeof(struct mycms_certificate_pkcs11_s))) == NULL) {
		goto cleanup;
	}

	switch (EVP_PKEY_id(evp)) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			if ((certificate_pkcs11->rsa = EVP_PKEY_get1_RSA(evp)) == NULL) {
				goto cleanup;
			}
		break;
#endif
		default:
			goto cleanup;
	}

	if (!mycms_certificate_set_userdata(certificate, certificate_pkcs11)) {
		goto cleanup;
	}
	certificate_pkcs11 = NULL;

	if (!mycms_certificate_apply_certificate(certificate, &blob)) {
		goto cleanup;
	}

	ret = 1;

cleanup:
	if (blob.data != NULL) {
		OPENSSL_free(blob.data);
		blob.data = NULL;
	}

	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}

	if (work != NULL) {
		OPENSSL_free(work);
		work = NULL;
	}

	if (evp != NULL) {
		EVP_PKEY_free(evp);
		evp = NULL;
	}

	if (certificate_pkcs11 != NULL) {
#ifndef OPENSSL_NO_RSA
		if (certificate_pkcs11->rsa != NULL) {
			RSA_free(certificate_pkcs11->rsa);
			certificate_pkcs11->rsa = NULL;
		}
#endif
		OPENSSL_free(certificate_pkcs11);
		certificate_pkcs11 = NULL;
	}

	return ret;
}

int mycms_certificate_driver_pkcs11_apply(
	const mycms_certificate certificate
) {
	mycms_certificate_set_driver_free(certificate, __driver_pkcs11_free);
	mycms_certificate_set_driver_load(certificate, __driver_pkcs11_load);
#ifndef OPENSSL_NO_RSA
	mycms_certificate_set_driver_rsa_private_op(certificate, __driver_pkcs11_rsa_private_op);
#endif
	return 1;
}

#endif
