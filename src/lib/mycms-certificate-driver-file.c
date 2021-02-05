#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_CERTIFICATE_DRIVER_FILE

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms-certificate-driver-file.h>

struct __mycms_certificate_driver_file_s {
#ifndef OPENSSL_NO_RSA
	RSA *rsa;
#endif
};
typedef struct __mycms_certificate_driver_file_s *__mycms_certificate_driver_file;

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
__driver_load_pkey(const char *file) {
	EVP_PKEY *k = NULL;
	BIO *bio = NULL;

	if ((bio = BIO_new_file(file, "rb")) == NULL) {
		goto cleanup;
	}

	if ((k = d2i_PrivateKey_bio(bio, NULL)) == NULL) {
		goto cleanup;
	}

cleanup:

	BIO_free(bio);
	bio = NULL;

	return k;
}

#ifndef OPENSSL_NO_RSA
static
int
__driver_rsa_private_op(
	const mycms_certificate certificate,
	const int op,
	const unsigned char * const from,
	const size_t from_size,
	unsigned char * const to,
	const size_t to_size __attribute__((unused)),
	const int padding
) {
	__mycms_certificate_driver_file certificate_file = (__mycms_certificate_driver_file)mycms_certificate_get_driverdata(certificate);
	int cpadding;
	const RSA_METHOD *rsa_method = NULL;
	int ret = -1;

	if ((cpadding = __convert_padding(padding)) == -1) {
		goto cleanup;
	}

	if ((rsa_method = RSA_get_method(certificate_file->rsa)) == NULL) {
		goto cleanup;
	}

	switch (op) {
		case MYCMS_PRIVATE_OP_ENCRYPT:
			ret = RSA_meth_get_priv_enc(rsa_method)(from_size, from, to, certificate_file->rsa, cpadding);
		break;
		case MYCMS_PRIVATE_OP_DECRYPT:
			ret = RSA_meth_get_priv_dec(rsa_method)(from_size, from, to, certificate_file->rsa, cpadding);
		break;
		default:
			goto cleanup;
	}

cleanup:

	return ret;
}
#endif

static
int
__driver_free(
	const mycms_certificate certificate
) {
	__mycms_certificate_driver_file certificate_file = (__mycms_certificate_driver_file)mycms_certificate_get_driverdata(certificate);

	int ret = 1;

	if (certificate_file != NULL) {
		#ifndef OPENSSL_NO_RSA
			RSA_free(certificate_file->rsa);
			certificate_file->rsa = NULL;
		#endif
		OPENSSL_free(certificate_file);
	}

	return ret;
}

static
int
__driver_load(
	const mycms_certificate certificate,
	const char * const what
) {
	__mycms_certificate_driver_file certificate_file = NULL;

	EVP_PKEY *evp = NULL;

	int ret = 0;
	char *work = NULL;
	char *p;
	char *cert_file;
	char *key_file;
	FILE *fp = NULL;
	mycms_blob blob = {NULL, 0};

	if ((work = OPENSSL_strdup(what)) == NULL) {
		goto cleanup;
	}

	p = work;
	cert_file = p;
	if ((p = strchr(p, ':')) == NULL) {
		goto cleanup;
	}
	*p = '\0';
	p++;
	key_file = p;
	if ((p = strchr(p, ':')) != NULL) {
		*p = '\0';
	}

	if ((fp = fopen(cert_file, "rb")) == NULL) {
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

	if ((evp = __driver_load_pkey(key_file)) == NULL) {
		goto cleanup;
	}

	if ((certificate_file = OPENSSL_zalloc(sizeof(*certificate_file))) == NULL) {
		goto cleanup;
	}

	switch (EVP_PKEY_id(evp)) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			if ((certificate_file->rsa = EVP_PKEY_get1_RSA(evp)) == NULL) {
				goto cleanup;
			}
		break;
#endif
		default:
			goto cleanup;
	}

	if (!mycms_certificate_set_driverdata(certificate, certificate_file)) {
		goto cleanup;
	}
	certificate_file = NULL;

	if (!mycms_certificate_apply_certificate(certificate, &blob)) {
		goto cleanup;
	}

	ret = 1;

cleanup:
	OPENSSL_free(blob.data);
	blob.data = NULL;

	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}

	OPENSSL_free(work);
	work = NULL;

	EVP_PKEY_free(evp);
	evp = NULL;

	if (certificate_file != NULL) {
#ifndef OPENSSL_NO_RSA
		if (certificate_file->rsa != NULL) {
			RSA_free(certificate_file->rsa);
			certificate_file->rsa = NULL;
		}
#endif
		OPENSSL_free(certificate_file);
		certificate_file = NULL;
	}

	return ret;
}

int mycms_certificate_driver_file_apply(
	const mycms_certificate certificate
) {
	mycms_certificate_set_driver_free(certificate, __driver_free);
	mycms_certificate_set_driver_load(certificate, __driver_load);
#ifndef OPENSSL_NO_RSA
	mycms_certificate_set_driver_rsa_private_op(certificate, __driver_rsa_private_op);
#endif
	return 1;
}

#endif
