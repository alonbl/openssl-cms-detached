#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms/mycms-certificate-driver-file.h>

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

	if (file == NULL) {
		goto cleanup;
	}

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
	const size_t to_size,
	const int padding
) {
	__mycms_certificate_driver_file certificate_file = NULL;
	const RSA_METHOD *rsa_method = NULL;
	int cpadding;
	int ret = -1;

	if ((certificate_file = (__mycms_certificate_driver_file)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	if (from == NULL) {
		goto cleanup;
	}

	if (to == NULL) {
		goto cleanup;
	}

	if (from_size == 0) {
		goto cleanup;
	}

	if (to_size < from_size) {
		goto cleanup;
	}

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
	mycms_system system = NULL;
	__mycms_certificate_driver_file certificate_file;
	int ret = 0;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_file = (__mycms_certificate_driver_file)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

#ifndef OPENSSL_NO_RSA
	RSA_free(certificate_file->rsa);
	certificate_file->rsa = NULL;
#endif

	if (!mycms_system_free(system, certificate_file)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

static
int
__driver_load(
	const mycms_certificate certificate,
	const mycms_dict parameters
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_file certificate_file = NULL;

	EVP_PKEY *evp = NULL;
	BIO *bio_in = NULL;
	BIO *bio_out = NULL;

	const char *cert_file;
	const char *key_file;
	mycms_blob blob;
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (parameters == NULL) {
		goto cleanup;
	}

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((cert_file = mycms_dict_entry_get(parameters, "cert", NULL)) == NULL) {
		goto cleanup;
	}

	if ((key_file = mycms_dict_entry_get(parameters, "key", NULL)) == NULL) {
		goto cleanup;
	}

	if ((bio_in = BIO_new_file(cert_file, "rb")) == NULL) {
		goto cleanup;
	}

	if ((bio_out = BIO_new(BIO_s_mem())) == NULL) {
		goto cleanup;
	}

	{
		unsigned char buffer[1024];
		int n;

		while ((n = BIO_read(bio_in, buffer, sizeof(buffer))) > 0) {
			if (BIO_write(bio_out, buffer, n) != n) {
				goto cleanup;
			}
		}
		if (n != 0) {
			goto cleanup;
		}
	}

	blob.size = BIO_get_mem_data(bio_out, &blob.data);

	if ((evp = __driver_load_pkey(key_file)) == NULL) {
		goto cleanup;
	}

	if ((certificate_file = mycms_system_zalloc(system, sizeof(*certificate_file))) == NULL) {
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
	BIO_free(bio_in);
	bio_in = NULL;

	BIO_free(bio_out);
	bio_out = NULL;

	EVP_PKEY_free(evp);
	evp = NULL;

	if (certificate_file != NULL) {
#ifndef OPENSSL_NO_RSA
		RSA_free(certificate_file->rsa);
		certificate_file->rsa = NULL;
#endif
		mycms_system_free(system, certificate_file);
		certificate_file = NULL;
	}

	return ret;
}

const char *
mycms_certificate_driver_file_usage(void) {
	return (
		"cert: DER encoded certificate file\n"
		"key: DER encoded PKCS#8 file\n"
	);
}

int mycms_certificate_driver_file_apply(
	const mycms_certificate certificate
) {
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (!mycms_certificate_set_driver_free(certificate, __driver_free)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_driver_load(certificate, __driver_load)) {
		goto cleanup;
	}

#ifndef OPENSSL_NO_RSA
	if (!mycms_certificate_set_driver_rsa_private_op(certificate, __driver_rsa_private_op)) {
		goto cleanup;
	}
#endif
	ret = 1;

cleanup:

	return ret;
}
