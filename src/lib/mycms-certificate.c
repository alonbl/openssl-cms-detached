#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms-certificate-driver-file.h>

struct mycms_certificate_s {
	mycms mycms;
	const void *userdata;
	const void *driverdata;
	mycms_certificate_driver_free driver_free;
	mycms_certificate_driver_load driver_load;
	mycms_certificate_driver_rsa_private_op driver_rsa_private_op;
	mycms_certificate_passphrase_callback passphrase_callback;
	X509 *x509;
	EVP_PKEY *evp;
};

static struct {
#ifndef OPENSSL_NO_RSA
	RSA_METHOD *rsa_method;
	int rsa_index;
#endif
} __openssl_methods;

static int __convert_padding(const int padding) {
	int ret;
	switch (padding) {
#ifndef OPENSSL_NO_RSA
		case RSA_PKCS1_PADDING:
			ret = MYCMS_PADDING_PKCS1;
		break;
		case RSA_PKCS1_OAEP_PADDING:
			ret = MYCMS_PADDING_OEAP;
		break;
		case RSA_NO_PADDING:
			ret = MYCMS_PADDING_NONE;
		break;
#endif
		default:
			ret = MYCMS_PADDING_INVALID;
		break;
	}
	return ret;
}

static
int
__driver_free_default(
	const mycms_certificate certificate __attribute__((unused))
) {
	return 1;
}

static
int
__driver_load_default(
	const mycms_certificate certificate __attribute__((unused)),
	const char * const what __attribute__((unused))
) {
	return 0;
}

static
int
driver_rsa_private_op_default(
	const mycms_certificate certificate __attribute__((unused)),
	const int op __attribute__((unused)),
	const unsigned char * const from __attribute__((unused)),
	const size_t from_size __attribute__((unused)),
	unsigned char * const to __attribute__((unused)),
	const size_t to_size __attribute__((unused)),
	const int padding __attribute__((unused))
) {
	return -1;
}

static
int
passphrase_callback_default(
	const mycms_certificate certificate __attribute__((unused)),
	char **p,
	const size_t size __attribute__((unused))
) {
	*p = NULL;
	return 1;
}

#ifndef OPENSSL_NO_RSA

static
int
__setup_rsa_evp(
	mycms_certificate certificate,
	EVP_PKEY *evp
) {
	RSA *rsa = NULL;
	int ret = 0;

	if ((rsa = EVP_PKEY_get1_RSA(evp)) == NULL) {
		goto cleanup;
	}

	if (!RSA_set_method(rsa, __openssl_methods.rsa_method)) {
		goto cleanup;
	}

	if (!RSA_set_ex_data(rsa, __openssl_methods.rsa_index, certificate)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	RSA_free(rsa);
	rsa = NULL;

	return ret;
}

static
mycms_certificate
__get_rsa_certificate(
	RSA *rsa
) {
	mycms_certificate certificate = NULL;

	if (rsa == NULL) {
		goto cleanup;
	}

	certificate = (mycms_certificate)RSA_get_ex_data(rsa, __openssl_methods.rsa_index);

cleanup:

	return certificate;
}

static
inline
int
__rsa_op(
	int private_op,
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	mycms_certificate certificate = __get_rsa_certificate(rsa);
	int cpadding;
	int ret = -1;

	if (certificate->driver_rsa_private_op == NULL) {
		goto cleanup;
	}

	if ((cpadding = __convert_padding(padding)) == MYCMS_PADDING_INVALID) {
		goto cleanup;
	}

	ret = certificate->driver_rsa_private_op(
		certificate,
		private_op,
		from,
		flen,
		to,
		flen,
		cpadding
	);

cleanup:

	return ret;
}

static
int
__openssl_rsa_enc(
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	return __rsa_op(
		MYCMS_PRIVATE_OP_ENCRYPT,
		flen,
		from,
		to,
		rsa,
		padding
	);
}

static
int
__openssl_rsa_dec(
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	return __rsa_op(
		MYCMS_PRIVATE_OP_DECRYPT,
		flen,
		from,
		to,
		rsa,
		padding
	);
}
#endif

int
_mycms_certificate_static_init(void) {
#ifndef OPENSSL_NO_RSA
	RSA_METHOD *rsa_method = NULL;
	int rsa_index = -1;
#endif
	int ret = 0;

#ifndef OPENSSL_NO_RSA
	if (__openssl_methods.rsa_method == NULL) {
	
		if ((rsa_method = RSA_meth_dup(RSA_get_default_method())) == NULL) {
			goto cleanup;
		}
		if (!RSA_meth_set1_name(rsa_method, "mycms")) {
			goto cleanup;
		}
		if (!RSA_meth_set_priv_dec(rsa_method, __openssl_rsa_dec)) {
			goto cleanup;
		}
		if (!RSA_meth_set_priv_enc(rsa_method, __openssl_rsa_enc)) {
			goto cleanup;
		}
#if 0
		if (!RSA_meth_set_flags(rsa_method, RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY)) {
			goto cleanup;
		}
#endif
		if ((rsa_index = RSA_get_ex_new_index(
			0,
			"mycms",
			NULL,
			NULL,
			NULL
		)) == -1) {
			goto cleanup;
		}
	}
#endif

#ifndef OPENSSL_NO_RSA
	__openssl_methods.rsa_method = rsa_method;
	rsa_method = NULL;
	__openssl_methods.rsa_index = rsa_index;
#endif

	ret = 1;

cleanup:
	RSA_meth_free (rsa_method);
	rsa_method = NULL;

	return ret;
}

int
_mycms_certificate_static_free(void) {
#ifndef OPENSSL_NO_RSA
	if (__openssl_methods.rsa_method != NULL) {
		RSA_meth_free (__openssl_methods.rsa_method);
		__openssl_methods.rsa_method = NULL;
	}
#endif
	return 1;
}

mycms_certificate
mycms_certificate_new(
	const mycms mycms
) {
	mycms_certificate certificate = NULL;

	if ((certificate = OPENSSL_zalloc(sizeof(*certificate))) != NULL) {
		certificate->mycms = mycms;
		certificate->driver_free = __driver_free_default;
		certificate->driver_load = __driver_load_default;
		certificate->driver_rsa_private_op = driver_rsa_private_op_default;
		certificate->passphrase_callback = passphrase_callback_default;
	}

	return certificate;
}

int
mycms_certificate_construct(
	const mycms_certificate certificate __attribute__((unused))
) {
	return 1;
}

int
mycms_certificate_destroy(
	const mycms_certificate certificate
) {
	if (certificate != NULL) {
		EVP_PKEY_free(certificate->evp);
		certificate->evp = NULL;

		X509_free(certificate->x509);
		certificate->x509 = NULL;

		certificate->driver_free(certificate);

		OPENSSL_free(certificate);
	}

	return 1;
}

mycms
mycms_certificate_get_mycms(
	const mycms_certificate certificate
) {
	return certificate->mycms;
}

const void *
mycms_certificate_get_userdata(
	const mycms_certificate certificate
) {
	return certificate->userdata;
}

int
mycms_certificate_set_userdata(
	const mycms_certificate certificate,
	const void *userdata
) {
	certificate->userdata = userdata;
	return 1;
}

const void *
mycms_certificate_get_driverdata(
	const mycms_certificate certificate
) {
	return certificate->driverdata;
}

int
mycms_certificate_set_driverdata(
	const mycms_certificate certificate,
	const void *driverdata
) {
	certificate->driverdata = driverdata;
	return 1;
}

int
mycms_certificate_set_driver_load(
	const mycms_certificate certificate,
	const mycms_certificate_driver_load driver_load
) {
	certificate->driver_load = driver_load;
	return 1;
}

int
mycms_certificate_set_driver_free(
	const mycms_certificate certificate,
	const mycms_certificate_driver_free driver_free
) {
	certificate->driver_free = driver_free;
	return 1;
}

int
mycms_certificate_set_driver_rsa_private_op(
	const mycms_certificate certificate,
	const mycms_certificate_driver_rsa_private_op driver_rsa_private_op
) {
	certificate->driver_rsa_private_op = driver_rsa_private_op;
	return 1;
}

int
mycms_certificate_set_passphrase_callback(
	const mycms_certificate certificate,
	const mycms_certificate_passphrase_callback passphrase_callback
) {
	certificate->passphrase_callback = passphrase_callback;
	return 1;
}

int
mycms_certificate_load(
	const mycms_certificate certificate,
	const char * const what
) {
	return certificate->driver_load(certificate, what);
}

int
mycms_certificate_apply_certificate(
	const mycms_certificate certificate,
	const mycms_blob *blob
) {
	unsigned const char * p;
	X509 *x509 = NULL;
	EVP_PKEY *evp = NULL;
	int ret = 0;

	p = blob->data;
	if ((x509 = d2i_X509(NULL, &p, blob->size)) == NULL) {
		goto cleanup;
	}

	if ((evp = X509_get_pubkey(x509)) == NULL) {
		goto cleanup;
	}

	switch (EVP_PKEY_id(evp)) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			if (!__setup_rsa_evp(certificate, evp)) {
				goto cleanup;
			}
		break;
#endif
		default:
			goto cleanup;
	}

	certificate->x509 = x509;
	x509 = NULL;
	certificate->evp = evp;
	evp = NULL;

	ret = 1;

cleanup:
	X509_free(x509);
	x509 = NULL;

	EVP_PKEY_free(evp);
	evp = NULL;

	return ret;
}

int
mycms_certificate_aquire_passphrase(
	const mycms_certificate certificate,
	char **p,
	const size_t size
) {
	return certificate->passphrase_callback(certificate, p, size);
}

X509 *
_mycms_certificate_get_X509(
	const mycms_certificate certificate
) {
	return certificate->x509;
}

EVP_PKEY *
_mycms_certificate_get_EVP_PKEY(
	const mycms_certificate certificate
) {
	return certificate->evp;
}
