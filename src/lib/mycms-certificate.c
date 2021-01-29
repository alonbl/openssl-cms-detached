#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms-certificate-driver-file.h>

struct mycms_certificate_s {
	void *userdata;
	mycms_certificate_driver_free driver_free;
	mycms_certificate_driver_load driver_load;
	mycms_certificate_driver_rsa_private_op driver_rsa_private_op;
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

#ifndef OPENSSL_NO_RSA

static
int
__mycms_certificate_setup_rsa_evp(
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

	if (rsa != NULL) {
		RSA_free(rsa);
		rsa = NULL;
	}

	return ret;
}

static
mycms_certificate
__mycms_openssl_get_rsa_certificate(
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
__mycms_certificate_rsa_op(
	int private_op,
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	mycms_certificate certificate = __mycms_openssl_get_rsa_certificate(rsa);
	int cpadding;
	int ret = -1;

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
__mycms_certificate_rsa_enc (
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	return __mycms_certificate_rsa_op(
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
__mycms_certificate_rsa_dec (
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	return __mycms_certificate_rsa_op(
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
		if (!RSA_meth_set_priv_dec(rsa_method, __mycms_certificate_rsa_dec)) {
			goto cleanup;
		}
		if (!RSA_meth_set_priv_enc(rsa_method, __mycms_certificate_rsa_enc)) {
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
	if (rsa_method != NULL) {
		RSA_meth_free (rsa_method);
		rsa_method = NULL;
	}

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
mycms_certificate_new(void) {
	return calloc(1, sizeof(struct mycms_certificate_s));
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
	if (certificate->evp != NULL) {
		EVP_PKEY_free(certificate->evp);
		certificate->evp = NULL;
	}
	if (certificate->x509 != NULL) {
		X509_free(certificate->x509);
		certificate->x509 = NULL;
	}
	if (certificate->driver_free != NULL) {
		certificate->driver_free(certificate);
	}
	free(certificate);
	return 1;
}

void *
mycms_certificate_get_userdata(
	const mycms_certificate certificate
) {
	return certificate->userdata;
}

int
mycms_certificate_set_userdata(
	const mycms_certificate certificate,
	void *userdata
) {
	certificate->userdata = userdata;
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
			if (!__mycms_certificate_setup_rsa_evp(certificate, evp)) {
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
	if (x509 == NULL) {
		X509_free(x509);
		x509 = NULL;
	}

	if (evp != NULL) {
		EVP_PKEY_free(evp);
		evp = NULL;
	}

	return ret;
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
