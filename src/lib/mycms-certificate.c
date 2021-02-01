#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms/mycms-certificate-driver-file.h>
#include <mycms/mycms.h>

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
	const mycms_dict dict __attribute__((unused))
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

static const struct mycms_certificate_s __MYCMS_CERTIFICATE_INIT = {
	NULL,
	NULL,
	NULL,
	__driver_free_default,
	__driver_load_default,
	driver_rsa_private_op_default,
	passphrase_callback_default,
	NULL,
	NULL
};

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
	mycms_certificate certificate;
	int cpadding;
	int ret = -1;

 	if ((certificate = __get_rsa_certificate(rsa)) == NULL) {
		goto cleanup;
	}

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
	mycms_system system = NULL;
	mycms_certificate certificate = NULL;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	if ((certificate = mycms_system_malloc(system, sizeof(*certificate))) == NULL) {
		goto cleanup;
	}

	memcpy(certificate, &__MYCMS_CERTIFICATE_INIT, sizeof(__MYCMS_CERTIFICATE_INIT));
	certificate->mycms = mycms;

cleanup:

	return certificate;
}

int
mycms_certificate_construct(
	const mycms_certificate certificate __attribute__((unused))
) {
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_certificate_destruct(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;
	int ret = 0;

	if (certificate == NULL) {
		ret = 1;
		goto cleanup;
	}

	if ((system = mycms_get_system(certificate->mycms)) == NULL) {
		goto cleanup;
	}

	EVP_PKEY_free(certificate->evp);
	certificate->evp = NULL;

	X509_free(certificate->x509);
	certificate->x509 = NULL;

	certificate->driver_free(certificate);

	mycms_system_free(system, certificate);

	ret = 1;

cleanup:

	return ret;
}

mycms
mycms_certificate_get_mycms(
	const mycms_certificate certificate
) {
	mycms ret = NULL;

	if (certificate == NULL) {
		goto cleanup;
	}

	ret = certificate->mycms;

cleanup:

	return ret;
}

mycms_system
mycms_certificate_get_system(
	const mycms_certificate certificate
) {
	mycms_system ret = NULL;

	if (certificate == NULL) {
		goto cleanup;
	}

	ret = mycms_get_system(certificate->mycms);

cleanup:

	return ret;
}

const void *
mycms_certificate_get_userdata(
	const mycms_certificate certificate
) {
	const void *ret = NULL;

	if (certificate == NULL) {
		goto cleanup;
	}

	ret = certificate->userdata;

cleanup:

	return ret;
}

int
mycms_certificate_set_userdata(
	const mycms_certificate certificate,
	const void *userdata
) {
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	certificate->userdata = userdata;

	ret = 1;

cleanup:

	return ret;
}

const void *
mycms_certificate_get_driverdata(
	const mycms_certificate certificate
) {
	const void *ret = NULL;

	if (certificate == NULL) {
		goto cleanup;
	}

	ret = certificate->driverdata;

cleanup:

	return ret;
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
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (driver_load == NULL) {
		goto cleanup;
	}

	certificate->driver_load = driver_load;

	ret = 1;

cleanup:

	return ret;
}

int
mycms_certificate_set_driver_free(
	const mycms_certificate certificate,
	const mycms_certificate_driver_free driver_free
) {
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (driver_free == NULL) {
		goto cleanup;
	}

	certificate->driver_free = driver_free;

	ret = 1;

cleanup:

	return ret;
}

int
mycms_certificate_set_driver_rsa_private_op(
	const mycms_certificate certificate,
	const mycms_certificate_driver_rsa_private_op driver_rsa_private_op
) {
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (driver_rsa_private_op == NULL) {
		goto cleanup;
	}

	certificate->driver_rsa_private_op = driver_rsa_private_op;

	ret = 1;

cleanup:

	return ret;
}

int
mycms_certificate_set_passphrase_callback(
	const mycms_certificate certificate,
	const mycms_certificate_passphrase_callback passphrase_callback
) {
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (passphrase_callback == NULL) {
		goto cleanup;
	}

	certificate->passphrase_callback = passphrase_callback;

	ret = 1;

cleanup:

	return ret;
}

int
mycms_certificate_load(
	const mycms_certificate certificate,
	const mycms_dict parameters
) {
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (parameters == NULL) {
		goto cleanup;
	}

	ret = certificate->driver_load(certificate, parameters);

cleanup:

	return ret;
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

	if (certificate == NULL) {
		goto cleanup;
	}

	if (blob == NULL) {
		goto cleanup;
	}

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
	int ret = 0;

	if (certificate == NULL) {
		goto cleanup;
	}

	if (p == NULL) {
		goto cleanup;
	}

	ret = certificate->passphrase_callback(certificate, p, size);

cleanup:

	return ret;
}

X509 *
_mycms_certificate_get_X509(
	const mycms_certificate certificate
) {
	X509 *ret = NULL;

	if (certificate == NULL) {
		goto cleanup;
	}

	ret = certificate->x509;

cleanup:

	return ret;
}

EVP_PKEY *
_mycms_certificate_get_EVP_PKEY(
	const mycms_certificate certificate
) {
	EVP_PKEY *ret = NULL;

	if (certificate == NULL) {
		goto cleanup;
	}

	ret = certificate->evp;

cleanup:

	return ret;
}
