#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_CERTIFICATE_DRIVER_PKCS11

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms-certificate-driver-pkcs11.h>

#include "pkcs11.h"

struct __mycms_certificate_driver_pkcs11_s {
	void *module_handle;
	int should_finalize;
	CK_FUNCTION_LIST_PTR f;
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE key_handle;
};
typedef struct __mycms_certificate_driver_pkcs11_s *__mycms_certificate_driver_pkcs11;

static CK_MECHANISM_TYPE __convert_padding(const int padding) {
	int ret;
	switch (padding) {
		case MYCMS_PADDING_PKCS1:
			ret = CKM_RSA_PKCS;
		break;
		case MYCMS_PADDING_OEAP:
			ret = CKM_RSA_PKCS_OAEP;
		break;
		case MYCMS_PADDING_NONE:
			ret = CKM_RSA_X_509;
		break;
		default:
			ret = CKR_MECHANISM_INVALID;
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

static
CK_RV
__load_provider (
	const __mycms_certificate_driver_pkcs11 certificate_pkcs11,
	const char * const module
) {
	void *p;

	CK_C_GetFunctionList gfl = NULL;
	CK_C_INITIALIZE_ARGS initargs;
	CK_C_INITIALIZE_ARGS_PTR pinitargs = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	certificate_pkcs11->module_handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	if (certificate_pkcs11->module_handle == NULL) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	/*
	 * Make compiler happy!
	 */
	p = dlsym (
		certificate_pkcs11->module_handle,
		"C_GetFunctionList"
	);
	memmove(&gfl, &p, sizeof(gfl));

	if (gfl == NULL) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	if ((rv = gfl(&certificate_pkcs11->f)) != CKR_OK) {
		goto cleanup;
	}

	memset(&initargs, 0, sizeof(initargs));
	if ((initargs.pReserved = getenv("PKCS11H_INIT_ARGS_RESERVED")) != NULL) {
		pinitargs = &initargs;
	}

	if ((rv = certificate_pkcs11->f->C_Initialize(pinitargs)) != CKR_OK) {
		if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			rv = CKR_OK;
		}
		else {
			goto cleanup;
		}
	}
	else {
		certificate_pkcs11->should_finalize = 1;
	}

cleanup:

	return rv;
}

static
CK_RV
__unload_provider(
	const __mycms_certificate_driver_pkcs11 certificate_pkcs11
) {
	if (certificate_pkcs11->should_finalize) {
		certificate_pkcs11->f->C_Finalize(NULL);
		certificate_pkcs11->should_finalize = 0;
	}

	if (certificate_pkcs11->f != NULL) {
		certificate_pkcs11->f = NULL;
	}

	if (certificate_pkcs11->module_handle != NULL) {
		dlclose (certificate_pkcs11->module_handle);
		certificate_pkcs11->module_handle = NULL;
	}

	return CKR_OK;
}

static
int
__driver_pkcs11_rsa_private_op(
	const mycms_certificate certificate,
	const int op,
	const unsigned char * const from,
	const size_t from_size,
	unsigned char * const to,
	const size_t to_size,
	const int padding
) {
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_userdata(certificate);

	CK_MECHANISM mech = {
		0, NULL, 0
	};
	CK_ULONG size;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if ((mech.mechanism = __convert_padding(padding)) == CKR_MECHANISM_INVALID) {
		goto cleanup;
	}

	switch (op) {
		case MYCMS_PRIVATE_OP_ENCRYPT:
			if ((rv = certificate_pkcs11->f->C_SignInit (
				certificate_pkcs11->session_handle,
				&mech,
				certificate_pkcs11->key_handle
			)) != CKR_OK) {
				goto cleanup;
			}
			size = to_size;
			if ((rv = certificate_pkcs11->f->C_Sign (
				certificate_pkcs11->session_handle,
				(CK_BYTE_PTR)from,
				from_size,
				(CK_BYTE_PTR)to,
				&size
			)) != CKR_OK) {
				goto cleanup;
			}
		break;
		case MYCMS_PRIVATE_OP_DECRYPT:
			if ((rv = certificate_pkcs11->f->C_DecryptInit (
				certificate_pkcs11->session_handle,
				&mech,
				certificate_pkcs11->key_handle
			)) != CKR_OK) {
				goto cleanup;
			}
			size = to_size;
			if ((rv = certificate_pkcs11->f->C_Decrypt (
				certificate_pkcs11->session_handle,
				(CK_BYTE_PTR)from,
				from_size,
				(CK_BYTE_PTR)to,
				&size
			)) != CKR_OK) {
				goto cleanup;
			}
		break;
		default:
			goto cleanup;
	}

cleanup:

	return rv;
}

int
__driver_pkcs11_free(
	const mycms_certificate certificate
) {
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_userdata(certificate);

	int ret = 1;

	if (certificate_pkcs11 != NULL) {
		__unload_provider(certificate_pkcs11);
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
#if 0
	mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

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

	if ((certificate_pkcs11 = OPENSSL_zalloc(sizeof(*certificate_pkcs11))) == NULL) {
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
#endif
}

int mycms_certificate_driver_pkcs11_apply(
	const mycms_certificate certificate
) {
	mycms_certificate_set_driver_free(certificate, __driver_pkcs11_free);
	mycms_certificate_set_driver_load(certificate, __driver_pkcs11_load);
	mycms_certificate_set_driver_rsa_private_op(certificate, __driver_pkcs11_rsa_private_op);
	return 1;
}

#endif
