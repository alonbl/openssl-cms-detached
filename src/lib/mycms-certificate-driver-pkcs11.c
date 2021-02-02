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

#define __INVALID_SESSION_HANDLE	((CK_SESSION_HANDLE)-1)
#define __INVALID_OBJECT_HANDLE		((CK_OBJECT_HANDLE)-1)

struct __mycms_certificate_driver_pkcs11_s {
	void *module_handle;
	int should_finalize;
	CK_FUNCTION_LIST_PTR f;
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE key_handle;
};
typedef struct __mycms_certificate_driver_pkcs11_s *__mycms_certificate_driver_pkcs11;

static
void
__fixupFixedString(
	char * const target,			/* MUST BE >= length+1 */
	const char * const source,
	const size_t length			/* FIXED STRING LENGTH */
) {
	char *p;

	p = target+length;
	memmove (target, source, length);
	*p = '\0';
	p--;
	while (p >= target && *p == ' ') {
		*p = '\0';
		p--;
	}
}

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
CK_RV
__load_provider(
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
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate);

	CK_MECHANISM mech = {
		0, NULL, 0
	};
	CK_ULONG size;
	CK_RV rv = CKR_FUNCTION_FAILED;
	int ret = -1;

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

	ret = size;

cleanup:

	return ret;
}

static
int
__driver_pkcs11_free(
	const mycms_certificate certificate
) {
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate);

	int ret = 1;

	if (certificate_pkcs11 != NULL) {
		if (certificate_pkcs11->key_handle != __INVALID_OBJECT_HANDLE) {
			certificate_pkcs11->key_handle = __INVALID_OBJECT_HANDLE;
		}
		if (certificate_pkcs11->session_handle != __INVALID_SESSION_HANDLE) {
			certificate_pkcs11->f->C_Logout(certificate_pkcs11->session_handle);
			certificate_pkcs11->f->C_CloseSession(certificate_pkcs11->session_handle);
			certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
		}
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
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;
	char *work = NULL;
	char *p;
	char *module = NULL;
	char *tokenlabel = NULL;
	char *keylabel = NULL;
	char pin[512];
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG slotnum = 0;
	CK_ULONG slot_index;
	CK_RV rv = CKR_FUNCTION_FAILED;
	int ret = 0;
	int found = 0;

	if ((work = OPENSSL_strdup(what)) == NULL) {
		goto cleanup;
	}

	p = work;
	module = p;
	if ((p = strchr(p, ':')) == NULL) {
		goto cleanup;
	}
	*p = '\0';
	p++;
	tokenlabel = p;
	if ((p = strchr(p, ':')) == NULL) {
		goto cleanup;
	}
	*p = '\0';
	p++;
	keylabel = p;
	if ((p = strchr(p, ':')) != NULL) {
		*p = '\0';
	}

	if ((certificate_pkcs11 = OPENSSL_zalloc(sizeof(*certificate_pkcs11))) == NULL) {
		goto cleanup;
	}
	certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
	certificate_pkcs11->key_handle = __INVALID_OBJECT_HANDLE;

	if (!mycms_certificate_set_driverdata(certificate, certificate_pkcs11)) {
		goto cleanup;
	}

	if ((rv = __load_provider(certificate_pkcs11, module)) != CKR_OK) {
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->f->C_GetSlotList (
			CK_TRUE,
			NULL_PTR,
			&slotnum
		)) != CKR_OK
	) {
		goto cleanup;
	}

	if ((slots = OPENSSL_zalloc(sizeof(*slots) * slotnum)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->f->C_GetSlotList (
			CK_TRUE,
			slots,
			&slotnum
		)) != CKR_OK
	) {
		goto cleanup;
	}

	for (
		slot_index=0;
		(
			slot_index < slotnum &&
			!found
		);
		slot_index++
	) {
		CK_TOKEN_INFO info;

		if ((rv = certificate_pkcs11->f->C_GetTokenInfo (
			slots[slot_index],
			&info
		)) != CKR_OK) {
		} else {
			char label[sizeof(info.label)+1];
			__fixupFixedString(label, (char *)info.label, sizeof(info.label));

			if (!strcmp(label, tokenlabel)) {
				found = 1;
				break;
			}
		}
	}

	if (!found) {
		goto cleanup;
	}

	if ((rv = certificate_pkcs11->f->C_OpenSession (
		slots[slot_index],
		CKF_SERIAL_SESSION,
		NULL_PTR,
		NULL_PTR,
		&certificate_pkcs11->session_handle
	)) != CKR_OK) {
		certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
		goto cleanup;
	}

	p = pin;
	if (!mycms_certificate_aquire_passphrase(certificate, &p, sizeof(pin))) {
		goto cleanup;
	}

	if ((rv = certificate_pkcs11->f->C_Login (
		certificate_pkcs11->session_handle,
		CKU_USER,
		(CK_UTF8CHAR_PTR)p,
		p == NULL ? 0 : strlen(p)
	)) != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
		goto cleanup;
	}

#if 0
	if (!mycms_certificate_apply_certificate(certificate, &blob)) {
		goto cleanup;
	}
#endif

	ret = 1;

cleanup:

	if (slots != NULL) {
		OPENSSL_free(slots);
		slots = NULL;
	}

	return ret;
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
