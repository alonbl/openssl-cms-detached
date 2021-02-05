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
__fixup_fixed_string(
	char * const target,			/* MUST BE >= length+1 */
	const char * const source,
	const size_t length			/* FIXED STRING LENGTH */
) {
	char *p;

	memmove (target, source, length);
	p = target+length;
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
	const char * const module,
	const char * const reserved
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
	if (reserved != NULL) {
		initargs.pReserved = (char *)reserved;
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

	certificate_pkcs11->f = NULL;

	if (certificate_pkcs11->module_handle != NULL) {
		dlclose (certificate_pkcs11->module_handle);
		certificate_pkcs11->module_handle = NULL;
	}

	return CKR_OK;
}

static
CK_RV
__get_object_attributes(
	__mycms_certificate_driver_pkcs11 certificate_pkcs11,
	const CK_OBJECT_HANDLE object,
	const CK_ATTRIBUTE_PTR attrs,
	const unsigned count
) {
	CK_RV rv = CKR_FUNCTION_FAILED;
	unsigned i;

	if (
		(rv = certificate_pkcs11->f->C_GetAttributeValue(
			certificate_pkcs11->session_handle,
			object,
			attrs,
			count
		)) != CKR_OK
	) {
		goto cleanup;
	}

	for (i=0;i<count;i++) {
		if (attrs[i].ulValueLen == (CK_ULONG)-1) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto cleanup;
		}
		else if (attrs[i].ulValueLen == 0) {
			attrs[i].pValue = NULL;
		}
		else {
			if (
				(attrs[i].pValue = OPENSSL_zalloc(
					attrs[i].ulValueLen
				)) == NULL
			) {
				rv = CKR_HOST_MEMORY;
				goto cleanup;
			}
		}
	}

	if (
		(rv = certificate_pkcs11->f->C_GetAttributeValue(
			certificate_pkcs11->session_handle,
			object,
			attrs,
			count
		)) != CKR_OK
	) {
		goto cleanup;
	}

cleanup:

	return rv;
}

static
CK_RV
__free_attributes (
	const CK_ATTRIBUTE_PTR attrs,
	const unsigned count
) {
	unsigned i;

	for (i=0;i<count;i++) {
		OPENSSL_free(attrs[i].pValue);
		attrs[i].pValue = NULL;
	}

	return CKR_OK;
}

static
CK_RV
__find_object(
	__mycms_certificate_driver_pkcs11 certificate_pkcs11,
	const CK_ATTRIBUTE * const filter,
	const CK_ULONG filter_attrs,
	CK_OBJECT_HANDLE_PTR object_handle
) {
	int should_FindObjectsFinal = 0;
	CK_ULONG objects_size;
	CK_RV rv = CKR_FUNCTION_FAILED;

	*object_handle = __INVALID_OBJECT_HANDLE;

	if (
		(rv = certificate_pkcs11->f->C_FindObjectsInit(
			certificate_pkcs11->session_handle,
			(CK_ATTRIBUTE_PTR)filter,
			filter_attrs
		)) != CKR_OK
	) {
		goto cleanup;
	}
	should_FindObjectsFinal = 1;

	if ((rv = certificate_pkcs11->f->C_FindObjects(
		certificate_pkcs11->session_handle,
		object_handle,
		1,
		&objects_size
	)) != CKR_OK) {
		goto cleanup;
	}

	if (objects_size == 0) {
		*object_handle = __INVALID_OBJECT_HANDLE;
	}

	rv = CKR_OK;

cleanup:

	if (should_FindObjectsFinal) {
		certificate_pkcs11->f->C_FindObjectsFinal(
			certificate_pkcs11->session_handle
		);
		should_FindObjectsFinal = 0;
	}

	return rv;
}

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
__driver_free(
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
__driver_load(
	const mycms_certificate certificate,
	const mycms_dict parameters
) {
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG slotnum = 0;
	CK_ULONG slot_index;
	CK_RV rv = CKR_FUNCTION_FAILED;

	const char *module = NULL;
	const char *tokenlabel = NULL;
	const char *certlabel = NULL;

	char pin[512];
	char *p;

	int ret = 0;
	int found = 0;

	const int CERT_ATTRS_ID = 0;
	const int CERT_ATTRS_VALUE = 1;
	CK_ATTRIBUTE cert_attrs[] = {
		{CKA_ID, NULL, 0},
		{CKA_VALUE, NULL, 0}
	};

	if ((module = mycms_dict_entry_get(parameters, "module", NULL)) == NULL) {
		goto cleanup;
	}

	if ((tokenlabel = mycms_dict_entry_get(parameters, "token-label", NULL)) == NULL) {
		goto cleanup;
	}

	if ((certlabel = mycms_dict_entry_get(parameters, "cert-label", NULL)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = OPENSSL_zalloc(sizeof(*certificate_pkcs11))) == NULL) {
		goto cleanup;
	}
	certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
	certificate_pkcs11->key_handle = __INVALID_OBJECT_HANDLE;

	if (!mycms_certificate_set_driverdata(certificate, certificate_pkcs11)) {
		goto cleanup;
	}

	if ((rv = __load_provider(certificate_pkcs11, module, mycms_dict_entry_get(parameters, "init-reserved", NULL))) != CKR_OK) {
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
			__fixup_fixed_string(label, (char *)info.label, sizeof(info.label));
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

	{
		CK_OBJECT_CLASS c = CKO_CERTIFICATE;
		const CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, &c, sizeof(c)},
			{CKA_LABEL, certlabel, strlen(certlabel)}
		};
		mycms_blob blob;
		CK_OBJECT_HANDLE o;

		if ((rv = __find_object(
			certificate_pkcs11,
			filter,
			sizeof(filter) / sizeof(*filter),
			&o
		)) != CKR_OK) {
			goto cleanup;
		}

		if (o == __INVALID_OBJECT_HANDLE) {
			goto cleanup;
		}

		if ((rv = __get_object_attributes(
			certificate_pkcs11,
			o,
			cert_attrs,
			sizeof(cert_attrs) / sizeof(*cert_attrs)
		)) != CKR_OK) {
			goto cleanup;
		}

		blob.data = cert_attrs[CERT_ATTRS_VALUE].pValue;
		blob.size = cert_attrs[CERT_ATTRS_VALUE].ulValueLen;
		if (!mycms_certificate_apply_certificate(certificate, &blob)) {
			goto cleanup;
		}
	}

	{
		CK_OBJECT_CLASS c = CKO_PRIVATE_KEY;
		const CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, &c, sizeof(c)},
			{CKA_ID, cert_attrs[CERT_ATTRS_ID].pValue, cert_attrs[CERT_ATTRS_ID].ulValueLen}
		};

		if ((rv = __find_object(
			certificate_pkcs11,
			filter,
			sizeof(filter) / sizeof(*filter),
			&certificate_pkcs11->key_handle
		)) != CKR_OK) {
			goto cleanup;
		}

		if (certificate_pkcs11->key_handle == __INVALID_OBJECT_HANDLE) {
			goto cleanup;
		}
	}

	ret = 1;

cleanup:

	OPENSSL_cleanse(pin, sizeof(pin));

	__free_attributes(
		cert_attrs,
		sizeof(cert_attrs) / sizeof(*cert_attrs)
	);

	OPENSSL_free(slots);
	slots = NULL;

	return ret;
}

const char *
mycms_certificate_driver_pkcs11_usage(void) {
	return (
		"module: PKCS#11 module to load\n"
		"token-label: token label\n"
		"cert-label: certificate label\n"
		"init-reserved: reserved C_Initialize argument\n"
	);
}

int mycms_certificate_driver_pkcs11_apply(
	const mycms_certificate certificate
) {
	mycms_certificate_set_driver_free(certificate, __driver_free);
	mycms_certificate_set_driver_load(certificate, __driver_load);
	mycms_certificate_set_driver_rsa_private_op(certificate, __driver_rsa_private_op);
	return 1;
}

#endif
