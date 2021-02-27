#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef BUILD_WINDOWS
#include <windows.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms/mycms-list.h>
#include <mycms/mycms-certificate-driver-pkcs11.h>

#include "mycms-private.h"
#include "pkcs11.h"

#define __INVALID_SESSION_HANDLE	((CK_SESSION_HANDLE)-1)
#define __INVALID_OBJECT_HANDLE		((CK_OBJECT_HANDLE)-1)

struct __pkcs11_provider_s {
	char *name;
	int reference_count;
#ifdef BUILD_WINDOWS
	HANDLE module_handle;
#else
	void *module_handle;
#endif
	int should_finalize;
	CK_FUNCTION_LIST_PTR f;
};

MYCMS_LIST_DECLARE(pkcs11_provider, struct __pkcs11_provider_s, entry)

struct __mycms_certificate_driver_pkcs11_s {
	struct __pkcs11_provider_s *p;
	char *token_label;
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE key_handle;
	int protected_auth;
	int login_required;
	int always_authenticate;
	mycms_blob id;

	int assume_loggedin;
	int key_attributes_valid;
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
__get_object_attributes(
	const mycms_system system,
	const __mycms_certificate_driver_pkcs11 certificate_pkcs11,
	const CK_OBJECT_HANDLE object,
	const CK_ATTRIBUTE_PTR attrs,
	const unsigned count
) {
	CK_RV rv = CKR_FUNCTION_FAILED;
	unsigned i;

	if (certificate_pkcs11->session_handle == __INVALID_SESSION_HANDLE) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetAttributeValue(
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
				(attrs[i].pValue = mycms_system_zalloc(
					system,
					attrs[i].ulValueLen
				)) == NULL
			) {
				rv = CKR_HOST_MEMORY;
				goto cleanup;
			}
		}
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetAttributeValue(
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
	const mycms_system system,
	const CK_ATTRIBUTE_PTR attrs,
	const unsigned count
) {
	unsigned i;

	for (i=0;i<count;i++) {
		mycms_system_free(system, attrs[i].pValue);
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

	if (certificate_pkcs11->session_handle == __INVALID_SESSION_HANDLE) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_FindObjectsInit(
			certificate_pkcs11->session_handle,
			(CK_ATTRIBUTE_PTR)filter,
			filter_attrs
		)) != CKR_OK
	) {
		goto cleanup;
	}
	should_FindObjectsFinal = 1;

	if ((rv = certificate_pkcs11->p->f->C_FindObjects(
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
		certificate_pkcs11->p->f->C_FindObjectsFinal(
			certificate_pkcs11->session_handle
		);
		should_FindObjectsFinal = 0;
	}

	return rv;
}

static
void
__unload_provider(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;

	mycms_list_pkcs11_provider head;
	int found;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	head = (mycms_list_pkcs11_provider)_mycms_get_pkcs11_state(mycms_certificate_get_mycms(certificate));
	found = 1;
	while (found) {
		mycms_list_pkcs11_provider p;
		mycms_list_pkcs11_provider t;
		found = 0;

		for (
			p = NULL, t = head;
			t != NULL;
			p = t, t = t->next
		) {
			if (t->entry.reference_count == 0) {
				break;
			}
		}

		if (t != NULL) {
			if (p == NULL) {
				head = t->next;
			} else {
				p->next = t->next;
			}


			if (t->entry.should_finalize) {
				t->entry.f->C_Finalize(NULL);
				t->entry.should_finalize = 0;
			}
			t->entry.f = NULL;
			if (t->entry.module_handle != NULL) {
#if BUILD_WINDOWS
				mycms_system_get_driver(system)->FreeLibrary(system, t->entry.module_handle);
#else
				mycms_system_get_driver(system)->dlclose(
					system,
					t->entry.module_handle
				);
#endif
				t->entry.module_handle = NULL;
			}
			mycms_system_free(system, t->entry.name);
			mycms_system_free(system, t);
			t = NULL;
		}
	}

	_mycms_set_pkcs11_state(mycms_certificate_get_mycms(certificate), head);

cleanup:
	;
}

static
struct __pkcs11_provider_s *
__load_provider(
	const mycms_certificate certificate,
	const char * const module,
	const char * const reserved
) {
	mycms_system system = NULL;
	mycms_list_pkcs11_provider t = NULL;
	mycms_list_pkcs11_provider pkcs11_provider = NULL;
	CK_C_GetFunctionList gfl = NULL;
	CK_C_INITIALIZE_ARGS initargs;
	CK_C_INITIALIZE_ARGS_PTR pinitargs = NULL;
	CK_RV rv;
	struct __pkcs11_provider_s *ret = NULL;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	for (
		t = (mycms_list_pkcs11_provider)_mycms_get_pkcs11_state(mycms_certificate_get_mycms(certificate));
		t != NULL;
		t = t->next
	) {
		if (!strcmp(t->entry.name, module)) {
			break;
		}
	}

	if (t != NULL) {
		pkcs11_provider = t;
	} else {
		if ((pkcs11_provider = mycms_system_zalloc(system, sizeof(*pkcs11_provider))) == NULL) {
			goto cleanup;
		}

		if ((pkcs11_provider->entry.name = mycms_system_strdup(system, module)) == NULL) {
			goto cleanup;
		}

		pkcs11_provider->next = (mycms_list_pkcs11_provider)_mycms_get_pkcs11_state(mycms_certificate_get_mycms(certificate));
		_mycms_set_pkcs11_state(mycms_certificate_get_mycms(certificate), pkcs11_provider);

#ifdef BUILD_WINDOWS
		if ((pkcs11_provider->entry.module_handle = mycms_system_get_driver(system)->LoadLibraryA(system, module)) == NULL) {
			goto cleanup;
		}

		{
			FARPROC p;

			/*
			 * Make compiler happy!
			 */
			p = mycms_system_get_driver(system)->GetProcAddress(
				system,
				pkcs11_provider->entry.module_handle,
				"C_GetFunctionList"
			);

			memmove(&gfl, &p, sizeof(gfl));
		}
#else
		if ((pkcs11_provider->entry.module_handle = mycms_system_get_driver(system)->dlopen(
			system,
			module,
			RTLD_NOW | RTLD_LOCAL
		)) == NULL) {
			goto cleanup;
		}

		{
			void *p;

			/*
			 * Make compiler happy!
			 */
			p = mycms_system_get_driver(system)->dlsym(
				system,
				pkcs11_provider->entry.module_handle,
				"C_GetFunctionList"
			);
			memmove(&gfl, &p, sizeof(gfl));
		}
#endif

		if (gfl == NULL) {
			goto cleanup;
		}

		if ((rv = gfl(&pkcs11_provider->entry.f)) != CKR_OK) {
			goto cleanup;
		}

		memset(&initargs, 0, sizeof(initargs));
		if (reserved != NULL) {
			initargs.pReserved = (char *)reserved;
			pinitargs = &initargs;
		}

		if ((rv = pkcs11_provider->entry.f->C_Initialize(pinitargs)) != CKR_OK) {
			if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				goto cleanup;
			}
		}
		else {
			pkcs11_provider->entry.should_finalize = 1;
		}
	}

	pkcs11_provider->entry.reference_count++;
	ret = &pkcs11_provider->entry;
	pkcs11_provider = NULL;

cleanup:
	__unload_provider(certificate);

	return ret;
}

static
CK_RV
__common_login(
	const mycms_certificate certificate,
	const CK_USER_TYPE user,
	const char * const what
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	char pin[512];
	char *p;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	if (certificate_pkcs11->session_handle == __INVALID_SESSION_HANDLE) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto cleanup;
	}

	if (certificate_pkcs11->protected_auth) {
		if ((rv = certificate_pkcs11->p->f->C_Login (
			certificate_pkcs11->session_handle,
			user,
			NULL_PTR,
			0
		)) != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			goto cleanup;
		}
	} else {
		p = pin;
		if (!mycms_certificate_aquire_passphrase(certificate, what, &p, sizeof(pin))) {
			goto cleanup;
		}

		if ((rv = certificate_pkcs11->p->f->C_Login (
			certificate_pkcs11->session_handle,
			user,
			(CK_UTF8CHAR_PTR)p,
			p == NULL ? 0 : strlen(p)
		)) != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			goto cleanup;
		}
	}

	rv = CKR_OK;

cleanup:
	mycms_system_cleanse(system, pin, sizeof(pin));

	return rv;
}

static
CK_RV
__context_login(
	const mycms_certificate certificate
) {
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_RV rv = CKR_FUNCTION_FAILED;

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	if (certificate_pkcs11->always_authenticate) {
		if ((rv = __common_login(certificate, CKU_CONTEXT_SPECIFIC, "key")) != CKR_OK) {
			goto cleanup;
		}
	}

	rv = CKR_OK;

cleanup:

	return rv;
}

static
int
__open_slot(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG slotnum = 0;
	CK_ULONG slot_index;
	CK_RV rv = CKR_FUNCTION_FAILED;

	int found;
	int ret = 0;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetSlotList (
			CK_TRUE,
			NULL_PTR,
			&slotnum
		)) != CKR_OK
	) {
		goto cleanup;
	}

	if ((slots = mycms_system_zalloc(system, sizeof(*slots) * slotnum)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetSlotList (
			CK_TRUE,
			slots,
			&slotnum
		)) != CKR_OK
	) {
		goto cleanup;
	}

	for (
		found = 0, slot_index = 0;
		(
			slot_index < slotnum &&
			!found
		);
		slot_index++
	) {
		CK_TOKEN_INFO info;

		if ((rv = certificate_pkcs11->p->f->C_GetTokenInfo (
			slots[slot_index],
			&info
		)) != CKR_OK) {
		} else {
			char label[sizeof(info.label)+1];
			__fixup_fixed_string(label, (char *)info.label, sizeof(info.label));
			if (!strcmp(label, certificate_pkcs11->token_label)) {
				found = 1;
				certificate_pkcs11->protected_auth = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? 1 : 0;
				certificate_pkcs11->login_required = (info.flags & CKF_LOGIN_REQUIRED) ? 1 : 0;
				break;
			}
		}
	}

	if (!found) {
		goto cleanup;
	}

	if ((rv = certificate_pkcs11->p->f->C_OpenSession (
		slots[slot_index],
		CKF_SERIAL_SESSION,
		NULL_PTR,
		NULL_PTR,
		&certificate_pkcs11->session_handle
	)) != CKR_OK) {
		certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
		goto cleanup;
	}

	ret = 1;

cleanup:

	mycms_system_free(system, slots);
	slots = NULL;

	return ret;
}

static
int
__open_private_key(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_ATTRIBUTE key_attrs[] = {
		{CKA_ALWAYS_AUTHENTICATE, NULL, 0}
	};
	CK_RV rv = CKR_FUNCTION_FAILED;

	int retry;
	int ret = 0;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	retry = 3;
	while(retry--) {
		if (!certificate_pkcs11->assume_loggedin && certificate_pkcs11->login_required) {
			if ((rv = __common_login(certificate, CKU_USER, "token")) != CKR_OK) {
				switch (rv) {
					case CKR_SESSION_CLOSED:
					case CKR_SESSION_HANDLE_INVALID:
					case CKR_USER_NOT_LOGGED_IN:
						goto retry;
					default:
						goto cleanup;
				}
			}
			certificate_pkcs11->assume_loggedin = 1;
		}

		if (!certificate_pkcs11->key_attributes_valid) {
			CK_OBJECT_CLASS c = CKO_PRIVATE_KEY;
			const CK_ATTRIBUTE filter[] = {
				{CKA_CLASS, &c, sizeof(c)},
				{CKA_ID, certificate_pkcs11->id.data, certificate_pkcs11->id.size}
			};

			if ((rv = __find_object(
				certificate_pkcs11,
				filter,
				sizeof(filter) / sizeof(*filter),
				&certificate_pkcs11->key_handle
			)) != CKR_OK) {
				switch (rv) {
					case CKR_SESSION_CLOSED:
					case CKR_SESSION_HANDLE_INVALID:
					case CKR_USER_NOT_LOGGED_IN:
						goto retry;
					default:
						goto cleanup;
				}
				goto cleanup;
			}

			if (certificate_pkcs11->key_handle == __INVALID_OBJECT_HANDLE) {
				goto cleanup;
			}

			if ((rv = __get_object_attributes(
				system,
				certificate_pkcs11,
				certificate_pkcs11->key_handle,
				key_attrs,
				sizeof(key_attrs) / sizeof(*key_attrs)
			)) == CKR_OK) {
				certificate_pkcs11->always_authenticate = *(CK_BBOOL *)key_attrs[0].pValue != 0;
			}

			certificate_pkcs11->key_attributes_valid = 1;
		}

		break;

	retry:

		certificate_pkcs11->assume_loggedin = 0;
		if (!__open_slot(certificate)) {
			goto cleanup;
		}
	}

	ret = 1;

cleanup:

	__free_attributes(
		system,
		key_attrs,
		sizeof(key_attrs) / sizeof(*key_attrs)
	);

	return ret;
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
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_MECHANISM mech = {
		0, NULL, 0
	};
	CK_ULONG size;
	CK_RV rv = CKR_FUNCTION_FAILED;
	int ret = -1;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
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

	if ((mech.mechanism = __convert_padding(padding)) == CKR_MECHANISM_INVALID) {
		goto cleanup;
	}

	if (!__open_private_key(certificate)) {
		goto cleanup;
	}

	switch (op) {
		case MYCMS_PRIVATE_OP_ENCRYPT:
			if ((rv = certificate_pkcs11->p->f->C_SignInit (
				certificate_pkcs11->session_handle,
				&mech,
				certificate_pkcs11->key_handle
			)) != CKR_OK) {
				goto cleanup;
			}
			if ((rv = __context_login(certificate)) != CKR_OK) {
				goto cleanup;
			}
			size = to_size;
			if ((rv = certificate_pkcs11->p->f->C_Sign (
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
			if ((rv = certificate_pkcs11->p->f->C_DecryptInit (
				certificate_pkcs11->session_handle,
				&mech,
				certificate_pkcs11->key_handle
			)) != CKR_OK) {
				goto cleanup;
			}
			if ((rv = __context_login(certificate)) != CKR_OK) {
				goto cleanup;
			}
			size = to_size;
			if ((rv = certificate_pkcs11->p->f->C_Decrypt (
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
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;
	int ret = 0;

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	certificate_pkcs11->key_handle = __INVALID_OBJECT_HANDLE;
	if (certificate_pkcs11->session_handle != __INVALID_SESSION_HANDLE) {
		certificate_pkcs11->p->f->C_Logout(certificate_pkcs11->session_handle);
		certificate_pkcs11->p->f->C_CloseSession(certificate_pkcs11->session_handle);
		certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
	}

	mycms_system_free(system, certificate_pkcs11->id.data);
	certificate_pkcs11->id.data = NULL;

	mycms_system_free(system, certificate_pkcs11->token_label);
	certificate_pkcs11->token_label = NULL;

	if (certificate_pkcs11->p != NULL) {
		certificate_pkcs11->p->reference_count--;
		certificate_pkcs11->p = NULL;
	}
	mycms_system_free(system, certificate_pkcs11);

	__unload_provider(certificate);

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
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_RV rv = CKR_FUNCTION_FAILED;

	const char *module = NULL;
	const char *token_label = NULL;
	const char *certlabel = NULL;

	int ret = 0;

	const int CERT_ATTRS_ID = 0;
	const int CERT_ATTRS_VALUE = 1;
	CK_ATTRIBUTE cert_attrs[] = {
		{CKA_ID, NULL, 0},
		{CKA_VALUE, NULL, 0}
	};

	if (certificate == NULL) {
		goto cleanup;
	}

	if (parameters == NULL) {
		goto cleanup;
	}

	if ((system = mycms_certificate_get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((module = mycms_dict_entry_get(parameters, "module", NULL)) == NULL) {
		goto cleanup;
	}

	if ((token_label = mycms_dict_entry_get(parameters, "token-label", NULL)) == NULL) {
		goto cleanup;
	}

	if ((certlabel = mycms_dict_entry_get(parameters, "cert-label", NULL)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = mycms_system_zalloc(system, sizeof(*certificate_pkcs11))) == NULL) {
		goto cleanup;
	}
	certificate_pkcs11->token_label = mycms_system_strdup(system, token_label);
	certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
	certificate_pkcs11->key_handle = __INVALID_OBJECT_HANDLE;

	if (!mycms_certificate_set_driverdata(certificate, certificate_pkcs11)) {
		goto cleanup;
	}

	if ((certificate_pkcs11->p = __load_provider(certificate, module, mycms_dict_entry_get(parameters, "init-reserved", NULL))) == NULL) {
		goto cleanup;
	}

	if (!__open_slot(certificate)) {
		goto cleanup;
	}

	{
		CK_OBJECT_CLASS c = CKO_CERTIFICATE;
		const CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, &c, sizeof(c)},
			{CKA_LABEL, (char *)certlabel, strlen(certlabel)}
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
			system,
			certificate_pkcs11,
			o,
			cert_attrs,
			sizeof(cert_attrs) / sizeof(*cert_attrs)
		)) != CKR_OK) {
			goto cleanup;
		}

		certificate_pkcs11->id.size = cert_attrs[CERT_ATTRS_ID].ulValueLen;
		if ((certificate_pkcs11->id.data = mycms_system_malloc(system, certificate_pkcs11->id.size)) == NULL) {
			goto cleanup;
		}
		memcpy(certificate_pkcs11->id.data, cert_attrs[CERT_ATTRS_ID].pValue, certificate_pkcs11->id.size);
		blob.data = cert_attrs[CERT_ATTRS_VALUE].pValue;
		blob.size = cert_attrs[CERT_ATTRS_VALUE].ulValueLen;
		if (!mycms_certificate_apply_certificate(certificate, &blob)) {
			goto cleanup;
		}
	}

	ret = 1;

cleanup:

	__free_attributes(
		system,
		cert_attrs,
		sizeof(cert_attrs) / sizeof(*cert_attrs)
	);

	return ret;
}

const char *
mycms_certificate_driver_pkcs11_usage(void) {
	return (
		"CERTIFICATE EXPRESSION ATTRIBUTES\n"
		"module: PKCS#11 module to load\n"
		"token-label: token label\n"
		"cert-label: certificate label\n"
		"init-reserved: reserved C_Initialize argument\n"
		"\n"
		"PASSPHRASE EXPRESSION WHAT\n"
		"token: token passphrase\n"
		"key: key passphrase\n"
	);
}

int mycms_certificate_driver_pkcs11_apply(
	const mycms_certificate certificate
) {
	int ret = 0;

	if (!mycms_certificate_set_driver_free(certificate, __driver_free)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_driver_load(certificate, __driver_load)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_driver_rsa_private_op(certificate, __driver_rsa_private_op)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}
