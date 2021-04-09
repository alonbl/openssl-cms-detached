#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef BUILD_WINDOWS
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <stdio.h>
#include <string.h>

#include "mycms-system-driver-core.h"

struct mycms_system_s {
	const void *userdata;
	struct mycms_system_driver_entry_s driver_entries[256];
};

#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT

static
int
__driver_default_explicit_bzero(
	const mycms_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
#if defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(p, size);
#elif defined(HAVE_SECUREZEROMEMORY)
	SecureZeroMemory(p, size);
#else
	memset(p, 0, size);
#endif
	return 1;
}

static
void *
__driver_default_malloc(
	const mycms_system system __attribute__((unused)),
	const size_t size
) {
	return malloc(size);
}
static
void *
__driver_default_realloc(
	const mycms_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
	return realloc(p, size);
}
static
int
__driver_default_free(
	const mycms_system system __attribute__((unused)),
	void * const p
) {
	free(p);
	return 1;
}

#ifdef BUILD_WINDOWS

static
HMODULE
__driver_default_LoadLibraryA(
	const mycms_system system __attribute__((unused)),
	LPCSTR lpLibFileName
) {
	return LoadLibraryA(lpLibFileName);
}
static
BOOL
__driver_default_FreeLibrary(
	const mycms_system system __attribute__((unused)),
	HMODULE hLibModule
) {
	return FreeLibrary(hLibModule);
}
static
FARPROC
__driver_default_GetProcAddress(
	const mycms_system system __attribute__((unused)),
	HMODULE hModule,
	LPCSTR lpProcName
) {
	return GetProcAddress(hModule, lpProcName);
}

#else

static
int
__driver_default_dlclose(
	const mycms_system system __attribute__((unused)),
	void *handle
) {
	return dlclose(handle);
}
static
void *
__driver_default_dlopen(
	const mycms_system system __attribute__((unused)),
	const char *filename,
	int flags
) {
	return dlopen(filename, flags);
}
static
void *
__driver_default_dlsym(
	const mycms_system system __attribute__((unused)),
	void *handle,
	const char *symbol
) {
	return dlsym(handle, symbol);
}

#endif

static
void
__driver_default_CMS_ContentInfo_free(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms
) {
	CMS_ContentInfo_free(cms);
}

static
int
__driver_default_CMS_RecipientInfo_encrypt(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms,
	CMS_RecipientInfo *ri
) {
	return CMS_RecipientInfo_encrypt(cms, ri);
}

static
EVP_PKEY_CTX *
__driver_default_CMS_RecipientInfo_get0_pkey_ctx(
	const mycms_system system __attribute__((unused)),
	CMS_RecipientInfo *ri
) {
	return CMS_RecipientInfo_get0_pkey_ctx(ri);
}

static
int
__driver_default_CMS_RecipientInfo_ktri_cert_cmp(
	const mycms_system system __attribute__((unused)),
	CMS_RecipientInfo *ri,
	X509 *cert
) {
	return CMS_RecipientInfo_ktri_cert_cmp(ri, cert);
}

static
int
__driver_default_CMS_SignerInfo_cert_cmp(
	const mycms_system system __attribute__((unused)),
	CMS_SignerInfo *si,
	X509 *cert
) {
	return CMS_SignerInfo_cert_cmp(si, cert);
}

static
int
__driver_default_CMS_SignerInfo_get0_signer_id(
	const mycms_system system __attribute__((unused)),
	CMS_SignerInfo *si,
	ASN1_OCTET_STRING **keyid,
	X509_NAME **issuer,
	ASN1_INTEGER **sno
) {
	return CMS_SignerInfo_get0_signer_id(si, keyid, issuer, sno);
}

static
int
__driver_default_CMS_SignerInfo_verify_content(
	const mycms_system system __attribute__((unused)),
	CMS_SignerInfo *si,
	BIO *chain
) {
	return CMS_SignerInfo_verify_content(si, chain);
}

static
CMS_RecipientInfo *
__driver_default_CMS_add1_recipient_cert(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms,
	X509 *recip,
	unsigned int flags
) {
	return CMS_add1_recipient_cert(cms, recip, flags);
}

static
CMS_SignerInfo *
__driver_default_CMS_add1_signer(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms,
	X509 *signer,
	EVP_PKEY *pk,
	const EVP_MD *md,
	unsigned int flags
) {
	return CMS_add1_signer(cms, signer, pk, md, flags);
}

static
BIO *
__driver_default_CMS_dataInit(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms,
	BIO *icont
) {
	return CMS_dataInit(cms, icont);
}

static
int
__driver_default_CMS_decrypt(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms,
	EVP_PKEY *pkey,
	X509 *cert,
	BIO *dcont,
	BIO *out,
	unsigned int flags
) {
	return CMS_decrypt(cms, pkey, cert, dcont, out, flags);
}

static
int
__driver_default_CMS_decrypt_set1_pkey(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms,
	EVP_PKEY *pk,
	X509 *cert
) {
	return CMS_decrypt_set1_pkey(cms, pk, cert);
}

static
CMS_ContentInfo *
__driver_default_CMS_encrypt(
	const mycms_system system __attribute__((unused)),
	STACK_OF(X509) *certs,
	BIO *in,
	const EVP_CIPHER *cipher,
	unsigned int flags
) {
	return CMS_encrypt(certs, in, cipher, flags);
}

static
int
__driver_default_CMS_final(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms,
	BIO *data,
	BIO *dcont,
	unsigned int flags
) {
	return CMS_final(cms, data, dcont, flags);
}

static
STACK_OF(CMS_SignerInfo) *
__driver_default_CMS_get0_SignerInfos(
	const mycms_system system __attribute__((unused)),
	CMS_ContentInfo *cms
) {
	return CMS_get0_SignerInfos(cms);
}

static
CMS_ContentInfo *
__driver_default_CMS_sign(
	const mycms_system system __attribute__((unused)),
	X509 *signcert,
	EVP_PKEY *pkey,
	STACK_OF(X509) *certs,
	BIO *data,
	unsigned int flags
) {
	return CMS_sign(signcert, pkey, certs, data, flags);
}

static
CMS_ContentInfo *
__driver_default_d2i_CMS_bio(
	const mycms_system system __attribute__((unused)),
	BIO *bp,
	CMS_ContentInfo **cms
) {
	return d2i_CMS_bio(bp, cms);
}

static
int
__driver_default_i2d_CMS_bio(
	const mycms_system system __attribute__((unused)),
	BIO *bp,
	CMS_ContentInfo *cms
) {
	return i2d_CMS_bio(bp, cms);
}

static
int
__driver_default_i2d_CMS_bio_stream(
	const mycms_system system __attribute__((unused)),
	BIO *out,
	CMS_ContentInfo *cms,
	BIO *in,
	int flags
) {
	return i2d_CMS_bio_stream(out, cms, in, flags);
}

#pragma GCC diagnostic ignored "-Wcast-function-type"
static const struct mycms_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ MYCMS_SYSTEM_DRIVER_ID_core_explicit_bzero, (void(*)()) __driver_default_explicit_bzero},
	{ MYCMS_SYSTEM_DRIVER_ID_core_free, (void (*)()) __driver_default_free},
	{ MYCMS_SYSTEM_DRIVER_ID_core_malloc, (void (*)()) __driver_default_malloc},
	{ MYCMS_SYSTEM_DRIVER_ID_core_realloc, (void (*)()) __driver_default_realloc},

#ifdef BUILD_WINDOWS
	{ MYCMS_SYSTEM_DRIVER_ID_core_FreeLibrary, (void (*)()) __driver_default_FreeLibrary},
	{ MYCMS_SYSTEM_DRIVER_ID_core_GetProcAddress, (void (*)()) __driver_default_GetProcAddress},
	{ MYCMS_SYSTEM_DRIVER_ID_core_LoadLibraryA, (void (*)()) __driver_default_LoadLibraryA},
#else
	{ MYCMS_SYSTEM_DRIVER_ID_core_dlclose, (void (*)()) __driver_default_dlclose},
	{ MYCMS_SYSTEM_DRIVER_ID_core_dlopen, (void (*)()) __driver_default_dlopen},
	{ MYCMS_SYSTEM_DRIVER_ID_core_dlsym, (void (*)()) __driver_default_dlsym},
#endif

	/*
	 * TODO: add add the rest libcrypto entries
	 */

	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_ContentInfo_free, (void (*)()) __driver_default_CMS_ContentInfo_free},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_RecipientInfo_encrypt, (void (*)()) __driver_default_CMS_RecipientInfo_encrypt},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_RecipientInfo_get0_pkey_ctx, (void (*)()) __driver_default_CMS_RecipientInfo_get0_pkey_ctx},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_RecipientInfo_ktri_cert_cmp, (void (*)()) __driver_default_CMS_RecipientInfo_ktri_cert_cmp},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_SignerInfo_cert_cmp, (void (*)()) __driver_default_CMS_SignerInfo_cert_cmp},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_SignerInfo_get0_signer_id, (void (*)()) __driver_default_CMS_SignerInfo_get0_signer_id},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_SignerInfo_verify_content, (void (*)()) __driver_default_CMS_SignerInfo_verify_content},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_add1_recipient_cert, (void (*)()) __driver_default_CMS_add1_recipient_cert},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_add1_signer, (void (*)()) __driver_default_CMS_add1_signer},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_dataInit, (void (*)()) __driver_default_CMS_dataInit},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_decrypt, (void (*)()) __driver_default_CMS_decrypt},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_decrypt_set1_pkey, (void (*)()) __driver_default_CMS_decrypt_set1_pkey},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_encrypt, (void (*)()) __driver_default_CMS_encrypt},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_final, (void (*)()) __driver_default_CMS_final},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_get0_SignerInfos, (void (*)()) __driver_default_CMS_get0_SignerInfos},
	{ MYCMS_SYSTEM_DRIVER_ID_core_CMS_sign, (void (*)()) __driver_default_CMS_sign},
	{ MYCMS_SYSTEM_DRIVER_ID_core_d2i_CMS_bio, (void (*)()) __driver_default_d2i_CMS_bio},
	{ MYCMS_SYSTEM_DRIVER_ID_core_i2d_CMS_bio, (void (*)()) __driver_default_i2d_CMS_bio},
	{ MYCMS_SYSTEM_DRIVER_ID_core_i2d_CMS_bio_stream, (void (*)()) __driver_default_i2d_CMS_bio_stream},

	{ 0, NULL}
};
#pragma GCC diagnostic pop
#else
static const struct mycms_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ 0, NULL}
};
#endif

size_t
mycms_system_get_context_size(void) {
	return sizeof(*(mycms_system)NULL);
}

int
mycms_system_init(
	const mycms_system system,
	const size_t size
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	if (size < mycms_system_get_context_size()) {
		goto cleanup;
	}

	mycms_system_clean(system);
	mycms_system_driver_register(system, __DRIVER_ENTRIES);

	ret = 1;

cleanup:

	return ret;
}

int
mycms_system_clean(
	const mycms_system system
) {
	memset(system, 0, sizeof(*system));
	return 1;
}

int mycms_system_driver_register(
	const mycms_system system,
	const struct mycms_system_driver_entry_s * const entries
) {
	struct mycms_system_driver_entry_s *t;
	const struct mycms_system_driver_entry_s *s;
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	for (t = system->driver_entries; t->id != 0; t++);
	for (s = entries; s->id != 0; s++);
	s++;

	if (s - entries >= system->driver_entries + sizeof(system->driver_entries) / sizeof(*system->driver_entries) - t) {
		goto cleanup;
	}

	memcpy(t, entries, sizeof(*entries) * (s - entries));

cleanup:

	return ret;
}

void (*mycms_system_driver_find(
	const mycms_system system,
	const unsigned id
))() {
	struct mycms_system_driver_entry_s *x;
	void (*ret)() = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	/* TODO: optimize */
	for (x = system->driver_entries; x->id != 0; x++) {
		if (x->id == id) {
			ret = x->f;
		}
	}

cleanup:

	return ret;
}

const void *
mycms_system_get_userdata(
	const mycms_system system
) {
	const void *ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->userdata;

cleanup:

	return ret;
}

int
mycms_system_set_userdata(
	const mycms_system system,
	const void *userdata
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	system->userdata = userdata;

	ret = 1;

cleanup:

	return ret;
}

int
mycms_system_cleanse(
	const mycms_system system,
	void * const p,
	const size_t size
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	mycms_system_driver_core_explicit_bzero(system)(system, p, size);
	ret = 1;

cleanup:

	return ret;
}

void *
mycms_system_malloc(
	const mycms_system system,
	const size_t size
) {
	return mycms_system_driver_core_malloc(system)(system, size);
}

void *
mycms_system_realloc(
	const mycms_system system,
	void * const p,
	const size_t size
) {
	return mycms_system_driver_core_realloc(system)(system, p, size);
}

int
mycms_system_free(
	const mycms_system system,
	void * const p
) {
	mycms_system_driver_core_free(system)(system, p);
	return 1;
}

void *
mycms_system_zalloc(
	const mycms_system system,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	if ((ret = mycms_system_malloc(system, size)) == NULL) {
		goto cleanup;
	}

	mycms_system_cleanse(system, ret, size);

cleanup:

	return ret;
}

char *
mycms_system_strdup(
	const mycms_system system,
	const char * const s
) {
	char *ret = NULL;
	size_t size;

	if (system == NULL) {
		goto cleanup;
	}

	if (s == NULL) {
		return NULL;
	}

	size = strlen(s) + 1;

	if ((ret = mycms_system_malloc(system, size)) == NULL) {
		goto cleanup;
	}

	memcpy(ret, s, size);

cleanup:

	return ret;
}
