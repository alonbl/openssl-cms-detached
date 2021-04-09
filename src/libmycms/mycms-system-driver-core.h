#ifndef __MYCMS_SYSTEM_DRIVER_core_H
#define __MYCMS_SYSTEM_DRIVER_core_H

#ifdef BUILD_WINDOWS
#include <windows.h>
#endif

#include <stdlib.h>

#include <openssl/cms.h>

#include <mycms/mycms-system.h>

#include "mycms-system-driver-ids-core.h"

#pragma GCC diagnostic ignored "-Wcast-function-type"
MYCMS_SYSTEM_DRIVER_FUNC(core, void, explicit_bzero, void * const s, size_t size)
MYCMS_SYSTEM_DRIVER_FUNC(core, void *, malloc, size_t size)
MYCMS_SYSTEM_DRIVER_FUNC(core, void *, realloc, void * const p, size_t size)
MYCMS_SYSTEM_DRIVER_FUNC(core, void, free, void * const p)
#ifdef BUILD_WINDOWS
MYCMS_SYSTEM_DRIVER_FUNC(core, HMODULE, LoadLibraryA,
	LPCSTR lpLibFileName)
MYCMS_SYSTEM_DRIVER_FUNC(core, BOOL, FreeLibrary,
	HMODULE hLibModule)
MYCMS_SYSTEM_DRIVER_FUNC(core, FARPROC, GetProcAddress,
	HMODULE hModule,
	LPCSTR lpProcName)
#else
MYCMS_SYSTEM_DRIVER_FUNC(core, int, dlclose, void *handle)
MYCMS_SYSTEM_DRIVER_FUNC(core, void *, dlopen, const char *filename, int flags)
MYCMS_SYSTEM_DRIVER_FUNC(core, void *, dlsym, void *handle, const char *symbol)
#endif

MYCMS_SYSTEM_DRIVER_FUNC(core, void, CMS_ContentInfo_free,
	CMS_ContentInfo *cms)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_RecipientInfo_encrypt,
	CMS_ContentInfo *cms,
	CMS_RecipientInfo *ri)

MYCMS_SYSTEM_DRIVER_FUNC(core, EVP_PKEY_CTX *, CMS_RecipientInfo_get0_pkey_ctx,
	CMS_RecipientInfo *ri)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_RecipientInfo_ktri_cert_cmp,
	CMS_RecipientInfo *ri,
	X509 *cert)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_SignerInfo_cert_cmp,
	CMS_SignerInfo *si,
	X509 *cert)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_SignerInfo_get0_signer_id,
	CMS_SignerInfo *si,
	ASN1_OCTET_STRING **keyid,
	X509_NAME **issuer,
	ASN1_INTEGER **sno)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_SignerInfo_verify_content,
	CMS_SignerInfo *si,
	BIO *chain)

MYCMS_SYSTEM_DRIVER_FUNC(core, CMS_RecipientInfo *, CMS_add1_recipient_cert,
	CMS_ContentInfo *cms,
	X509 *recip,
	unsigned int flags)

MYCMS_SYSTEM_DRIVER_FUNC(core, CMS_SignerInfo *, CMS_add1_signer,
	CMS_ContentInfo *cms,
	X509 *signer,
	EVP_PKEY *pk,
	const EVP_MD *md,
	unsigned int flags)

MYCMS_SYSTEM_DRIVER_FUNC(core, BIO *, CMS_dataInit,
	CMS_ContentInfo *cms,
	BIO *icont)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_decrypt,
	CMS_ContentInfo *cms,
	EVP_PKEY *pkey,
	X509 *cert,
	BIO *dcont,
	BIO *out,
	unsigned int flags)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_decrypt_set1_pkey,
	CMS_ContentInfo *cms,
	EVP_PKEY *pk,
	X509 *cert)

MYCMS_SYSTEM_DRIVER_FUNC(core, CMS_ContentInfo *, CMS_encrypt,
	STACK_OF(X509) *certs,
	BIO *in,
	const EVP_CIPHER *cipher,
	unsigned int flags)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, CMS_final,
	CMS_ContentInfo *cms,
	BIO *data,
	BIO *dcont,
	unsigned int flags)

MYCMS_SYSTEM_DRIVER_FUNC(core, STACK_OF(CMS_SignerInfo) *, CMS_get0_SignerInfos,
	CMS_ContentInfo *cms)

MYCMS_SYSTEM_DRIVER_FUNC(core, CMS_ContentInfo *, CMS_sign,
	X509 *signcert,
	EVP_PKEY *pkey,
	STACK_OF(X509) *certs,
	BIO *data,
	unsigned int flags)

MYCMS_SYSTEM_DRIVER_FUNC(core, CMS_ContentInfo *, d2i_CMS_bio,
	BIO *bp,
	CMS_ContentInfo **cms)

MYCMS_SYSTEM_DRIVER_FUNC(core, int, i2d_CMS_bio,
	BIO *bp,
	CMS_ContentInfo *cms)
MYCMS_SYSTEM_DRIVER_FUNC(core, int, i2d_CMS_bio_stream,
	BIO *out,
	CMS_ContentInfo *cms,
	BIO *in,
	int flags)

#pragma GCC diagnostic pop

#endif
