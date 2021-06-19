#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <mycms/mycms.h>

#include "mycms-certificate-private.h"
#include "mycms-io-private.h"
#include "mycms-system-driver-core.h"

int
mycms_sign(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_list_str digests,
	const mycms_dict keyopt,
	const mycms_io cms_in,
	const mycms_io cms_out,
	const mycms_io data_in
) {
	mycms_system system = NULL;
	CMS_ContentInfo *cms = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	mycms_list_str t;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_USE_KEYID | CMS_NOCERTS | CMS_NOSMIMECAP;
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	if (certificate == NULL) {
		goto cleanup;
	}

	if (cms_in == NULL) {
		flags |= CMS_PARTIAL;
		if ((cms = mycms_system_driver_core_CMS_sign(system)(system, NULL, NULL, NULL, NULL, flags)) == NULL) {
			goto cleanup;
		}
	} else {
		if ((cms = mycms_system_driver_core_d2i_CMS_bio(system)(system, _mycms_io_get_BIO(cms_in), NULL)) == NULL) {
			goto cleanup;
		}
	}

	if (data_in == NULL) {
		flags |= CMS_REUSE_DIGEST;
	}

	for (t = digests;t != NULL; t = t->next) {
		const EVP_MD *digest = NULL;
		CMS_SignerInfo *signer = NULL;
		mycms_list_dict_entry opt;

		if ((digest = EVP_get_digestbyname(t->str)) == NULL) {
			goto cleanup;
		}

		if ((signer = mycms_system_driver_core_CMS_add1_signer(system)(
			system,
			cms,
			_mycms_certificate_get_X509(certificate),
			_mycms_certificate_get_EVP_PKEY(certificate),
			digest,
			flags | (mycms_dict_entries(keyopt) == NULL ? 0 : CMS_KEY_PARAM) /* Does not work for 2nd sign, see https://github.com/openssl/openssl/issues/14257 */
		)) == NULL) {
			goto cleanup;
		}

		if (mycms_dict_entries(keyopt) != NULL) { /* TODO: remove when openssl bug fixed */
			if ((ctx = CMS_SignerInfo_get0_pkey_ctx(signer)) == NULL) {
				goto cleanup;
			}

			for (opt = mycms_dict_entries(keyopt); opt != NULL; opt = opt->next) {
				if (!EVP_PKEY_CTX_ctrl_str(ctx, opt->entry.k, opt->entry.v)) {
					goto cleanup;
				}
			}
		}
	}

	if (cms_in != NULL) {
		if (!mycms_system_driver_core_i2d_CMS_bio_stream(system)(system, _mycms_io_get_BIO(cms_out), cms, _mycms_io_get_BIO(data_in), flags)) {
			goto cleanup;
		}
	} else {
		if (!mycms_system_driver_core_CMS_final(system)(system, cms, _mycms_io_get_BIO(data_in), NULL, flags)) {
			goto cleanup;
		}
		if (mycms_system_driver_core_i2d_CMS_bio(system)(system, _mycms_io_get_BIO(cms_out), cms) <= 0) {
			goto cleanup;
		}
	}

	ret = 1;

cleanup:

	mycms_system_driver_core_CMS_ContentInfo_free(system)(system, cms);
	cms = NULL;

	return ret;
}
