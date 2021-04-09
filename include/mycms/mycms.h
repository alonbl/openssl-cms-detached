#ifndef __MYCMS_H
#define __MYCMS_H

#include <stdlib.h>

#include "mycms-certificate.h"
#include "mycms-io.h"
#include "mycms-list.h"
#include "mycms-system.h"

struct mycms_signer_s {
	mycms_blob cert;
	mycms_blob keyid;
	char *digest;
};

MYCMS_LIST_DECLARE(str, char *, str)
MYCMS_LIST_DECLARE(signer, struct mycms_signer_s, signer)

int
mycms_static_init(
	const mycms_system system
);

int
mycms_static_free(void);

mycms
mycms_new(
	const mycms_system system
);

int
mycms_construct(mycms mycms);

int
mycms_destruct(mycms mycms);

mycms_system
mycms_get_system(mycms mycms);

int
mycms_sign(
	mycms mycms __attribute__((unused)),
	const mycms_certificate certificate,
	const mycms_list_str digests,
	const mycms_io cms_in,
	const mycms_io cms_out,
	const mycms_io data_in
);

int
mycms_verify_list_free(
	const mycms mycms,
	const mycms_list_signer l
);

int
mycms_verify_list(
	const mycms mycms,
	const mycms_io cms_in,
	mycms_list_signer * const signers
);

int
mycms_verify(
	const mycms mycms,
	const mycms_io cms_in,
	const mycms_io data_in,
	const mycms_list_signer signers,
	int * const verified
);

int
mycms_encrypt(
	const mycms mycms,
	const char * const cipher_name,
	const mycms_list_blob to,
	const mycms_io cms_out,
	const mycms_io data_pt,
	const mycms_io data_ct
);

int
mycms_encrypt_add(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_list_blob to,
	const mycms_io cms_in,
	const mycms_io cms_out
);

int
mycms_encrypt_reset(
	const mycms mycms,
	const mycms_list_blob to,
	const mycms_io cms_in,
	const mycms_io cms_out
);

int
mycms_decrypt(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_io cms_in,
	const mycms_io data_pt,
	const mycms_io data_ct
);

#endif
