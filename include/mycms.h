#ifndef __MYCMS_H
#define __MYCMS_H

#include <stdlib.h>

#include <openssl/bio.h>

#include "mycms-certificate.h"

struct mycms_s;
typedef struct mycms_s *mycms;

int
mycms_static_init(void);

int
mycms_static_free(void);

mycms
mycms_create();

int
mycms_initialize(
	const mycms cms
);

int
mycms_destroy(
	const mycms cms
);

int
mycms_set_certificate(
	const mycms cms,
	const mycms_certificate certificate
);

int mycms_encrypt(
	const EVP_CIPHER *cipher,
	const mycms_blob_list to,
	BIO *cms_out,
	BIO *data_pt,
	BIO *data_ct
);

int mycms_encrypt_add(
	const mycms_certificate certificate,
	const mycms_blob_list to,
	BIO *cms_in,
	BIO *cms_out
);

int mycms_decrypt(
	const mycms_certificate certificate,
	BIO *cms_in,
	BIO *data_pt,
	BIO *data_ct
);

#endif
