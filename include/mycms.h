#ifndef __MYCMS_H
#define __MYCMS_H

#include <stdlib.h>

#include <openssl/bio.h>

#include "mycms-certificate.h"

int
mycms_static_init(void);

int
mycms_static_free(void);

mycms
mycms_new(void);

int
mycms_construct(mycms m);

int
mycms_destroy(mycms m);

int mycms_decrypt(
	const mycms mycms,
	const mycms_certificate certificate,
	BIO *cms_in,
	BIO *data_pt,
	BIO *data_ct
);

int mycms_encrypt(
	const mycms mycms,
	const EVP_CIPHER *cipher,
	const mycms_list_blob to,
	BIO *cms_out,
	BIO *data_pt,
	BIO *data_ct
);

int mycms_encrypt_add(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_list_blob to,
	BIO *cms_in,
	BIO *cms_out
);

#endif
