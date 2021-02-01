#ifndef __MYCMS_H
#define __MYCMS_H

#include <stdlib.h>

#include <openssl/bio.h>

#include "mycms-certificate.h"
#include "mycms-system.h"

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

int mycms_decrypt(
	const mycms mycms,
	const mycms_certificate certificate,
	BIO *cms_in,
	BIO *data_pt,
	BIO *data_ct
);

int mycms_encrypt(
	const mycms mycms,
	const char * const cipher,
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
