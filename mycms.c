#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

static X509 *load_cert(const char *file) {
	X509 *c = NULL;
	BIO *bio = NULL;

	if ((bio = BIO_new_file(file, "rb")) == NULL) {
		goto cleanup;
	}

	if ((c = d2i_X509_bio(bio, NULL)) == NULL) {
		goto cleanup;
	}

cleanup:

	if (bio != NULL) {
		BIO_free(bio);
		bio = NULL;
	}

	return c;
}

static EVP_PKEY *load_pkey(const char *file) {
	EVP_PKEY *k = NULL;
	BIO *bio = NULL;

	if ((bio = BIO_new_file(file, "rb")) == NULL) {
		goto cleanup;
	}

	if ((k = d2i_PrivateKey_bio(bio, NULL)) == NULL) {
		goto cleanup;
	}

cleanup:

	if (bio != NULL) {
		BIO_free(bio);
		bio = NULL;
	}

	return k;
}

static STACK_OF(CMS_RecipientInfo) *add_recepients(CMS_ContentInfo *cms, STACK_OF(X509) *to, int flags) {
	STACK_OF(CMS_RecipientInfo) *ret = NULL;
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	int i;

	if ((added = sk_CMS_RecipientInfo_new_null()) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	for (i = 0; i < sk_X509_num(to); i++) {
		X509 *x = sk_X509_value(to, i);
		CMS_RecipientInfo *ri;
		EVP_PKEY_CTX *ctx;

		if ((ri = CMS_add1_recipient_cert(cms, x, flags | CMS_KEY_PARAM)) == NULL) {
			ERR_print_errors_fp(stderr);
			goto cleanup;
		}

		if ((ctx = CMS_RecipientInfo_get0_pkey_ctx(ri)) == NULL) {
			ERR_print_errors_fp(stderr);
			goto cleanup;
		}

		if (!EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)) {
			ERR_print_errors_fp(stderr);
			goto cleanup;
		}

		sk_CMS_RecipientInfo_push(added, ri);
	}

	ret = added;
	added = NULL;

cleanup:
	if (added != NULL) {
		sk_CMS_RecipientInfo_free(added);
		added = NULL;
	}

	return ret;
}

static int encrypt(int argc, char *argv[]) {
	enum {
		OPT_CMS_OUT = 0x1000,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"cms-out", required_argument, NULL, OPT_CMS_OUT},
		{"data-pt", required_argument, NULL, OPT_DATA_PT},
		{"data-ct", required_argument, NULL, OPT_DATA_CT},
		{"to", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	int option;
	int ret = 1;

	const EVP_CIPHER *cipher = EVP_aes_256_cbc();

	STACK_OF(X509) *to = NULL;
	BIO *cms_out = NULL;
	BIO *data_pt = NULL;
	BIO *data_ct = NULL;

	STACK_OF(CMS_RecipientInfo) *added = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;

	if ((to = sk_X509_new_null()) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
			case OPT_CMS_OUT:
				if ((cms_out = BIO_new_file(optarg, "wb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_DATA_PT:
				if ((data_pt = BIO_new_file(optarg, "rb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_DATA_CT:
				if ((data_ct = BIO_new_file(optarg, "wb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_TO:
				{
					X509 *cert = load_cert(optarg);
					if (cert == NULL) {
						ERR_print_errors_fp(stderr);
						goto cleanup;
					}
					sk_X509_push(to, cert);
				}
			break;
			default:
				fprintf(stderr, "Invalid options\n");
				goto cleanup;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}

	if (cms_out == NULL) {
		fprintf(stderr, "Out is mandatory\n");
		goto cleanup;
	}
	if (data_pt == NULL) {
		fprintf(stderr, "Data in is mandatory\n");
		goto cleanup;
	}
	if (data_ct == NULL) {
		fprintf(stderr, "Data out is mandatory\n");
		goto cleanup;
	}

	if ((cms = CMS_encrypt(NULL, NULL, cipher, flags)) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if ((added = add_recepients(cms, to, flags)) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (CMS_final(cms, data_pt, data_ct, flags) <= 0) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (i2d_CMS_bio(cms_out, cms)  <= 0) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (added != NULL) {
		sk_CMS_RecipientInfo_free(added);
		added = NULL;
	}

	if (cms != NULL ) {
		CMS_ContentInfo_free(cms);
		cms = NULL;
	}

	if (cms_out != NULL) {
		BIO_free(cms_out);
		cms_out = NULL;
	}

	if (data_pt != NULL) {
		BIO_free(data_pt);
		data_pt = NULL;
	}

	if (data_ct != NULL) {
		BIO_free(data_ct);
		data_ct = NULL;
	}

	if (to != NULL ) {
		sk_X509_pop_free(to, X509_free);
		to = NULL;
	}

	return ret;
}

static int encrypt_add(int argc, char *argv[]) {
	enum {
		OPT_CMS_IN = 0x1000,
		OPT_CMS_OUT,
		OPT_RECIP_CERT,
		OPT_RECIP_KEY,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"cms-in", required_argument, NULL, OPT_CMS_IN},
		{"cms-out", required_argument, NULL, OPT_CMS_OUT},
		{"recip-cert", required_argument, NULL, OPT_RECIP_CERT},
		{"recip-key", required_argument, NULL, OPT_RECIP_KEY},
		{"to", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	int option;
	int ret = 1;
	int i;

	BIO *cms_in = NULL;
	BIO *cms_out = NULL;
	X509 *recip_x509 = NULL;
	EVP_PKEY *recip_pkey = NULL;
	STACK_OF(X509) *to = NULL;

	STACK_OF(CMS_RecipientInfo) *added = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;


	if ((to = sk_X509_new_null()) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
			case OPT_CMS_IN:
				if ((cms_in = BIO_new_file(optarg, "rb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_CMS_OUT:
				if ((cms_out = BIO_new_file(optarg, "wb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_RECIP_CERT:
				if ((recip_x509 = load_cert(optarg)) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_RECIP_KEY:
				if ((recip_pkey = load_pkey(optarg)) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_TO:
				{
					X509 *cert = load_cert(optarg);
					if (cert == NULL) {
						ERR_print_errors_fp(stderr);
						goto cleanup;
					}
					sk_X509_push(to, cert);
				}
			break;
			default:
				fprintf(stderr, "Invalid options\n");
				goto cleanup;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}

	if (cms_in == NULL) {
		fprintf(stderr, "In is mandatory\n");
		goto cleanup;
	}
	if (cms_out == NULL) {
		fprintf(stderr, "Out is mandatory\n");
		goto cleanup;
	}
	if (recip_x509 == NULL) {
		fprintf(stderr, "Certification is mandatory\n");
		goto cleanup;
	}
	if (recip_pkey == NULL) {
		fprintf(stderr, "Key is mandatory\n");
		goto cleanup;
	}
	if (to == NULL) {
		fprintf(stderr, "To is mandatory\n");
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(cms_in, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, recip_pkey, recip_x509)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if ((added = add_recepients(cms, to, flags)) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	for (i = 0; i < sk_CMS_RecipientInfo_num(added); i++) {
		CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(added, i);

		if (!CMS_RecipientInfo_encrypt(cms, ri)) {
			ERR_print_errors_fp(stderr);
			goto cleanup;
		}
	}

	if (CMS_final(cms, NULL, NULL, flags) <= 0) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (i2d_CMS_bio(cms_out, cms)  <= 0) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (added != NULL) {
		sk_CMS_RecipientInfo_free(added);
		added = NULL;
	}

	if (cms != NULL ) {
		CMS_ContentInfo_free(cms);
		cms = NULL;
	}

	if (cms_in != NULL) {
		BIO_free(cms_in);
		cms_in = NULL;
	}

	if (cms_out != NULL) {
		BIO_free(cms_out);
		cms_out = NULL;
	}

	if (recip_x509 != NULL ) {
		X509_free(recip_x509);
		recip_x509 = NULL;
	}

	if (recip_pkey != NULL ) {
		EVP_PKEY_free(recip_pkey);
		recip_pkey = NULL;
	}

	if (to != NULL ) {
		sk_X509_pop_free(to, X509_free);
		to = NULL;
	}


	return ret;
}

static int decrypt(int argc, char *argv[]) {
	enum {
		OPT_CMS_IN = 0x1000,
		OPT_RECIP_CERT,
		OPT_RECIP_KEY,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"cms-in", required_argument, NULL, OPT_CMS_IN},
		{"recip-cert", required_argument, NULL, OPT_RECIP_CERT},
		{"recip-key", required_argument, NULL, OPT_RECIP_KEY},
		{"data-pt", required_argument, NULL, OPT_DATA_PT},
		{"data-ct", required_argument, NULL, OPT_DATA_CT},
		{NULL, 0, NULL, 0}
	};

	int option;
	int ret = 1;

	BIO *cms_in = NULL;
	X509 *recip_x509 = NULL;
	EVP_PKEY *recip_pkey = NULL;
	BIO *data_pt = NULL;
	BIO *data_ct = NULL;

	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED;

	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
			case OPT_CMS_IN:
				if ((cms_in = BIO_new_file(optarg, "rb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_RECIP_CERT:
				if ((recip_x509 = load_cert(optarg)) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_RECIP_KEY:
				if ((recip_pkey = load_pkey(optarg)) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_DATA_PT:
				if ((data_pt = BIO_new_file(optarg, "wb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_DATA_CT:
				if ((data_ct = BIO_new_file(optarg, "rb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			default:
				fprintf(stderr, "Invalid options\n");
				goto cleanup;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}

	if (cms_in == NULL) {
		fprintf(stderr, "In is mandatory\n");
		goto cleanup;
	}
	if (recip_x509 == NULL) {
		fprintf(stderr, "Certification is mandatory\n");
		goto cleanup;
	}
	if (recip_pkey == NULL) {
		fprintf(stderr, "Key is mandatory\n");
		goto cleanup;
	}
	if (data_pt == NULL) {
		fprintf(stderr, "Data in is mandatory\n");
		goto cleanup;
	}
	if (data_ct == NULL) {
		fprintf(stderr, "Data out is mandatory\n");
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(cms_in, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, recip_pkey, recip_x509)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (!CMS_decrypt(cms, NULL, NULL, data_ct, data_pt, flags)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (cms != NULL ) {
		CMS_ContentInfo_free(cms);
		cms = NULL;
	}

	if (cms_in != NULL) {
		BIO_free(cms_in);
		cms_in = NULL;
	}

	if (recip_x509 != NULL ) {
		X509_free(recip_x509);
		recip_x509 = NULL;
	}

	if (recip_pkey != NULL ) {
		EVP_PKEY_free(recip_pkey);
		recip_pkey = NULL;
	}

	if (data_pt != NULL) {
		BIO_free(data_pt);
		data_pt = NULL;
	}

	if (data_ct != NULL) {
		BIO_free(data_ct);
		data_ct = NULL;
	}

	return ret;
}

int main(int argc, char *argv[]) {
	const char *command;
	int ret = 1;

	ERR_load_crypto_strings();

	if (optind == argc) {
		fprintf(stderr, "Command is missing\n");
		goto cleanup;
	}

	command = argv[optind++];

	if (!strcmp("encrypt", command)) {
		ret = encrypt(argc, argv);
		goto cleanup;
	} else if (!strcmp("encrypt-add", command)) {
		ret = encrypt_add(argc, argv);
		goto cleanup;
	} else if (!strcmp("decrypt", command)) {
		ret = decrypt(argc, argv);
		goto cleanup;
	} else {
		fprintf(stderr, "Unknown command '%s'\n", command);
		goto cleanup;
	}

	ret = 0;
cleanup:

	ERR_free_strings();

	return ret;
}
