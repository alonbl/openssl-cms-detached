#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <mycms.h>
#include <mycms-certificate-driver-file.h>

#if defined(ENABLE_CMS_DECRYPT) || defined(ENABLE_CMS_DECRYPT)

static int load_cert(const char * file, mycms_blob *blob) {

	FILE *fp = NULL;
	unsigned char * data = NULL;
	int ret = 0;

	if ((fp = fopen(file, "rb")) == NULL) {
		goto cleanup;
	}

	if (fseek(fp, 0L, SEEK_END) != 0) {
		goto cleanup;
	}
	{
		long l;
		if ((l = ftell(fp)) == -1) {
			goto cleanup;
		}
		blob->size = l;
	}
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		goto cleanup;
	}

	if ((data = OPENSSL_zalloc(blob->size)) == NULL) {
		goto cleanup;
	}

	if (fread(data, blob->size, 1, fp) != 1) {
		goto cleanup;
	}

	blob->data = data;
	data = NULL;
	ret = 1;

cleanup:
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}

	if (data != NULL) {
		OPENSSL_free(data);
		data = NULL;
	}

	return ret;
}

#endif

#if defined(ENABLE_CMS_ENCRYPT)

static int cmd_encrypt(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_OUT,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help", no_argument, NULL, OPT_HELP},
		{"cms-out", required_argument, NULL, OPT_CMS_OUT},
		{"data-pt", required_argument, NULL, OPT_DATA_PT},
		{"data-ct", required_argument, NULL, OPT_DATA_CT},
		{"to", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	int option;
	int ret = 1;

	const EVP_CIPHER *cipher = EVP_aes_256_cbc();

	mycms_blob_list to = NULL;
	BIO *cms_out = NULL;
	BIO *data_pt = NULL;
	BIO *data_ct = NULL;

	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				printf("help\n");
				ret = 0;
				goto cleanup;
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
					mycms_blob_list t;

					if ((t = OPENSSL_zalloc(sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!load_cert(optarg, &t->blob)) {
						OPENSSL_free(t);
						goto cleanup;
					}

					t->next = to;
					to = t;
				}
			break;
			default:
				fprintf(stderr, "Invalid option\n");
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

	if (mycms_encrypt(cipher, to, cms_out, data_pt, data_ct)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

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

	while(to != NULL) {
		mycms_blob_list t = to;
		to = to->next;
		t->next = NULL;
		OPENSSL_free(t->blob.data);
		t->blob.data = NULL;
		OPENSSL_free(t);
	}

	return ret;
}


static int cmd_encrypt_add(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_CMS_OUT,
		OPT_RECIP_CERT,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help", no_argument, NULL, OPT_HELP},
		{"cms-in", required_argument, NULL, OPT_CMS_IN},
		{"cms-out", required_argument, NULL, OPT_CMS_OUT},
		{"recip-cert", required_argument, NULL, OPT_RECIP_CERT},
		{"to", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	int option;
	int ret = 1;

	BIO *cms_in = NULL;
	BIO *cms_out = NULL;
	mycms_blob_list to = NULL;

	mycms_certificate certificate = NULL;

	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				printf("help\n");
				ret = 0;
				goto cleanup;
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
				if (certificate != NULL) {
					fprintf(stderr, "Recipient already specified\n");
					goto cleanup;
				}

				if ((certificate = mycms_certificate_new()) == NULL) {
					goto cleanup;
				}

				if (!mycms_certificate_construct(certificate)) {
					goto cleanup;
				}

				if (!mycms_certificate_driver_file_apply(certificate)) {
					goto cleanup;
				}

				if (!mycms_certificate_load(certificate, optarg)) {
					goto cleanup;
				}
			break;
			case OPT_TO:
				{
					mycms_blob_list t;

					if ((t = OPENSSL_zalloc(sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!load_cert(optarg, &t->blob)) {
						OPENSSL_free(t);
						goto cleanup;
					}

					t->next = to;
					to = t;
				}
			break;
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}
	if (certificate == NULL) {
		fprintf(stderr, "Certificate is mandatory\n");
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
	if (to == NULL) {
		fprintf(stderr, "To is mandatory\n");
		goto cleanup;
	}

	if (mycms_encrypt_add(certificate, to, cms_in, cms_out)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (certificate != NULL) {
		mycms_certificate_destroy(certificate);
		certificate = NULL;
	}

	if (cms_in != NULL) {
		BIO_free(cms_in);
		cms_in = NULL;
	}

	if (cms_out != NULL) {
		BIO_free(cms_out);
		cms_out = NULL;
	}

	while(to != NULL) {
		mycms_blob_list t = to;
		to = to->next;
		t->next = NULL;
		OPENSSL_free(t->blob.data);
		t->blob.data = NULL;
		OPENSSL_free(t);
	}

	return ret;
}

#endif

#if defined(ENABLE_CMS_DECRYPT)

static int cmd_decrypt(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_RECIP_CERT,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help", no_argument, NULL, OPT_HELP},
		{"cms-in", required_argument, NULL, OPT_CMS_IN},
		{"recip-cert", required_argument, NULL, OPT_RECIP_CERT},
		{"data-pt", required_argument, NULL, OPT_DATA_PT},
		{"data-ct", required_argument, NULL, OPT_DATA_CT},
		{NULL, 0, NULL, 0}
	};

	int option;
	int ret = 1;

	BIO *cms_in = NULL;
	BIO *data_pt = NULL;
	BIO *data_ct = NULL;

	mycms_certificate certificate = NULL;

	while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				printf("help\n");
				ret = 0;
				goto cleanup;
			case OPT_CMS_IN:
				if ((cms_in = BIO_new_file(optarg, "rb")) == NULL) {
					ERR_print_errors_fp(stderr);
					goto cleanup;
				}
			break;
			case OPT_RECIP_CERT:
				if (certificate != NULL) {
					fprintf(stderr, "Recipient already specified\n");
					goto cleanup;
				}

				if ((certificate = mycms_certificate_new()) == NULL) {
					goto cleanup;
				}

				if (!mycms_certificate_construct(certificate)) {
					goto cleanup;
				}

				if (!mycms_certificate_driver_file_apply(certificate)) {
					goto cleanup;
				}

				if (!mycms_certificate_load(certificate, optarg)) {
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
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}
	if (certificate == NULL) {
		fprintf(stderr, "Certificate is mandatory\n");
		goto cleanup;
	}
	if (cms_in == NULL) {
		fprintf(stderr, "In is mandatory\n");
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

	if (mycms_decrypt(certificate, cms_in, data_pt, data_ct)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	if (certificate != NULL) {
		mycms_certificate_destroy(certificate);
		certificate = NULL;
	}

	if (cms_in != NULL) {
		BIO_free(cms_in);
		cms_in = NULL;
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

#endif

int main(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_SHOW_COMMANDS,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help", no_argument, NULL, OPT_HELP},
		{"show-commands", no_argument, NULL, OPT_SHOW_COMMANDS},
		{NULL, 0, NULL, 0}
	};

	const char *command;
	int option;
	int ret = 1;

	if (!mycms_static_init()) {
		fprintf(stderr, "Failed to initialize certificate interface\n");
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, "+", long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				printf("help\n");
				ret = 0;
				goto cleanup;
			case OPT_SHOW_COMMANDS:
#if defined(ENABLE_CMS_DECRYPT)
				printf("decrypt\n");
#endif
#if defined(ENABLE_CMS_ENCRYPT)
				printf("encrypt\n");
#endif
				ret = 0;
				goto cleanup;
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Command is missing\n");
		goto cleanup;
	}

	command = argv[optind++];

	if (0) {
#if defined(ENABLE_CMS_ENCRYPT)
	} else if (!strcmp("encrypt", command)) {
		ret = cmd_encrypt(argc, argv);
	} else if (!strcmp("encrypt-add", command)) {
		ret = cmd_encrypt_add(argc, argv);
#endif
#if defined(ENABLE_CMS_DECRYPT)
	} else if (!strcmp("decrypt", command)) {
		ret = cmd_decrypt(argc, argv);
#endif
	} else {
		fprintf(stderr, "Unknown command '%s'\n", command);
	}

cleanup:

	mycms_static_free();

	return ret;
}
