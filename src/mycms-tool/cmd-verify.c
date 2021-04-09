#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <mycms/mycms-util-system.h>
#include <mycms/mycms.h>

#include "getoptutil.h"
#include "util.h"

#include "cmd-common.h"
#include "cmd-verify.h"

int
_cmd_verify_list(
	const mycms_system system,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-in\0FILE|input cms", required_argument, NULL, OPT_CMS_IN},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_list_signer signers = NULL;
	mycms_list_signer t = NULL;

	if ((mycms = mycms_new(system)) == NULL) {
		goto cleanup;
	}

	if (!mycms_construct(mycms)) {
		goto cleanup;
	}

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "sign [options]", long_options);
				_cmd_common_extra_usage();
				ret = 0;
				goto cleanup;
			case OPT_CMS_IN:
				if ((cms_in = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(cms_in)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(cms_in, optarg, "rb")) {
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

	if (cms_in == NULL) {
		fprintf(stderr, "CMS in is mandatory\n");
		goto cleanup;
	}

	if (!mycms_verify_list(mycms, cms_in, &signers)) {
		goto cleanup;
	}

	for (t = signers; t != NULL; t = t->next) {
		size_t i;
		for (i = 0; i < t->signer.keyid.size; i++) {
			printf("%02x", t->signer.keyid.data[i]);
		}
		printf(" %s\n", t->signer.digest);
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_verify_list_free(mycms, signers);
	signers = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	return ret;
}

int
_cmd_verify(
	const mycms_system system,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_DATA_IN,
		OPT_DIGEST,
		OPT_CERT,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-in\0FILE|input cms", required_argument, NULL, OPT_CMS_IN},
		{"data-in\0FILE|input text data", required_argument, NULL, OPT_DATA_IN},
		{"digest\0DIGEST|digest to use, default is any", required_argument, NULL, OPT_DIGEST},
		{"cert\0FILE|add certificate to consider", required_argument, NULL, OPT_CERT},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	char *digest = NULL;
	int verified = 0;
	int ret = 1;

	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io data_in = NULL;
	mycms_list_signer signers = NULL;

	if ((mycms = mycms_new(system)) == NULL) {
		goto cleanup;
	}

	if (!mycms_construct(mycms)) {
		goto cleanup;
	}

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "sign [options]", long_options);
				_cmd_common_extra_usage();
				ret = 0;
				goto cleanup;
			case OPT_CMS_IN:
				if ((cms_in = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(cms_in)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(cms_in, optarg, "rb")) {
					goto cleanup;
				}
			break;
			case OPT_DATA_IN:
				if ((data_in = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(data_in)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(data_in, optarg, "rb")) {
					goto cleanup;
				}
			break;
			case OPT_DIGEST:
				digest = optarg;
			break;
			case OPT_CERT:
				{
					mycms_list_signer t;

					if ((t = mycms_system_zalloc(system, sizeof(*t))) == NULL) {
						goto cleanup;
					}
					t->next = signers;
					signers = t;

					if (!_cmd_common_load_cert(system, optarg, &t->signer.cert)) {
						goto cleanup;
					}

					if (digest != NULL) {
						if ((t->signer.digest = mycms_system_strdup(system, digest)) == NULL) {
							goto cleanup;
						}
					}
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

	if (cms_in == NULL) {
		fprintf(stderr, "CMS in is mandatory\n");
		goto cleanup;
	}

	if (!mycms_verify(mycms, cms_in, data_in, signers, &verified)) {
		goto cleanup;
	}

	if (verified) {
		printf("VERIFIED");
	} else {
		printf("FAILED");
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_io_destruct(data_in);
	data_in = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	while(signers != NULL) {
		mycms_list_signer t = signers;
		signers = signers->next;
		t->next = NULL;
		mycms_system_free(system, t->signer.cert.data);
		t->signer.cert.data = NULL;
		mycms_system_free(system, t->signer.digest);
		t->signer.digest = NULL;
		mycms_system_free(system, t);
	}

	return ret;
}
