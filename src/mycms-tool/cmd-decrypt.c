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
#include "cmd-decrypt.h"

int
_cmd_decrypt(
	const mycms_system system,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_RECIP_CERT,
		OPT_RECIP_CERT_PASS,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-in\0FILE|input cms", required_argument, NULL, OPT_CMS_IN},
		{"recip-cert\0CERTIFICATE_EXPRESSION|recipient certificate to use", required_argument, NULL, OPT_RECIP_CERT},
		{"recip-cert-pass\0PASSPHRASE_EXPRESSION|recipient certificate passphrase to use", required_argument, NULL, OPT_RECIP_CERT_PASS},
		{"data-ct\0FILE|input ciphered text data", required_argument, NULL, OPT_DATA_CT},
		{"data-pt\0FILE|output plain text data", required_argument, NULL, OPT_DATA_PT},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char * certificate_exp = NULL;
	const char * pass_exp = NULL;

	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io data_pt = NULL;
	mycms_io data_ct = NULL;
	mycms_dict certificate_dict = NULL;
	mycms_dict pass_dict = NULL;
	mycms_certificate certificate = NULL;

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
				getoptutil_usage(stdout, argv[0], "decrypt [options]", long_options);
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
			case OPT_RECIP_CERT:
				certificate_exp = optarg;
			break;
			case OPT_RECIP_CERT_PASS:
				pass_exp = optarg;
			break;
			case OPT_DATA_PT:
				if ((data_pt = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(data_pt)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(data_pt, optarg, "wb")) {
					goto cleanup;
				}
			break;
			case OPT_DATA_CT:
				if ((data_ct = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(data_ct)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(data_ct, optarg, "rb")) {
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
	if (certificate_exp == NULL) {
		fprintf(stderr, "Certificate is mandatory\n");
		goto cleanup;
	}
	if (cms_in == NULL) {
		fprintf(stderr, "CMS in is mandatory\n");
		goto cleanup;
	}

	if (data_pt == NULL) {
		fprintf(stderr, "Data PT is mandatory\n");
		goto cleanup;
	}
	if (data_ct == NULL) {
		fprintf(stderr, "Data CT is mandatory\n");
		goto cleanup;
	}

	if ((certificate_dict = mycms_dict_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(certificate_dict)) {
		goto cleanup;
	}

	if (!util_split_string(certificate_dict, certificate_exp)) {
		goto cleanup;
	}

	if ((pass_dict = mycms_dict_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(pass_dict)) {
		goto cleanup;
	}

	if (!util_split_string(pass_dict, pass_exp)) {
		goto cleanup;
	}

	if ((certificate = mycms_certificate_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_certificate_construct(certificate)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_userdata(certificate, pass_dict)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_passphrase_callback(certificate, _cmd_common_passphrase_callback)) {
		goto cleanup;
	}

	{
		_cmd_common_certificate_driver_apply x;
		if ((x = _cmd_common_get_certificate_driver(&certificate_exp)) == NULL) {
			goto cleanup;
		}
		if (!x(certificate)) {
			goto cleanup;
		}
	}

	if (!mycms_certificate_load(certificate, certificate_dict)) {
		goto cleanup;
	}

	if (!mycms_decrypt(mycms, certificate, cms_in, data_pt, data_ct)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_io_destruct(data_pt);
	data_pt = NULL;

	mycms_io_destruct(data_ct);
	data_ct = NULL;

	mycms_certificate_destruct(certificate);
	certificate = NULL;

	mycms_dict_destruct(certificate_dict);
	certificate_dict = NULL;

	mycms_dict_destruct(pass_dict);
	pass_dict = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	return ret;
}
