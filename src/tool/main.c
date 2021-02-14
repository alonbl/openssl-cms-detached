#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <mycms/mycms.h>
#include <mycms/mycms-certificate-driver-file.h>
#include <mycms/mycms-certificate-driver-pkcs11.h>

#include "getoptutil.h"
#include "util.h"

static const char *__FEATURES[] = {
	"sane",
#if defined(ENABLE_CERTIFICATE_DRIVER_FILE)
	"certificate-driver-file",
#endif
#if defined(ENABLE_CERTIFICATE_DRIVER_PKCS11)
	"certificate-driver-pkcs11",
#endif
#if defined(ENABLE_CMS_SIGN)
	"sign",
#endif
#if defined(ENABLE_CMS_VERIFY)
	"verify",
#endif
#if defined(ENABLE_CMS_ENCRYPT)
	"encrypt",
#endif
#if defined(ENABLE_CMS_DECRYPT)
	"decrypt",
#endif
	NULL
};

typedef int (*certificate_driver_apply)(const mycms_certificate c);
typedef const char *(*certificate_driver_usage)(void);
static const struct certificate_driver_s {
	const char *name;
	certificate_driver_usage u;
	certificate_driver_apply p;
} __CERTIFICATE_DRIVERS[] = {
#ifdef ENABLE_CERTIFICATE_DRIVER_FILE
	{"file", mycms_certificate_driver_file_usage, mycms_certificate_driver_file_apply},
#endif
#ifdef ENABLE_CERTIFICATE_DRIVER_PKCS11
	{"pkcs11", mycms_certificate_driver_pkcs11_usage, mycms_certificate_driver_pkcs11_apply},
#endif
	{NULL, NULL, NULL}
};

static
certificate_driver_apply
__get_certificate_driver(
	const char ** what
) {
	const struct certificate_driver_s *sd = __CERTIFICATE_DRIVERS;
	const char *p;
	certificate_driver_apply ret = NULL;

	if (what == NULL || *what == NULL) {
		goto cleanup;
	}

	p = *what;
	if ((*what = strchr(p, ':')) == NULL) {
		goto cleanup;
	}
	(*what) = '\0';
	(*what)++;

	for (sd = __CERTIFICATE_DRIVERS; sd->name != NULL; sd++) {
		if (!strncmp(p, sd->name, strlen(sd->name))) {
			ret = sd->p;
			break;
		}
	}

cleanup:

	return ret;
}

static
void
__extra_usage() {
	static const struct pass_s {
		const char *k;
		const char *u;
	} PASS_USAGE[] = {
		{"pass:string", "read passphrase from string"},
		{"env:key", "read the passphrase from environment"},
		{"file:name", "read the passphrase from file"},
		{"fd:n", "read the passphrase from file descriptor"},
		{NULL, NULL}
	};
	const struct certificate_driver_s *sd;
	const struct pass_s *pu;

	printf("\nPASSPHRASE_EXPRESSION\n");
	for (pu = PASS_USAGE; pu->k != NULL; pu++) {
		printf("%4s%-16s- %s\n", "", pu->k, pu->u);
	}

	printf("\nCERTIFICATE_EXPRESSION\n%4sdriver:attribute=value:attribute=value\n", "");

	printf("\n%4sAvailable certificate drivers:\n", "");
	for (sd = __CERTIFICATE_DRIVERS; sd->name != NULL; sd++) {
		char x[1024];
		char *p1;
		char *p2;

		strncpy(x, sd->u(), sizeof(x) - 1);
		x[sizeof(x) - 1] = '\0';

		printf("%8s%s: attributes:\n", "", sd->name);
		p1 = x;
		while (p1 != NULL) {
			if ((p2 = strchr(p1, '\n')) != NULL) {
				*p2 = '\0';
				p2++;
			}
			printf("%12s%s\n", "", p1);
			p1 = p2;
		}
	}
}

static
int
__load_cert(
	const mycms_system system,
	const char * const file,
	mycms_blob *blob
) {

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

	if ((data = mycms_system_malloc(system, blob->size)) == NULL) {
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

	mycms_system_free(system, data);
	data = NULL;

	return ret;
}

static
int
__passphrase_callback(
	const mycms_certificate certificate,
	char **p,
	const size_t size
) {
	char *exp = (char *)mycms_certificate_get_userdata(certificate);

	if (exp == NULL) {
		*p = NULL;
		return 1;
	} else {
		return util_getpass(exp, *p, size);
	}
}

#if defined(ENABLE_CMS_SIGN)

static int __cmd_sign(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_DIGEST,
		OPT_SIGNER_CERT,
		OPT_SIGNER_CERT_PASS,
		OPT_CMS_IN,
		OPT_CMS_OUT,
		OPT_DATA_IN,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"digest\0DIGEST|digest to use, default is SHA3-256", required_argument, NULL, OPT_DIGEST},
		{"signer-cert\0CERTIFICATE_EXPRESSION|signer certificate to use", required_argument, NULL, OPT_SIGNER_CERT},
		{"signer-cert-pass\0PASSPHRASE_EXPRESSION|signer certificate passphrase to use", required_argument, NULL, OPT_SIGNER_CERT_PASS},
		{"cms-in\0FILE|input cms for resign", required_argument, NULL, OPT_CMS_IN},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"data-in\0FILE|input text data", required_argument, NULL, OPT_DATA_IN},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char * certificate_exp = NULL;
	const char * pass_exp = NULL;

	char _mycms_system[MYCMS_SYSTEM_CONTEXT_SIZE] = {0};
	mycms_system system = (mycms_system)_mycms_system;
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io cms_out = NULL;
	mycms_io data_in = NULL;
	mycms_dict dict = NULL;
	mycms_certificate certificate = NULL;
	mycms_list_str digests = NULL;

	if (!mycms_system_init(system, sizeof(_mycms_system))) {
		goto cleanup;
	}

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
				ret = 0;
				goto cleanup;
			case OPT_DIGEST:
				{
					mycms_list_str t;

					if ((t = mycms_system_zalloc(system, sizeof(*t))) == NULL) {
						goto cleanup;
					}
					t->next = digests;
					digests = t;
					t->str = optarg;
				}
			break;
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
			case OPT_CMS_OUT:
				if ((cms_out = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(cms_out)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(cms_out, optarg, "wb")) {
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
			case OPT_SIGNER_CERT:
				certificate_exp = optarg;
			break;
			case OPT_SIGNER_CERT_PASS:
				pass_exp = optarg;
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
	if (cms_out == NULL) {
		fprintf(stderr, "CMS out is mandatory\n");
		goto cleanup;
	}

	if (digests == NULL) {
		digests = mycms_system_zalloc(system, sizeof(*digests));
		digests->str = "SHA3-256";
	}

	if ((dict = mycms_dict_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(dict)) {
		goto cleanup;
	}

	if (!util_split_string(dict, certificate_exp)) {
		goto cleanup;
	}

	if ((certificate = mycms_certificate_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_certificate_construct(certificate)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_userdata(certificate, pass_exp)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_passphrase_callback(certificate, __passphrase_callback)) {
		goto cleanup;
	}

	{
		certificate_driver_apply x;
		if ((x = __get_certificate_driver(&certificate_exp)) == NULL) {
			goto cleanup;
		}
		if (!x(certificate)) {
			goto cleanup;
		}
	}

	if (!mycms_certificate_load(certificate, dict)) {
		goto cleanup;
	}

	if (!mycms_sign(mycms, certificate, digests, cms_in, cms_out, data_in)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	while (digests != NULL) {
		mycms_list_str t = digests;
		digests = digests->next;
		mycms_system_free(system, t);
	}

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_io_destruct(cms_out);
	cms_out = NULL;

	mycms_io_destruct(data_in);
	data_in = NULL;

	mycms_certificate_destruct(certificate);
	certificate = NULL;

	mycms_dict_destruct(dict);
	dict = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	mycms_system_clean(system);

	return ret;
}

#endif

#if defined(ENABLE_CMS_VERIFY)

static int __cmd_verify_list(int argc, char *argv[]) {
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

	char _mycms_system[MYCMS_SYSTEM_CONTEXT_SIZE] = {0};
	mycms_system system = (mycms_system)_mycms_system;
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_list_blob keyids = NULL;
	mycms_list_blob t = NULL;

	if (!mycms_system_init(system, sizeof(_mycms_system))) {
		goto cleanup;
	}

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

	if (!mycms_verify_list(mycms, cms_in, &keyids)) {
		goto cleanup;
	}

	for (t = keyids; t != NULL; t = t->next) {
		size_t i;
		for (i = 0; i < t->blob.size; i++) {
			printf("%s%02x", i == 0 ? "" : ":", t->blob.data[i]);
		}
		printf("\n");
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_verify_list_free(mycms, keyids);
	keyids = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	mycms_system_clean(system);

	return ret;
}

static int __cmd_verify(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_DATA_IN,
		OPT_CERT,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-in\0FILE|input cms", required_argument, NULL, OPT_CMS_IN},
		{"data-in\0FILE|input text data", required_argument, NULL, OPT_DATA_IN},
		{"cert\0FILE|add certificate to consider", required_argument, NULL, OPT_CERT},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int verified = 0;
	int ret = 1;

	char _mycms_system[MYCMS_SYSTEM_CONTEXT_SIZE] = {0};
	mycms_system system = (mycms_system)_mycms_system;
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io data_in = NULL;
	mycms_list_blob certs = NULL;

	if (!mycms_system_init(system, sizeof(_mycms_system))) {
		goto cleanup;
	}

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
			case OPT_CERT:
				{
					mycms_list_blob t;

					if ((t = mycms_system_zalloc(system, sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!__load_cert(system, optarg, &t->blob)) {
						mycms_system_free(system, t);
						goto cleanup;
					}

					t->next = certs;
					certs = t;
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

	if (!mycms_verify(mycms, cms_in, data_in, certs, &verified)) {
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

	while(certs != NULL) {
		mycms_list_blob t = certs;
		certs = certs->next;
		t->next = NULL;
		mycms_system_free(system, t->blob.data);
		t->blob.data = NULL;
		mycms_system_free(system, t);
	}

	mycms_system_clean(system);

	return ret;
}


#endif

#if defined(ENABLE_CMS_ENCRYPT)

static int __cmd_encrypt(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CIPHER,
		OPT_CMS_OUT,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cipher\0CIPHER|cipher to use, default is AES-256-CBC", required_argument, NULL, OPT_CIPHER},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"data-pt\0FILE|input plain text data", required_argument, NULL, OPT_DATA_PT},
		{"data-ct\0FILE|output plain text data", required_argument, NULL, OPT_DATA_CT},
		{"to\0FILE|target DER encoded certificate, may be specified several times", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char *cipher = "AES-256-CBC";

	char _mycms_system[MYCMS_SYSTEM_CONTEXT_SIZE] = {0};
	mycms_system system = (mycms_system)_mycms_system;
	mycms mycms = NULL;
	mycms_io cms_out = NULL;
	mycms_io data_pt = NULL;
	mycms_io data_ct = NULL;
	mycms_list_blob to = NULL;

	if (!mycms_system_init(system, sizeof(_mycms_system))) {
		goto cleanup;
	}

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
				getoptutil_usage(stdout, argv[0], "encrypt [options]", long_options);
				ret = 0;
				goto cleanup;
			case OPT_CIPHER:
				cipher = optarg;
			break;
			case OPT_CMS_OUT:
				if ((cms_out = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(cms_out)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(cms_out, optarg, "wb")) {
					goto cleanup;
				}
			break;
			case OPT_DATA_PT:
				if ((data_pt = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(data_pt)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(data_pt, optarg, "rb")) {
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
				if (!mycms_io_open_file(data_ct, optarg, "wb")) {
					goto cleanup;
				}
			break;
			case OPT_TO:
				{
					mycms_list_blob t;

					if ((t = mycms_system_zalloc(system, sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!__load_cert(system, optarg, &t->blob)) {
						mycms_system_free(system, t);
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
		fprintf(stderr, "CMS out is mandatory\n");
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

	if (!mycms_encrypt(mycms, cipher, to, cms_out, data_pt, data_ct)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_out);
	cms_out = NULL;

	mycms_io_destruct(data_pt);
	data_pt = NULL;

	mycms_io_destruct(data_ct);
	data_ct = NULL;

	while(to != NULL) {
		mycms_list_blob t = to;
		to = to->next;
		t->next = NULL;
		mycms_system_free(system, t->blob.data);
		t->blob.data = NULL;
		mycms_system_free(system, t);
	}

	mycms_destruct(mycms);
	mycms = NULL;

	mycms_system_clean(system);

	return ret;
}


static int __cmd_encrypt_add(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_CMS_OUT,
		OPT_RECIP_CERT,
		OPT_RECIP_CERT_PASS,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-in\0FILE|input cms", required_argument, NULL, OPT_CMS_IN},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"recip-cert\0CERTIFICATE_EXPRESSION|recipient certificate to use", required_argument, NULL, OPT_RECIP_CERT},
		{"recip-cert-pass\0PASSPHRASE_EXPRESSION|recipient certificate passphrase to use", required_argument, NULL, OPT_RECIP_CERT_PASS},
		{"to\0FILE|target DER encoded certificate, may be specified several times", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char * certificate_exp = NULL;
	const char * pass_exp = NULL;

	char _mycms_system[MYCMS_SYSTEM_CONTEXT_SIZE] = {0};
	mycms_system system = (mycms_system)_mycms_system;
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io cms_out = NULL;
	mycms_list_blob to = NULL;
	mycms_dict dict = NULL;
	mycms_certificate certificate = NULL;

	if (!mycms_system_init(system, sizeof(_mycms_system))) {
		goto cleanup;
	}

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
				getoptutil_usage(stdout, argv[0], "encrypt-add [options]", long_options);
				__extra_usage();
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
			case OPT_CMS_OUT:
				if ((cms_out = mycms_io_new(mycms)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(cms_out)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(cms_out, optarg, "wb")) {
					goto cleanup;
				}
			break;
			case OPT_RECIP_CERT:
				certificate_exp = optarg;
			break;
			case OPT_RECIP_CERT_PASS:
				pass_exp = optarg;
			break;
			case OPT_TO:
				{
					mycms_list_blob t;

					if ((t = mycms_system_zalloc(system, sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!__load_cert(system, optarg, &t->blob)) {
						mycms_system_free(system, t);
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
	if (certificate_exp == NULL) {
		fprintf(stderr, "Certificate is mandatory\n");
		goto cleanup;
	}
	if (cms_in == NULL) {
		fprintf(stderr, "CMS in is mandatory\n");
		goto cleanup;
	}
	if (cms_out == NULL) {
		fprintf(stderr, "CMS out is mandatory\n");
		goto cleanup;
	}
	if (to == NULL) {
		fprintf(stderr, "To is mandatory\n");
		goto cleanup;
	}

	if ((certificate = mycms_certificate_new(mycms)) == NULL) {
		goto cleanup;
	}

	if ((dict = mycms_dict_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(dict)) {
		goto cleanup;
	}

	if (!util_split_string(dict, certificate_exp)) {
		goto cleanup;
	}

	if (!mycms_certificate_construct(certificate)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_userdata(certificate, pass_exp)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_passphrase_callback(certificate, __passphrase_callback)) {
		goto cleanup;
	}

	{
		certificate_driver_apply x;
		if ((x = __get_certificate_driver(&certificate_exp)) == NULL) {
			goto cleanup;
		}
		if (!x(certificate)) {
			goto cleanup;
		}
	}

	if (!mycms_certificate_load(certificate, dict)) {
		goto cleanup;
	}

	if (!mycms_encrypt_add(mycms, certificate, to, cms_in, cms_out)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_io_destruct(cms_out);
	cms_out = NULL;

	mycms_certificate_destruct(certificate);
	certificate = NULL;

	mycms_dict_destruct(dict);
	dict = NULL;

	while(to != NULL) {
		mycms_list_blob t = to;
		to = to->next;
		t->next = NULL;
		mycms_system_free(system, t->blob.data);
		t->blob.data = NULL;
		mycms_system_free(system, t);
	}

	mycms_destruct(mycms);
	mycms = NULL;

	mycms_system_clean(system);

	return ret;
}

#endif

#if defined(ENABLE_CMS_DECRYPT)

static int __cmd_decrypt(int argc, char *argv[]) {
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

	char _mycms_system[MYCMS_SYSTEM_CONTEXT_SIZE] = {0};
	mycms_system system = (mycms_system)_mycms_system;
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io data_pt = NULL;
	mycms_io data_ct = NULL;
	mycms_dict dict = NULL;
	mycms_certificate certificate = NULL;

	if (!mycms_system_init(system, sizeof(_mycms_system))) {
		goto cleanup;
	}

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
				__extra_usage();
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

	if ((dict = mycms_dict_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(dict)) {
		goto cleanup;
	}

	if (!util_split_string(dict, certificate_exp)) {
		goto cleanup;
	}

	if ((certificate = mycms_certificate_new(mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_certificate_construct(certificate)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_userdata(certificate, pass_exp)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_passphrase_callback(certificate, __passphrase_callback)) {
		goto cleanup;
	}

	{
		certificate_driver_apply x;
		if ((x = __get_certificate_driver(&certificate_exp)) == NULL) {
			goto cleanup;
		}
		if (!x(certificate)) {
			goto cleanup;
		}
	}

	if (!mycms_certificate_load(certificate, dict)) {
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

	mycms_dict_destruct(dict);
	dict = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	mycms_system_clean(system);

	return ret;
}

#endif

int main(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_VERSION,
		OPT_MAX
	};

	static struct commands_s {
		const char *c;
		const char *m;
		int (*f)(int argc, char *argv[]);
	} commands[] = {
#if defined(ENABLE_CMS_SIGN)
		{"sign", "sign data", __cmd_sign},
#endif
#if defined(ENABLE_CMS_VERIFY)
		{"verify-list", "list signers", __cmd_verify_list},
		{"verify", "verift signature", __cmd_verify},
#endif
#if defined(ENABLE_CMS_ENCRYPT)
		{"encrypt", "encrypt data to recipients", __cmd_encrypt},
		{"encrypt-add", "add recipients to to existing cms", __cmd_encrypt_add},
#endif
#if defined(ENABLE_CMS_DECRYPT)
		{"decrypt", "decrypt cms", __cmd_decrypt},
#endif
		{NULL, NULL, NULL}
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"version\0print version", no_argument, NULL, OPT_VERSION},
		{NULL, 0, NULL, 0}
	};

	char _mycms_system[MYCMS_SYSTEM_CONTEXT_SIZE] = {0};
	mycms_system system = (mycms_system)_mycms_system;
	struct commands_s *cmd;
	const char *command;
	char optstring[1024];
	int option;
	int ret = 1;

	if (!mycms_system_init(system, sizeof(_mycms_system))) {
		goto cleanup;
	}

	if (!mycms_static_init(system)) {
		fprintf(stderr, "Failed to initialize certificate interface\n");
		goto cleanup;
	}

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "command [options]", long_options);
				printf("\nAvailable commands:\n");
				for (cmd = commands; cmd->c != NULL; cmd++) {
					printf("%8s%-16s - %s\n", "", cmd->c, cmd->m);
				}
				ret = 0;
				goto cleanup;
			case OPT_VERSION:
				printf("%s-%s\n", PACKAGE_NAME, PACKAGE_VERSION);
				printf("Features:");
				{
					const char **p;
					for (p = __FEATURES; *p != NULL; p++) {
						printf(" %s", *p);
					}
				}
				printf("\n");
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

	for (cmd = commands; cmd->c != NULL; cmd++) {
		if (!strcmp(command, cmd->c)) {
			ret = cmd->f(argc, argv);
			goto cleanup;
		}
	}

	fprintf(stderr, "Unknown command '%s'\n", command);

cleanup:

	mycms_static_free();

	mycms_system_clean(system);

	return ret;
}
