#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <mycms.h>
#include <mycms-certificate-driver-file.h>
#include <mycms-certificate-driver-pkcs11.h>

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
#if defined(ENABLE_CMS_DECRYPT)
	"decrypt",
#endif
#if defined(ENABLE_CMS_ENCRYPT)
	"encrypt",
#endif
	NULL
};

#if defined(ENABLE_CMS_ENCRYPT) || defined(ENABLE_CMS_DECRYPT)

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

	OPENSSL_free(data);
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

#endif

#if defined(ENABLE_CMS_ENCRYPT)

static int __cmd_encrypt(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_OUT,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"data-pt\0FILE|input plain text data", required_argument, NULL, OPT_DATA_PT},
		{"data-ct\0FILE|output plain text data", required_argument, NULL, OPT_DATA_CT},
		{"to\0FILE|target DER encoded certificate, may be specified several times", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const EVP_CIPHER *cipher = EVP_aes_256_cbc();

	BIO *cms_out = NULL;
	BIO *data_pt = NULL;
	BIO *data_ct = NULL;

	mycms mycms = NULL;
	mycms_list_blob to = NULL;

	if ((mycms = mycms_new()) == NULL) {
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
				getoptutil_usage(stdout, argv[0], "", long_options);
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
					mycms_list_blob t;

					if ((t = OPENSSL_zalloc(sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!__load_cert(optarg, &t->blob)) {
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

	if (mycms_encrypt(mycms, cipher, to, cms_out, data_pt, data_ct)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_destroy(mycms);
	mycms = NULL;

	BIO_free(cms_out);
	cms_out = NULL;

	BIO_free(data_pt);
	data_pt = NULL;

	BIO_free(data_ct);
	data_ct = NULL;

	while(to != NULL) {
		mycms_list_blob t = to;
		to = to->next;
		t->next = NULL;
		OPENSSL_free(t->blob.data);
		t->blob.data = NULL;
		OPENSSL_free(t);
	}

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
	BIO *cms_in = NULL;
	BIO *cms_out = NULL;
	mycms_list_blob to = NULL;

	mycms mycms = NULL;
	mycms_dict dict = NULL;
	mycms_certificate certificate = NULL;

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "", long_options);
				__extra_usage();
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
				certificate_exp = optarg;
			break;
			case OPT_RECIP_CERT_PASS:
				pass_exp = optarg;
			break;
			case OPT_TO:
				{
					mycms_list_blob t;

					if ((t = OPENSSL_zalloc(sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!__load_cert(optarg, &t->blob)) {
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
	if (certificate_exp == NULL) {
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

	if ((mycms = mycms_new()) == NULL) {
		goto cleanup;
	}

	if (!mycms_construct(mycms)) {
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

	if (mycms_encrypt_add(mycms, certificate, to, cms_in, cms_out)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_certificate_destroy(certificate);
	certificate = NULL;

	mycms_dict_destroy(dict);
	dict = NULL;

	mycms_destroy(mycms);
	mycms = NULL;

	BIO_free(cms_in);
	cms_in = NULL;

	BIO_free(cms_out);
	cms_out = NULL;

	while(to != NULL) {
		mycms_list_blob t = to;
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
	BIO *cms_in = NULL;
	BIO *data_pt = NULL;
	BIO *data_ct = NULL;

	mycms mycms = NULL;
	mycms_dict dict = NULL;
	mycms_certificate certificate = NULL;

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "", long_options);
				__extra_usage();
				ret = 0;
				goto cleanup;
			case OPT_CMS_IN:
				if ((cms_in = BIO_new_file(optarg, "rb")) == NULL) {
					ERR_print_errors_fp(stderr);
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
	if (certificate_exp == NULL) {
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

	if ((mycms = mycms_new()) == NULL) {
		goto cleanup;
	}

	if (!mycms_construct(mycms)) {
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

	if (mycms_decrypt(mycms, certificate, cms_in, data_pt, data_ct)) {
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_certificate_destroy(certificate);
	certificate = NULL;

	mycms_dict_destroy(dict);
	dict = NULL;

	mycms_destroy(mycms);
	mycms = NULL;

	BIO_free(cms_in);
	cms_in = NULL;

	BIO_free(data_pt);
	data_pt = NULL;

	BIO_free(data_ct);
	data_ct = NULL;

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

	struct commands_s *cmd;
	const char *command;
	char optstring[1024];
	int option;
	int ret = 1;

	if (!mycms_static_init()) {
		fprintf(stderr, "Failed to initialize certificate interface\n");
		goto cleanup;
	}

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "", long_options);
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

	return ret;
}
