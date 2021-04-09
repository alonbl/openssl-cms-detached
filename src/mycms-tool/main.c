#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <mycms/mycms-util-system.h>

#include "cmd-common.h"
#include "cmd-decrypt.h"
#include "cmd-encrypt.h"
#include "cmd-sign.h"
#include "cmd-verify.h"
#include "getoptutil.h"

static const char *__FEATURES[] = {
	"sane",
#if defined(ENABLE_PINENTRY)
	"pinentry",
#endif
#if defined(ENABLE_IO_DRIVER_FILE)
	"io-driver-file",
#endif
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

int main(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_VERSION,
		OPT_MAX
	};

	static struct commands_s {
		const char *c;
		const char *m;
		int (*f)(const mycms_system system, int argc, char *argv[]);
	} commands[] = {
#if defined(ENABLE_CMS_SIGN)
		{"sign", "sign data", _cmd_sign},
#endif
#if defined(ENABLE_CMS_VERIFY)
		{"verify-list", "list signers", _cmd_verify_list},
		{"verify", "verift signature", _cmd_verify},
#endif
#if defined(ENABLE_CMS_ENCRYPT)
		{"encrypt", "encrypt data to recipients", _cmd_encrypt},
		{"encrypt-add", "add recipients in existing cms", _cmd_encrypt_add},
		{"encrypt-reset", "reset recipients in existing cms", _cmd_encrypt_reset},
#endif
#if defined(ENABLE_CMS_DECRYPT)
		{"decrypt", "decrypt cms", _cmd_decrypt},
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
	if (!mycms_util_system_init(system)) {
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
			ret = cmd->f(system, argc, argv);
			goto cleanup;
		}
	}

	fprintf(stderr, "Unknown command '%s'\n", command);

cleanup:

	mycms_static_free();

	mycms_system_clean(system);

	return ret;
}
