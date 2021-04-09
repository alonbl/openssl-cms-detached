#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mycms/mycms-certificate-driver-file.h>
#include <mycms/mycms-certificate-driver-pkcs11.h>
#include <mycms/mycms-util-getpass.h>

#include "cmd-common.h"

typedef const char *(*__certificate_driver_usage)(void);
static const struct __certificate_driver_s {
	const char *name;
	__certificate_driver_usage u;
	_cmd_common_certificate_driver_apply p;
} __CERTIFICATE_DRIVERS[] = {
#ifdef ENABLE_CERTIFICATE_DRIVER_FILE
	{"file", mycms_certificate_driver_file_usage, mycms_certificate_driver_file_apply},
#endif
#ifdef ENABLE_CERTIFICATE_DRIVER_PKCS11
	{"pkcs11", mycms_certificate_driver_pkcs11_usage, mycms_certificate_driver_pkcs11_apply},
#endif
	{NULL, NULL, NULL}
};

_cmd_common_certificate_driver_apply
_cmd_common_get_certificate_driver(
	const char ** what
) {
	const struct __certificate_driver_s *sd = __CERTIFICATE_DRIVERS;
	const char *p;
	_cmd_common_certificate_driver_apply ret = NULL;

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

void
_cmd_common_extra_usage() {
	const struct __certificate_driver_s *sd;

	printf("\nPASSPHRASE_EXPRESSION\n%4swhat=attribute=value:what=attribute=value\n", "");
	{
		char x[1024];
		char *p1;
		strncpy(x, mycms_util_getpass_usage(), sizeof(x)-1);
		x[sizeof(x) - 1] = '\0';
		p1 = x;
		while (p1 != NULL) {
			char *p2;
			if ((p2 = strchr(p1, '\n')) != NULL) {
				*p2 = '\0';
				p2++;
			}
			printf("%12s%s\n", "", p1);
			p1 = p2;
		}
	}

	printf("\nCERTIFICATE_EXPRESSION\n%4sdriver:attribute=value:attribute=value\n", "");

	printf("\nCERTIFICATE DRIVERS\n");
	for (sd = __CERTIFICATE_DRIVERS; sd->name != NULL; sd++) {
		char x[1024];
		char *p1;

		strncpy(x, sd->u(), sizeof(x) - 1);
		x[sizeof(x) - 1] = '\0';

		printf("%4s%s:\n", "", sd->name);
		p1 = x;
		while (p1 != NULL) {
			char *p2;
			if ((p2 = strchr(p1, '\n')) != NULL) {
				*p2 = '\0';
				p2++;
			}
			printf("%12s%s\n", "", p1);
			p1 = p2;
		}
	}
}

int
_cmd_common_load_cert(
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

int
_cmd_common_passphrase_callback(
	const mycms_certificate certificate,
	const char * const what,
	char **p,
	const size_t size
) {
	mycms mycms = mycms_certificate_get_mycms(certificate);
	mycms_dict pass_dict = (mycms_dict)mycms_certificate_get_userdata(certificate);
	const char *exp = mycms_dict_entry_get(pass_dict, what, NULL);
	char prompt[1024];
	snprintf(prompt, sizeof(prompt), "%s PIN", what);
	prompt[sizeof(prompt)-1] = '\0';
	return mycms_util_getpass(mycms, "MyCMS", prompt, exp, *p, size);
}
