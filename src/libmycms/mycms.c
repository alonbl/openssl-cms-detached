#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/err.h>

#include "mycms-certificate-private.h"
#include "mycms-private.h"

struct mycms_s {
	mycms_system system;
	void *pkcs11_state;
};

static struct {
	int initialized;
	mycms_system system;
	void *(*orig_m)(size_t, const char *, int);
	void *(*orig_r)(void *, size_t, const char *, int);
	void (*orig_f)(void *, const char *, int);
} __mycms_static;

static
void *
__openssl_malloc(
	size_t num,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	return mycms_system_malloc(__mycms_static.system, num);
}

static
void *
__openssl_realloc(
	void *p,
	size_t num,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	return mycms_system_realloc(__mycms_static.system, p, num);
}

static
void
__openssl_free(
	void *p,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	mycms_system_free(__mycms_static.system, p);
}

int
mycms_static_init(
	const mycms_system system
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	__mycms_static.system = system;

	CRYPTO_get_mem_functions(
		&__mycms_static.orig_m,
		&__mycms_static.orig_r,
		&__mycms_static.orig_f
	);

	if (!CRYPTO_set_mem_functions(
		__openssl_malloc,
		__openssl_realloc,
		__openssl_free
	)) {
		goto cleanup;
	}
	__mycms_static.initialized = 1;

#if defined(ENABLE_OPENSSL_ERR_STRINGS)
	ERR_load_crypto_strings();
#endif

	if (!_mycms_certificate_static_init()) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	if (!ret) {
		mycms_static_free();
	}

	return ret;
}

int
mycms_static_free(void) {
	int ret = 1;

#if defined(ENABLE_OPENSSL_ERR_STRINGS)
	ERR_free_strings();
#endif

	ret = _mycms_certificate_static_free() && ret;

	if (__mycms_static.initialized) {
		CRYPTO_set_mem_functions(
			__mycms_static.orig_m,
			__mycms_static.orig_r,
			__mycms_static.orig_f
		);
	}
	mycms_system_cleanse(__mycms_static.system, &__mycms_static, sizeof(__mycms_static));

	return ret;
}

mycms
mycms_new(
	const mycms_system system
) {
	mycms ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	if ((ret = mycms_system_zalloc(system, sizeof(*(mycms)NULL))) == NULL) {
		goto cleanup;
	}

	ret->system = system;

cleanup:

	return ret;
}

int
mycms_construct(
	const mycms mycms
) {
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_destruct(const mycms mycms) {
	int ret = 0;

	if (mycms == NULL) {
		ret = 1;
		goto cleanup;
	}

	if (mycms->system == NULL) {
		goto cleanup;
	}

	ret = mycms_system_free(mycms->system, mycms);

cleanup:

	return ret;
}

mycms_system
mycms_get_system(
	const mycms mycms
) {
	mycms_system ret = NULL;

	if (mycms == NULL) {
		goto cleanup;
	}

	ret = mycms->system;

cleanup:

	return ret;
}

void *
_mycms_get_pkcs11_state(
	const mycms mycms
) {
	void *ret = NULL;

	if (mycms == NULL) {
		goto cleanup;
	}

	ret = mycms->pkcs11_state;

cleanup:

	return ret;
}

int
_mycms_set_pkcs11_state(
	const mycms mycms,
	void *pkcs11_state
) {
	int ret = 0;

	if (mycms == NULL) {
		goto cleanup;
	}

	mycms->pkcs11_state = pkcs11_state;
	ret = 1;

cleanup:

	return ret;
}
