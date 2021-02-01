#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <mycms/mycms-system.h>

struct mycms_system_s {
	const void *userdata;
	mycms_system_driver_cleanse driver_cleanse;
	mycms_system_driver_malloc driver_malloc;
	mycms_system_driver_realloc driver_realloc;
	mycms_system_driver_free driver_free;
};

static
int
__driver_cleanse_default(
	const mycms_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
	explicit_bzero(p, size);
	return 1;
}

static
void *
__driver_malloc_default(
	const mycms_system system __attribute__((unused)),
	const size_t size
) {
	return malloc(size);
}

static
void *
__driver_realloc_default(
	const mycms_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
	return realloc(p, size);
}

static
int
__driver_free_default(
	const mycms_system system __attribute__((unused)),
	void * const p
) {
	free(p);
	return 1;
}

static const struct mycms_system_s __MYCMS_SYSTEM_INIT = {
	NULL,
	__driver_cleanse_default,
	__driver_malloc_default,
	__driver_realloc_default,
	__driver_free_default
};

size_t
mycms_system_get_context_size(void) {
	return sizeof(*(mycms_system)NULL);
}

int
mycms_system_init(
	const mycms_system system,
	const size_t size
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	if (size < mycms_system_get_context_size()) {
		goto cleanup;
	}

	memcpy(system, &__MYCMS_SYSTEM_INIT, sizeof(__MYCMS_SYSTEM_INIT));

	ret = 1;

cleanup:

	return ret;
}

int
mycms_system_clean(
	const mycms_system system __attribute__((unused))
) {
	return 1;
}

const void *
mycms_system_get_userdata(
	const mycms_system system
) {
	const void *ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->userdata;

cleanup:

	return ret;
}

int
mycms_system_set_userdata(
	const mycms_system system,
	const void *userdata
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	system->userdata = userdata;

	ret = 1;

cleanup:

	return ret;
}

mycms_system_driver_cleanse
mycms_system_get_cleanse(
	const mycms_system system
) {
	mycms_system_driver_cleanse ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_cleanse;

cleanup:

	return ret;
}

int
mycms_system_set_cleanse(
	const mycms_system system,
	const mycms_system_driver_cleanse cleanse
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	if (cleanse == NULL) {
		goto cleanup;
	}

	system->driver_cleanse = cleanse;

	ret = 1;

cleanup:

	return ret;
}

mycms_system_driver_malloc
mycms_system_get_malloc(
	const mycms_system system
) {
	mycms_system_driver_malloc ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_malloc;

cleanup:

	return ret;
}

int
mycms_system_set_malloc(
	const mycms_system system,
	const mycms_system_driver_malloc malloc
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	if (malloc == NULL) {
		goto cleanup;
	}

	system->driver_malloc = malloc;

	ret = 1;

cleanup:

	return ret;
}

mycms_system_driver_realloc
mycms_system_get_realloc(
	const mycms_system system
) {
	mycms_system_driver_realloc ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_realloc;

cleanup:

	return ret;
}

int
mycms_system_set_realloc(
	const mycms_system system,
	const mycms_system_driver_realloc realloc
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	if (realloc == NULL) {
		goto cleanup;
	}

	system->driver_realloc = realloc;

	ret = 1;

cleanup:

	return ret;
}

mycms_system_driver_free
mycms_system_get_free(
	const mycms_system system
) {
	mycms_system_driver_free ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_free;

cleanup:

	return ret;
}

int
mycms_system_set_free(
	const mycms_system system,
	const mycms_system_driver_free free
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	if (free == NULL) {
		goto cleanup;
	}

	system->driver_free = free;

	ret = 1;

cleanup:

	return ret;
}

int
mycms_system_cleanse(
	const mycms_system system,
	void * const p,
	const size_t size
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_cleanse(system, p, size);

cleanup:

	return ret;
}

void *
mycms_system_malloc(
	const mycms_system system,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_malloc(system, size);

cleanup:

	return ret;
}

void *
mycms_system_realloc(
	const mycms_system system,
	void * const p,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_realloc(system, p, size);

cleanup:

	return ret;
}

int
mycms_system_free(
	const mycms_system system,
	void * const p
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	ret = system->driver_free(system, p);

cleanup:

	return ret;
}

void *
mycms_system_zalloc(
	const mycms_system system,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		goto cleanup;
	}

	if ((ret = mycms_system_malloc(system, size)) == NULL) {
		goto cleanup;
	}

	mycms_system_cleanse(system, ret, size);

cleanup:

	return ret;
}

char *
mycms_system_strdup(
	const mycms_system system,
	const char * const s
) {
	char *ret = NULL;
	size_t size;

	if (system == NULL) {
		goto cleanup;
	}

	if (s == NULL) {
		return NULL;
	}

	size = strlen(s) + 1;

	if ((ret = mycms_system_malloc(system, size)) == NULL) {
		goto cleanup;
	}

	memcpy(ret, s, size);

cleanup:

	return ret;
}
