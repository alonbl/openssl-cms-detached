#ifndef __MYCMS_SYSTEM_H
#define __MYCMS_SYSTEM_H

#define MYCMS_SYSTEM_DRIVER_FUNC(group, ret, name, ...) \
	typedef ret (*mycms_system_driver_p_##name)(const mycms_system system __VA_OPT__(,) __VA_ARGS__); \
	static inline mycms_system_driver_p_##name mycms_system_driver_##group##_##name (const mycms_system system) { \
		return (mycms_system_driver_p_##name)mycms_system_driver_find(system, MYCMS_SYSTEM_DRIVER_ID_##group##_##name); \
	}

#define MYCMS_SYSTEM_CONTEXT_SIZE 4096 * 10

struct mycms_system_s;
typedef struct mycms_system_s *mycms_system;

struct mycms_system_driver_entry_s {
	unsigned id;
	void (*f)();
};

size_t
mycms_system_get_context_size(void);

int
mycms_system_init(
	const mycms_system system,
	const size_t size
);

int
mycms_system_clean(
	const mycms_system system
);

int mycms_system_driver_register(
	const mycms_system system,
	const struct mycms_system_driver_entry_s * const entries
);

void (*mycms_system_driver_find(
	const mycms_system system,
	const unsigned id
))();

const void *
mycms_system_get_userdata(
	const mycms_system system
);

int
mycms_system_set_userdata(
	const mycms_system system,
	const void *userdata
);

int
mycms_system_cleanse(
	const mycms_system system,
	void * const p,
	const size_t size
);

void *
mycms_system_malloc(
	const mycms_system system,
	const size_t size
);

void *
mycms_system_realloc(
	const mycms_system system,
	void * const p,
	const size_t size
);

int
mycms_system_free(
	const mycms_system system,
	void * const p
);

void *
mycms_system_zalloc(
	const mycms_system system,
	const size_t size
);

char *
mycms_system_strdup(
	const mycms_system system,
	const char * const s
);

#endif
