#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/crypto.h>

#include <mycms/mycms-dict.h>
#include <mycms/mycms-list.h>
#include <mycms/mycms.h>

typedef struct {
	const char *k;
	const char *v;
} entry;

MYCMS_LIST_DECLARE(dict_entry, entry, entry)

struct mycms_dict_s {
	mycms mycms;
	mycms_list_dict_entry head;
};

static
void
__free_entry(
	const mycms_system system,
	const mycms_list_dict_entry entry
) {
	if (entry != NULL) {
		mycms_system_free(system, (void *)entry->entry.k);
		entry->entry.k = NULL;

		mycms_system_free(system, (void *)entry->entry.v);
		entry->entry.v = NULL;

		mycms_system_free(system, entry);
	}
}

mycms_dict
mycms_dict_new(
	const mycms mycms
) {
	mycms_system system = NULL;
	mycms_dict dict = NULL;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	if ((dict = mycms_system_zalloc(system, sizeof(*dict))) == NULL) {
		goto cleanup;
	}

	dict->mycms = mycms;

cleanup:

	return dict;
}

int
mycms_dict_construct(
	const mycms_dict dict
) {
	int ret = 0;

	if (dict == NULL) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_dict_destruct(
	const mycms_dict dict
) {
	mycms_system system = NULL;
	int ret = 0;

	if (dict == NULL) {
		ret = 1;
		goto cleanup;
	}

	if ((system = mycms_get_system(dict->mycms)) == NULL) {
		goto cleanup;
	}

	mycms_dict_entry_clear(dict);
	mycms_system_free(system, dict);

cleanup:

	return ret;
}

mycms
mycms_dict_get_mycms(
	const mycms_dict dict
) {
	mycms ret = NULL;

	if (dict == NULL) {
		goto cleanup;
	}

	ret = dict->mycms;

cleanup:

	return ret;
}

int
mycms_dict_entry_clear(
	const mycms_dict dict
) {
	mycms_system system = NULL;
	int ret = 0;

	if (dict == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(dict->mycms)) == NULL) {
		goto cleanup;
	}

	while(dict->head != NULL) {
		mycms_list_dict_entry t = dict->head;
		dict->head = dict->head->next;
		__free_entry(system, t);
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_dict_entry_put(
	const mycms_dict dict,
	const char * const k,
	const char * const v
) {
	mycms_system system = NULL;
	mycms_list_dict_entry t = NULL;
	const char *vdup = NULL;
	int ret = 0;

	if (dict == NULL) {
		goto cleanup;
	}

	if (k == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(dict->mycms)) == NULL) {
		goto cleanup;
	}

	if (v != NULL) {
		if ((vdup = mycms_system_strdup(system, v)) == NULL) {
			goto cleanup;
		}
	}

	for (t = dict->head; t != NULL; t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}
	if (t != NULL) {
		mycms_system_free(system, (void *)t->entry.v);
		t->entry.v = vdup;
		vdup = NULL;
		t = NULL;
	} else {
		if ((t = mycms_system_zalloc(system, sizeof(*t))) == NULL) {
			goto cleanup;
		}
		if ((t->entry.k = mycms_system_strdup(system, k)) == NULL) {
			goto cleanup;
		}
		t->entry.v = vdup;
		vdup = NULL;
		t->next = dict->head;
		dict->head = t;
		t = NULL;
	}

	ret = 1;

cleanup:
	__free_entry(system, t);

	return ret;
}

const char *
mycms_dict_entry_get(
	const mycms_dict dict,
	const char * const k,
	int * const found
) {
	mycms_list_dict_entry t;
	const char *ret = NULL;

	if (dict == NULL) {
		goto cleanup;
	}

	if (k == NULL) {
		goto cleanup;
	}

	if (found != NULL) {
		*found = 0;
	}

	for (t = dict->head; t != NULL; t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}

	if (t != NULL) {
		if (found != NULL) {
			*found = 1;
		}
		ret = t->entry.v;
	}

cleanup:

	return ret;
}

int
mycms_dict_entry_del(
	const mycms_dict dict,
	const char * const k
) {
	mycms_system system = NULL;
	mycms_list_dict_entry p;
	mycms_list_dict_entry t;
	int ret = 0;

	if (dict == NULL) {
		goto cleanup;
	}

	if (k == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(dict->mycms)) == NULL) {
		goto cleanup;
	}

	for (p = NULL, t = dict->head; t != NULL; p = t, t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}

	if (t != NULL) {
		if (p == NULL) {
			dict->head = t->next;
		} else {
			p->next = t->next;
		}
		__free_entry(system, t);
		t = NULL;
	}

	ret = 1;

cleanup:

	return ret;
}
