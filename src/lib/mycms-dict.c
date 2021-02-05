#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/crypto.h>

#include <mycms-dict.h>
#include <mycms-list.h>

typedef struct {
	const char *k;
	const char *v;
} entry;

MYCMS_LIST_DEFINE(dict_entry, entry, entry)

struct mycms_dict_s {
	mycms mycms;
	mycms_list_dict_entry head;
};

static
void
__free_entry(mycms_list_dict_entry entry) {
	if (entry != NULL) {
		OPENSSL_free((void *)entry->entry.k);
		entry->entry.k = NULL;

		OPENSSL_free((void *)entry->entry.v);
		entry->entry.v = NULL;

		OPENSSL_free(entry);
		entry = NULL;
	}
}

mycms_dict
mycms_dict_new(
	const mycms mycms
) {
	mycms_dict dict = NULL;

	if ((dict = OPENSSL_zalloc(sizeof(*dict))) != NULL) {
		dict->mycms = mycms;
	}

	return dict;
}

int
mycms_dict_construct(
	const mycms_dict dict __attribute__((unused))
) {
	return 1;
}

int
mycms_dict_destroy(
	const mycms_dict dict
) {
	if (dict != NULL) {
		while(dict->head != NULL) {
			mycms_list_dict_entry t = dict->head;
			dict->head = dict->head->next;
			__free_entry(t);
		}
		OPENSSL_free(dict);
	}
	return 1;
}

mycms
mycms_dict_get_mycms(
	const mycms_dict dict
) {
	return dict->mycms;
}

int
mycms_dict_entry_put(
	const mycms_dict dict,
	const char * const k,
	const char * const v
) {
	mycms_list_dict_entry t;
	int ret = 0;

	for (t = dict->head; t != NULL; t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}	
	if (t != NULL) {
		const char *vdup = NULL;
		if ((vdup = OPENSSL_strdup(v)) == NULL) {
			goto cleanup;
		}
		OPENSSL_free((void *)t->entry.v);
		t->entry.v = vdup;
		vdup = NULL;
		t = NULL;
	}
	if (t == NULL) {
		if ((t = OPENSSL_zalloc(sizeof(*t))) == NULL) {
			goto cleanup;
		}
		if ((t->entry.k = OPENSSL_strdup(k)) == NULL) {
			goto cleanup;
		}
		if ((t->entry.v = OPENSSL_strdup(v)) == NULL) {
			goto cleanup;
		}
		t->next = dict->head;
		dict->head = t;
		t = NULL;
	}

	ret = 1;

cleanup:
	__free_entry(t);

	return ret;
}

const char *
mycms_dict_entry_get(
	const mycms_dict dict,
	const char * const k,
	int * const found
) {
	mycms_list_dict_entry t;

	if (found != NULL) {
		*found = 0;
	}

	for (t = dict->head; t != NULL; t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}

	if (t == NULL) {
		return NULL;
	} else {
		if (found != NULL) {
			*found = 1;
		}
		return t->entry.v;
	}
}

int
mycms_dict_entry_del(
	const mycms_dict dict,
	const char * const k
) {
	mycms_list_dict_entry p;
	mycms_list_dict_entry t;

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
		__free_entry(t);
	}

	return 1;
}
