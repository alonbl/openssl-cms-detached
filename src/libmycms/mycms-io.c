#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "mycms-io-private.h"
#include <mycms/mycms.h>

struct mycms_io_s {
	mycms mycms;
	BIO *bio;
};

mycms_io
mycms_io_new(
	const mycms mycms
) {
	mycms_system system = NULL;
	mycms_io io = NULL;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	if ((io = mycms_system_zalloc(system, sizeof(*io))) == NULL) {
		goto cleanup;
	}

	io->mycms = mycms;

cleanup:

	return io;
}

int
mycms_io_construct(
	const mycms_io io
) {
	int ret = 0;

	if (io == NULL) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_io_destruct(
	const mycms_io io
) {
	mycms_system system = NULL;
	int ret = 0;

	if (io == NULL) {
		ret = 1;
		goto cleanup;
	}

	BIO_free(io->bio);
	io->bio = NULL;

	if ((system = mycms_get_system(io->mycms)) == NULL) {
		goto cleanup;
	}

	if (!mycms_system_free(system, io)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

mycms
mycms_io_get_mycms(
	const mycms_io io
) {
	mycms ret = NULL;

	if (io == NULL) {
		goto cleanup;
	}

	ret = io->mycms;

cleanup:

	return ret;
}

int
mycms_io_open_file(
	const mycms_io io,
	const char * const file,
	const char * const mode
) {
	int ret = 0;

	if (io == NULL) {
		goto cleanup;
	}

	BIO_free(io->bio);
	io->bio = NULL;

#ifdef ENABLE_IO_DRIVER_FILE
	if ((io->bio = BIO_new_file(file, mode)) == NULL) {
		goto cleanup;
	}
#else
	(void)file;
	(void)mode;
	goto cleanup;
#endif

	ret = 1;

cleanup:

	return ret;
}

int
mycms_io_map_mem(
	const mycms_io io,
	const void *p,
	const size_t s
) {
	int ret = 0;

	if (io == NULL) {
		goto cleanup;
	}

	BIO_free(io->bio);
	io->bio = NULL;

	if ((io->bio = BIO_new_mem_buf(p, s)) == NULL) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_io_open_mem(
	const mycms_io io
) {
	int ret = 0;

	if (io == NULL) {
		goto cleanup;
	}

	BIO_free(io->bio);
	io->bio = NULL;

	if ((io->bio = BIO_new(BIO_s_mem())) == NULL) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
mycms_io_get_mem_ptr(
	const mycms_io io,
	char **p
) {
	int ret = -1;

	if (io == NULL) {
		goto cleanup;
	}

	ret = BIO_get_mem_data(io->bio, &p);

cleanup:

	return ret;
}

BIO *
_mycms_io_get_BIO(
	const mycms_io io
) {
	BIO *ret = NULL;

	if (io == NULL) {
		goto cleanup;
	}

	ret = io->bio;

cleanup:

	return ret;
}
