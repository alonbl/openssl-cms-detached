#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pinentry.h"

static
int
__pinentry_readline(
	const int fd,
	char * const line,
	const size_t size
) {
	char *p = line;
	size_t s = size;
	ssize_t r;
	int ret = 0;

	while (s > 0) {
		if ((r = read(fd, p, sizeof(*p))) < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			goto cleanup;
		} else if (r == 0) {
			goto cleanup;
		}

		s--;
		if (*p == '\n') {
			*p = '\0';
			break;
		}
		p++;
	}

	if (s == 0) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

static
int
__pinentry_read_ok(
	const int fd
) {
	char buffer[1024];
	int ret = 0;

	if (!__pinentry_readline(fd, buffer, sizeof(buffer))) {
		goto cleanup;
	}

	if (strncmp(buffer, "OK", 2)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

static
int
__pinentry_read_data(
	const int fd,
	char * const buffer,
	const size_t size
) {
	char b[1024];
	int ret = 0;

	if (!__pinentry_readline(fd, b, sizeof(b))) {
		goto cleanup;
	}

	if (strncmp(b, "D ", 2)) {
		goto cleanup;
	}

	if (strlen(b) - 2 >= size) {
		goto cleanup;
	}

	strcpy(buffer, b+2);

	ret = 1;

cleanup:

	return ret;
}

static
int
__pinentry_printf(
	const int fd,
	const char *format,
	...
) __attribute__ ((format (printf, 2, 3)));

static
int
__pinentry_printf(
	const int fd,
	const char *format,
	...
) {
	va_list args;
	char buffer[1024];
	char *p;
	size_t s;
	ssize_t r;
	int ret = 0;

	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	p = buffer;
	s = strlen(buffer);
	while (s > 0) {
		if ((r = write(fd, p, s)) < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			goto cleanup;
		} else if (r == 0) {
			goto cleanup;
		}
		p += r;
		s -= r;
	}

	ret = 1;

cleanup:

	return ret;
}

int
pinentry_exec(
	const char * const prog,
	const char * const title,
	const char * const prompt,
	char * const pin,
	const size_t pin_size
) {
	const char * const tty = ttyname(0);
	const char * const args[] = {
		prog,
		"--ttyname",
		tty == NULL ? "" : tty,
		"--timeout=5",
		NULL
	};
	int sockets[2];
	int ret = 0;
	pid_t child;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		goto cleanup;
	}

	if ((child = fork()) == -1) {
		goto cleanup;
	}
	else if (child == 0) {
		struct rlimit r;
		unsigned long i;

		close(sockets[0]);

		if (dup2(sockets[1], 0) == -1) {
			goto child_cleanup;
		}
		if (dup2(sockets[1], 1) == -1) {
			goto child_cleanup;
		}

		if (getrlimit(RLIMIT_NOFILE, &r) == -1) {
			goto child_cleanup;
		}
		for (i = 4;i < r.rlim_cur;i++) {
			close(i);
		}

		if (execv(prog, (char **)args) == -1) {
			goto child_cleanup;
		}

	child_cleanup:

		_exit(1);
	}
	else {
		int status;

		close(sockets[1]);

		if (!__pinentry_read_ok(sockets[0])) {
			goto cleanup1;
		}
		if (!__pinentry_printf(sockets[0], "SETTITLE %s\n", title)) {
			goto cleanup1;
		}
		if (!__pinentry_read_ok(sockets[0])) {
			goto cleanup1;
		}
		if (!__pinentry_printf(sockets[0], "SETPROMPT %s\n", prompt)) {
			goto cleanup1;
		}
		if (!__pinentry_read_ok(sockets[0])) {
			goto cleanup1;
		}
		if (!__pinentry_printf(sockets[0], "GETPIN\n")) {
			goto cleanup1;
		}
		if (!__pinentry_read_data(sockets[0], pin, pin_size)) {
			goto cleanup1;
		}
		if (!__pinentry_read_ok(sockets[0])) {
			goto cleanup1;
		}

	cleanup1:

		if (!__pinentry_printf(sockets[0], "BYE\n")) {
			goto cleanup1;
		}

		if (waitpid(child, &status, 0) == -1) {
			ret = -errno;
			goto cleanup;
		}
		if (!WIFEXITED(status)) {
			goto cleanup;
		}
		if (WEXITSTATUS(status) != 0) {
			goto cleanup;
		}
	}

	ret = 1;

cleanup:

	return ret;
}

