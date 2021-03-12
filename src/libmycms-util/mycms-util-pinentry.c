#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef BUILD_WINDOWS
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mycms-system-driver-util.h"
#include "mycms-util-pinentry.h"

struct _mycms_util_pinentry_s {
	mycms mycms;
#ifdef BUILD_WINDOWS
	HANDLE channel;
	HANDLE process;
#else
	int channel;
	pid_t process;
#endif
	int dummy;
};

static const struct _mycms_util_pinentry_s __MYCMS_ENTRY_INIT = {
	NULL,
#ifdef BUILD_WINDOWS
	INVALID_HANDLE_VALUE,
	INVALID_HANDLE_VALUE,
#else
	-1,
	-1,
#endif
	0
};

#ifdef BUILD_WINDOWS

static
int
__pinentry_native_exec(
	const _mycms_pinentry pinentry,
	const char * const prog
) {
	mycms_system system = NULL;
	STARTUPINFOA startinfo;
	PROCESS_INFORMATION procinfo;
	OVERLAPPED overlapped;
	HANDLE h = INVALID_HANDLE_VALUE;
	char name_unique[1024];
	int ret = 0;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		goto cleanup;
	}

	mycms_system_cleanse(system, &startinfo, sizeof(startinfo));
	startinfo.hStdInput = startinfo.hStdOutput = startinfo.hStdError = INVALID_HANDLE_VALUE;
	mycms_system_cleanse(system, &procinfo, sizeof(procinfo));
	procinfo.hProcess = INVALID_HANDLE_VALUE;
	mycms_system_cleanse(system, &overlapped, sizeof(overlapped));
	overlapped.hEvent = mycms_system_driver_util_CreateEventA(system)(system, NULL, TRUE, FALSE, NULL);

	snprintf(
		name_unique,
		sizeof(name_unique),
		"\\\\.\\pipe\\mycms-%08lx-%08lx",
		mycms_system_driver_util_GetCurrentProcessId(system)(system),
		mycms_system_driver_util_GetCurrentThreadId(system)(system)
	);

	if ((pinentry->channel = mycms_system_driver_util_CreateNamedPipeA(system)(
		system,
		name_unique,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE,
		PIPE_UNLIMITED_INSTANCES,
		0,
		0,
		INFINITE,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		goto cleanup;
	}

	if (!mycms_system_driver_util_ConnectNamedPipe(system)(system, pinentry->channel, &overlapped)) {
		if (mycms_system_driver_util_GetLastError(system)(system) != ERROR_IO_PENDING) {
			goto cleanup;
		}
	}

	if ((h = mycms_system_driver_util_CreateFileA(system)(
		system,
		name_unique,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		goto cleanup;
	}


	{
		DWORD dw;
		if (!mycms_system_driver_util_GetOverlappedResult(system)(
			system,
			pinentry->channel,
			&overlapped,
			&dw,
		TRUE)) {
			goto cleanup;
		}
	}

	startinfo.cb = sizeof(startinfo);
	startinfo.dwFlags = STARTF_USESTDHANDLES;
	if (!mycms_system_driver_util_DuplicateHandle(system)(
		system,
		mycms_system_driver_util_GetCurrentProcess(system)(system),
		h,
		mycms_system_driver_util_GetCurrentProcess(system)(system),
		&startinfo.hStdInput,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	)) {
		goto cleanup;
	}
	if (!mycms_system_driver_util_DuplicateHandle(system)(
		system,
		mycms_system_driver_util_GetCurrentProcess(system)(system),
		h,
		mycms_system_driver_util_GetCurrentProcess(system)(system),
		&startinfo.hStdOutput,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	)) {
		goto cleanup;
	}
	if (!mycms_system_driver_util_DuplicateHandle(system)(
		system,
		mycms_system_driver_util_GetCurrentProcess(system)(system),
		mycms_system_driver_util_GetStdHandle(system)(system, STD_ERROR_HANDLE),
		mycms_system_driver_util_GetCurrentProcess(system)(system),
		&startinfo.hStdError,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	)) {
		goto cleanup;
	}

	if (!mycms_system_driver_util_CreateProcessA(system)(
		system,
		prog,
		NULL,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&startinfo,
		&procinfo
	)) {
		goto cleanup;
	}

	pinentry->process = procinfo.hProcess;
	procinfo.hProcess = INVALID_HANDLE_VALUE;

	ret = 1;

cleanup:

	if (h != INVALID_HANDLE_VALUE) {
		mycms_system_driver_util_CloseHandle(system)(system, h);
		h = INVALID_HANDLE_VALUE;
	}

	if (startinfo.hStdInput != INVALID_HANDLE_VALUE) {
		mycms_system_driver_util_CloseHandle(system)(system, startinfo.hStdInput);
		startinfo.hStdInput = INVALID_HANDLE_VALUE;
	}

	if (startinfo.hStdOutput != INVALID_HANDLE_VALUE) {
		mycms_system_driver_util_CloseHandle(system)(system, startinfo.hStdOutput);
		startinfo.hStdOutput = INVALID_HANDLE_VALUE;
	}

	if (startinfo.hStdError != INVALID_HANDLE_VALUE) {
		mycms_system_driver_util_CloseHandle(system)(system, startinfo.hStdError);
		startinfo.hStdError = INVALID_HANDLE_VALUE;
	}

	return ret;
}

static
int
__pinentry_native_close(
	const _mycms_pinentry pinentry
) {
	mycms_system system = NULL;
	int ret = 0;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		goto cleanup;
	}

	if (pinentry->channel != INVALID_HANDLE_VALUE) {
		mycms_system_driver_util_CloseHandle(system)(system, pinentry->channel);
		pinentry->channel = INVALID_HANDLE_VALUE;
	}

	if (pinentry->process != INVALID_HANDLE_VALUE) {

		if (mycms_system_driver_util_WaitForSingleObject(system)(
			system,
			pinentry->process, 5000
		) == WAIT_OBJECT_0) {
			mycms_system_driver_util_TerminateProcess(system)(system, pinentry->process, 1);
		}

		mycms_system_driver_util_CloseHandle(system)(system, pinentry->process);
		pinentry->process = INVALID_HANDLE_VALUE;
	}

	ret = 1;

cleanup:

	return ret;
}

static
ssize_t
__pinentry_native_read(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	mycms_system system = NULL;
	DWORD r;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		return -1;
	}

	if (mycms_system_driver_util_ReadFile(system)(system, pinentry->channel, p, s, &r, NULL)) {
		return r;
	}
	return -1;
}

static
ssize_t
__pinentry_native_write(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	mycms_system system = NULL;
	DWORD r;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		return -1;
	}

	if (mycms_system_driver_util_WriteFile(system)(system, pinentry->channel, p, s, &r, NULL)) {
		return r;
	}
	return -1;
}

#else

#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>

static
int
__pinentry_native_exec(
	const _mycms_pinentry pinentry,
	const char * const prog
) {
	mycms_system system = NULL;
	char tty[1024];
	const char * const args[] = {
		prog,
		"--ttyname",
		tty,
		NULL
	};
	int sockets[2] = {-1, -1};
	int ret = 0;
	pid_t child;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		goto cleanup;
	}

	if (mycms_system_driver_util_ttyname_r(system)(system, 0, tty, sizeof(tty)) != 0) {
		tty[0] = '\0';
	}

	if (mycms_system_driver_util_socketpair(system)(system, AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		goto cleanup;
	}

	if ((child = mycms_system_driver_util_fork(system)(system)) == -1) {
		goto cleanup;
	}
	else if (child == 0) {
		struct rlimit r;
		unsigned long i;

		mycms_system_driver_util_close(system)(system, sockets[0]);

		if (mycms_system_driver_util_dup2(system)(system, sockets[1], 0) == -1) {
			goto child_cleanup;
		}
		if (mycms_system_driver_util_dup2(system)(system, sockets[1], 1) == -1) {
			goto child_cleanup;
		}

		if (mycms_system_driver_util_getrlimit(system)(system, RLIMIT_NOFILE, &r) == -1) {
			goto child_cleanup;
		}
		for (i = 4;i < r.rlim_cur;i++) {
			mycms_system_driver_util_close(system)(system, i);
		}

		if (mycms_system_driver_util_execve(system)(
			system,
			prog,
			(char **)args,
			mycms_system_driver_util_get_environ(system)(system)
		) == -1) {
			goto child_cleanup;
		}

	child_cleanup:

		mycms_system_driver_util__exit(system)(system, 1);
	}

	pinentry->channel = sockets[0];
	sockets[0] = -1;
	pinentry->process = child;
	child = -1;

	ret = 1;

cleanup:

	if (sockets[0] != -1) {
		mycms_system_driver_util_close(system)(system, sockets[0]);
		sockets[0] = -1;
	}

	if (sockets[1] != -1) {
		mycms_system_driver_util_close(system)(system, sockets[1]);
		sockets[1] = -1;
	}

	return ret;
}

static
int
__pinentry_native_close(
	const _mycms_pinentry pinentry
) {
	mycms_system system = NULL;
	int ret = 0;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		goto cleanup;
	}

	if (pinentry->channel != -1) {
		mycms_system_driver_util_close(system)(system, pinentry->channel);
		pinentry->channel = -1;
	}

	if (pinentry->process != -1) {
		int fd;
		if ((fd = mycms_system_driver_util_pidfd_open(system)(system, pinentry->process, 0)) == -1) {
			if (mycms_system_driver_util_get_errno(system)(system) == ENOSYS) {
				mycms_system_driver_util_kill(system)(system, pinentry->process, SIGKILL);
				mycms_system_driver_util_waitpid(system)(system, pinentry->process, NULL, 0);
			}
		} else {
			struct pollfd pfd = {fd, POLLIN, 0};
			int r;
			while (
				(r = mycms_system_driver_util_poll(system)(system, &pfd, 1, 5000)) == -1 &&
				mycms_system_driver_util_get_errno(system)(system) == EINTR
			);
			if (r == 0) {
				mycms_system_driver_util_kill(system)(system, pinentry->process, SIGKILL);
			}
			mycms_system_driver_util_waitpid(system)(system, pinentry->process, NULL, 0);
			mycms_system_driver_util_close(system)(system, fd);
		}

		pinentry->process = -1;
	}

	ret = 1;

cleanup:

	return ret;
}

static
ssize_t
__pinentry_native_read(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	mycms_system system = NULL;
	ssize_t r = -1;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		return -1;
	}

	while (1) {
		if ((r = mycms_system_driver_util_read(system)(system, pinentry->channel, p, s)) < 0) {
			int e = mycms_system_driver_util_get_errno(system)(system);
			if (e != EAGAIN && e != EINTR) {
				break;
			}
		} else {
			break;
		}
	}

	return r;
}

static
ssize_t
__pinentry_native_write(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	mycms_system system = NULL;
	ssize_t r = -1;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		return -1;
	}

	while (1) {
		if ((r = mycms_system_driver_util_write(system)(system, pinentry->channel, p, s)) < 0) {
			int e = mycms_system_driver_util_get_errno(system)(system);
			if (e != EAGAIN && e != EINTR) {
				break;
			}
		} else {
			break;
		}
	}

	return r;
}

#endif

static
int
__pinentry_readline(
	const _mycms_pinentry pinentry,
	char * const line,
	const size_t size
) {
	char *p = line;
	size_t s = size;
	ssize_t r;
	int ret = 0;

	while (s > 0) {
		if ((r = __pinentry_native_read(pinentry, p, sizeof(*p))) < 0) {
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
	const _mycms_pinentry pinentry
) {
	char buffer[1024];
	int ret = 0;

	if (!__pinentry_readline(pinentry, buffer, sizeof(buffer))) {
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
	const _mycms_pinentry pinentry,
	char * const buffer,
	const size_t size
) {
	char b[1024];
	int ret = 0;

	if (!__pinentry_readline(pinentry, b, sizeof(b))) {
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
	const _mycms_pinentry pinentry,
	const char *format,
	...
) __attribute__ ((format (printf, 2, 3)));

static
int
__pinentry_printf(
	const _mycms_pinentry pinentry,
	const char *format,
	...
) {
	mycms_system system = NULL;
	va_list args;
	char buffer[1024];
	char *p;
	size_t s;
	ssize_t r;
	int ret = 0;

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		goto cleanup;
	}

	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	p = buffer;
	s = strlen(buffer);
	while (s > 0) {
		if ((r = __pinentry_native_write(pinentry, p, s)) < 0) {
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

_mycms_pinentry
_mycms_util_pinentry_new(
	const mycms mycms
) {
	mycms_system system = NULL;
	_mycms_pinentry pinentry = NULL;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	if ((pinentry = mycms_system_zalloc(system, sizeof(*pinentry))) == NULL) {
		goto cleanup;
	}

	memcpy(pinentry, &__MYCMS_ENTRY_INIT, sizeof(*pinentry));

	pinentry->mycms = mycms;

cleanup:

	return pinentry;
}

int
_mycms_util_pinentry_construct(
	const _mycms_pinentry pinentry,
	const char * const prog
) {
	int ret = 0;

	if (pinentry == NULL) {
		goto cleanup;
	}

	if (!__pinentry_native_exec(pinentry, prog)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

int
_mycms_util_pinentry_destruct(
	const _mycms_pinentry pinentry
) {
	mycms_system system = NULL;
	int ret = 0;

	if (pinentry == NULL) {
		ret = 1;
		goto cleanup;
	}

	if ((system = mycms_get_system(pinentry->mycms)) == NULL) {
		goto cleanup;
	}

	__pinentry_printf(pinentry, "BYE\n");

	if (!__pinentry_native_close(pinentry)) {
		goto cleanup;
	}

	if (!mycms_system_free(system, pinentry)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}

mycms
_mycms_util_pinentry_get_mycms(
	const _mycms_pinentry pinentry
) {
	mycms ret = NULL;

	if (pinentry == NULL) {
		goto cleanup;
	}

	ret = pinentry->mycms;

cleanup:

	return ret;
}

int
_mycms_util_pinentry_exec(
	const _mycms_pinentry pinentry,
	const char * const title,
	const char * const prompt,
	char * const pin,
	const size_t pin_size
) {
	int ret = 0;

	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}
	if (!__pinentry_printf(pinentry, "SETTITLE %s\n", title)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}
	if (!__pinentry_printf(pinentry, "SETPROMPT %s\n", prompt)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}
	if (!__pinentry_printf(pinentry, "GETPIN\n")) {
		goto cleanup;
	}
	if (!__pinentry_read_data(pinentry, pin, pin_size)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}

	ret = 1;

cleanup:

	return ret;
}
