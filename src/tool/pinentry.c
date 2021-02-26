#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "pinentry.h"

#ifdef BUILD_WINDOWS

#include <windows.h>

#define __MYEXEC_NATIVE_INVALID_FD INVALID_HANDLE_VALUE

typedef HANDLE __MYEXEC_NATIVE_HANDLE;

static
__MYEXEC_NATIVE_HANDLE
__pinentry_native_exec(
	const char * const prog
) {
	HANDLE h1 = INVALID_HANDLE_VALUE;
	HANDLE h2 = INVALID_HANDLE_VALUE;
	HANDLE ret = INVALID_HANDLE_VALUE;
	const char * const name = "\\\\.\\pipe\\mycms-%08lx";
	char name_unique[1024];
	STARTUPINFOA startinfo;
	PROCESS_INFORMATION procinfo;
	OVERLAPPED ovelapped;

	ZeroMemory(&startinfo, sizeof(startinfo));
	ZeroMemory(&procinfo, sizeof(procinfo));
	ZeroMemory(&ovelapped, sizeof(ovelapped));
	ovelapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	snprintf(name_unique, sizeof(name_unique), name, GetCurrentProcessId());

	if ((h1 = CreateNamedPipeA(
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

	if (!ConnectNamedPipe(h1, &ovelapped)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			goto cleanup;
		}
	}

	if ((h2 = CreateFile(
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
		if (!GetOverlappedResult(h1, &ovelapped, &dw, TRUE)) {
			goto cleanup;
		}
	}

	startinfo.cb = sizeof(startinfo);
	startinfo.dwFlags = STARTF_USESTDHANDLES;
	if (!DuplicateHandle(GetCurrentProcess(), h2, GetCurrentProcess(), &startinfo.hStdInput, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		goto cleanup;
	}
	if (!DuplicateHandle(GetCurrentProcess(), h2, GetCurrentProcess(), &startinfo.hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		goto cleanup;
	}
	if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(), &startinfo.hStdError, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		goto cleanup;
	}

	if (!CreateProcessA(
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

	ret = h1;
	h1 = INVALID_HANDLE_VALUE;

cleanup:

	if (h1 != INVALID_HANDLE_VALUE) {
		CloseHandle(h1);
	}

	if (h2 != INVALID_HANDLE_VALUE) {
		CloseHandle(h2);
	}

	if (startinfo.hStdInput != 0) {
		CloseHandle(startinfo.hStdInput);
	}

	if (startinfo.hStdOutput != 0) {
		CloseHandle(startinfo.hStdOutput);
	}

	if (startinfo.hStdError != 0) {
		CloseHandle(startinfo.hStdError);
	}

	if (procinfo.hProcess != 0) {
		CloseHandle(procinfo.hProcess);
	}

	return ret;
}

static
void
__pinentry_native_close(
	const __MYEXEC_NATIVE_HANDLE fd
) {
	if (fd != INVALID_HANDLE_VALUE) {
		CloseHandle(fd);
	}
}

static
ssize_t
__pinentry_native_read(
	const __MYEXEC_NATIVE_HANDLE fd,
	void * const p,
	size_t s
) {
	DWORD r;
	if (ReadFile(fd, p, s, &r, NULL)) {
		return r;
	}
	return -1;
}

static
ssize_t
__pinentry_native_write(
	const __MYEXEC_NATIVE_HANDLE fd,
	void * const p,
	size_t s
) {
	DWORD r;
	if (WriteFile(fd, p, s, &r, NULL)) {
		return r;
	}
	return -1;
}

#else

#include <errno.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define __MYEXEC_NATIVE_INVALID_FD -1

typedef int __MYEXEC_NATIVE_HANDLE;

static
__MYEXEC_NATIVE_HANDLE
__pinentry_native_exec(
	const char * const prog
) {
	const char * const tty = ttyname(0);
	const char * const args[] = {
		prog,
		"--ttyname",
		tty == NULL ? "" : tty,
		"--timeout=5",
		NULL
	};
	int sockets[2] = {-1, -1};
	int ret = -1;
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

	close(sockets[1]);
	sockets[1] = -1;
	ret = sockets[0];
	sockets[0] = -1;

cleanup:

	if (sockets[0] != -1) {
		close(sockets[0]);
		sockets[0] = -1;
	}

	if (sockets[1] != -1) {
		close(sockets[1]);
		sockets[1] = -1;
	}

	return ret;
}

static
void
__pinentry_native_close(
	const __MYEXEC_NATIVE_HANDLE fd
) {
	if (fd != -1) {
		close(fd);
	}
}

static
ssize_t
__pinentry_native_read(
	const __MYEXEC_NATIVE_HANDLE fd,
	void * const p,
	size_t s
) {
	return read(fd, p, s);
}

static
ssize_t
__pinentry_native_write(
	const __MYEXEC_NATIVE_HANDLE fd,
	void * const p,
	size_t s
) {
	return write(fd, p, s);
}

#endif

static
int
__pinentry_readline(
	const __MYEXEC_NATIVE_HANDLE fd,
	char * const line,
	const size_t size
) {
	char *p = line;
	size_t s = size;
	ssize_t r;
	int ret = 0;

	while (s > 0) {
		if ((r = __pinentry_native_read(fd, p, sizeof(*p))) < 0) {
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
	const __MYEXEC_NATIVE_HANDLE fd
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
	const __MYEXEC_NATIVE_HANDLE fd,
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
	const __MYEXEC_NATIVE_HANDLE fd,
	const char *format,
	...
) __attribute__ ((format (printf, 2, 3)));

static
int
__pinentry_printf(
	const __MYEXEC_NATIVE_HANDLE fd,
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
		if ((r = __pinentry_native_write(fd, p, s)) < 0) {
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
	__MYEXEC_NATIVE_HANDLE fd = __MYEXEC_NATIVE_INVALID_FD;
	int ret = 0;

	if ((fd = __pinentry_native_exec(prog)) == __MYEXEC_NATIVE_INVALID_FD) {
		goto cleanup;
	}

	if (!__pinentry_read_ok(fd)) {
		goto cleanup;
	}
	if (!__pinentry_printf(fd, "SETTITLE %s\n", title)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(fd)) {
		goto cleanup;
	}
	if (!__pinentry_printf(fd, "SETPROMPT %s\n", prompt)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(fd)) {
		goto cleanup;
	}
	if (!__pinentry_printf(fd, "GETPIN\n")) {
		goto cleanup;
	}
	if (!__pinentry_read_data(fd, pin, pin_size)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(fd)) {
		goto cleanup;
	}

	ret = 1;

cleanup:
	if (fd != __MYEXEC_NATIVE_INVALID_FD) {
		if (!__pinentry_printf(fd, "BYE\n")) {
			goto cleanup;
		}

		__pinentry_native_close(fd);
		fd = __MYEXEC_NATIVE_INVALID_FD;
	}

	return ret;
}
