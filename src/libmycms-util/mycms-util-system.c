#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef BUILD_WINDOWS
#include <windows.h>
#else
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <mycms/mycms-util-system.h>

#include "mycms-system-driver-ids-util.h"

#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT
static
char *
__driver_default_getenv(
	const mycms_system system __attribute__((unused)),
	const char *name
) {
	return getenv(name);
}
static
char **
__driver_default_get_environ(
	const mycms_system system __attribute__((unused))
) {
	extern char **environ;
	return environ;
}

static
FILE *
__driver_default_fopen(
	const mycms_system system __attribute__((unused)),
	const char *pathname,
	const char *mode
) {
	return fopen(pathname, mode);
}
static
int __driver_default_fclose(
	const mycms_system system __attribute__((unused)),
	FILE *stream
) {
	return fclose(stream);
}
static
char *
__driver_default_fgets(
	const mycms_system system __attribute__((unused)),
	char *s,
	int size,
	FILE *stream
) {
	return fgets(s, size, stream);
}

#ifdef BUILD_WINDOWS

static
DWORD
__driver_default_GetLastError(
	const mycms_system system __attribute__((unused))
) {
	return GetLastError();
}
static
HANDLE
__driver_default_GetCurrentProcess(
	const mycms_system system __attribute__((unused))
) {
	return GetCurrentProcess();
}
static
DWORD
__driver_default_GetCurrentProcessId(
	const mycms_system system __attribute__((unused))
) {
	return GetCurrentProcessId();
}
static
DWORD
__driver_default_GetCurrentThreadId(
	const mycms_system system __attribute__((unused))
) {
	return GetCurrentThreadId();
}

static
BOOL
__driver_default_CloseHandle(
	const mycms_system system __attribute__((unused)),
	HANDLE hObject
) {
	return CloseHandle(
		hObject
	);
}
static
BOOL
__driver_default_DuplicateHandle(
	const mycms_system system __attribute__((unused)),
	HANDLE hSourceProcessHandle,
	HANDLE hSourceHandle,
	HANDLE hTargetProcessHandle,
	LPHANDLE lpTargetHandle,
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwOptions
) {
	return DuplicateHandle(
		hSourceProcessHandle,
		hSourceHandle,
		hTargetProcessHandle,
		lpTargetHandle,
		dwDesiredAccess,
		bInheritHandle,
		dwOptions
	);
}
static
BOOL
__driver_default_GetOverlappedResult(
	const mycms_system system __attribute__((unused)),
	HANDLE hFile,
	LPOVERLAPPED lpOverlapped,
	LPDWORD lpNumberOfBytesTransferred,
	BOOL bWait
) {
	return GetOverlappedResult(
		hFile,
		lpOverlapped,
		lpNumberOfBytesTransferred,
		bWait
	);
}
static
DWORD
__driver_default_WaitForSingleObject(
	const mycms_system system __attribute__((unused)),
	HANDLE hHandle,
	DWORD dwMilliseconds
) {
	return WaitForSingleObject(
		hHandle,
		dwMilliseconds
	);
}
static
HANDLE
__driver_default_GetStdHandle(
	const mycms_system system __attribute__((unused)),
	DWORD nStdHandle
) {
	return GetStdHandle(
		nStdHandle
	);
}
static
BOOL
__driver_default_ReadFile(
	const mycms_system system __attribute__((unused)),
	HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	return ReadFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToRead,
		lpNumberOfBytesRead,
		lpOverlapped
	);
}
static
BOOL
__driver_default_WriteFile(
	const mycms_system system __attribute__((unused)),
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
) {
	return WriteFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToWrite,
		lpNumberOfBytesWritten,
		lpOverlapped
	);
}

static
HANDLE
__driver_default_CreateNamedPipeA(
	const mycms_system system __attribute__((unused)),
	LPCSTR lpName,
	DWORD dwOpenMode,
	DWORD dwPipeMode,
	DWORD nMaxInstances,
	DWORD nOutBufferSize,
	DWORD nInBufferSize,
	DWORD nDefaultTimeOut,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
	return CreateNamedPipeA(
		lpName,
		dwOpenMode,
		dwPipeMode,
		nMaxInstances,
		nOutBufferSize,
		nInBufferSize,
		nDefaultTimeOut,
		lpSecurityAttributes
	);
}
static
BOOL
__driver_default_ConnectNamedPipe(
	const mycms_system system __attribute__((unused)),
	HANDLE hNamedPipe,
	LPOVERLAPPED lpOverlapped
) {
	return ConnectNamedPipe(
		hNamedPipe,
		lpOverlapped
	);
}

static
HANDLE
__driver_default_CreateEventA(
	const mycms_system system __attribute__((unused)),
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL bManualReset,
	BOOL bInitialState,
	LPCSTR lpName
) {
	return CreateEventA(
		lpEventAttributes,
		bManualReset,
		bInitialState,
		lpName
	);
}
static
HANDLE
__driver_default_CreateFileA(
	const mycms_system system __attribute__((unused)),
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
) {
	return CreateFileA(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);
}
static
BOOL
__driver_default_CreateProcessA(
	const mycms_system system __attribute__((unused)),
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) {
	return CreateProcessA(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);
}
static
BOOL
__driver_default_TerminateProcess(
	const mycms_system system __attribute__((unused)),
	HANDLE hProcess,
	UINT uExitCode
) {
	return TerminateProcess(hProcess, uExitCode);
}

#else

static
int
__driver_default_get_errno(
	const mycms_system system __attribute__((unused))
) {
	return errno;
}

static
void
__driver_default__exit(
	const mycms_system system __attribute__((unused)),
	int status
) {
	_exit(status);
}
static
int
__driver_default_ttyname_r(
	const mycms_system system __attribute__((unused)),
	int fd,
	char *buf,
	size_t buflen
) {
	return ttyname_r(fd, buf, buflen);
}

static
int
__driver_default_close(
	const mycms_system system __attribute__((unused)),
	int fd
) {
	return close(fd);
}
static
int
__driver_default_dup2(
	const mycms_system system __attribute__((unused)),
	int oldfd,
	int newfd
) {
	return dup2(oldfd, newfd);
}

static
int
__driver_default_execve(
	const mycms_system system __attribute__((unused)),
	const char *pathname,
	char *const argv[],
	char *const envp[]
) {
	return execve(pathname, argv, envp);
}
static
pid_t
__driver_default_fork(
	const mycms_system system __attribute__((unused))
) {
	return fork();
}
static
int
__driver_default_getrlimit(
	const mycms_system system __attribute__((unused)),
	int resource,
	struct rlimit *rlim
) {
	return getrlimit(resource, rlim);
}
static
int
__driver_default_kill(
	const mycms_system system __attribute__((unused)),
	pid_t pid,
	int sig
) {
	return kill(pid, sig);
}
static
int
__driver_default_poll(
	const mycms_system system __attribute__((unused)),
	struct pollfd *fds,
	nfds_t nfds,
	int timeout
) {
	return poll(fds, nfds, timeout);
}
static
ssize_t
__driver_default_read(
	const mycms_system system __attribute__((unused)),
	int fd,
	void *buf,
	size_t count
) {
	return read(fd, buf, count);
}
static
ssize_t
__driver_default_write(
	const mycms_system system __attribute__((unused)),
	int fd,
	const void *buf,
	size_t count
) {
	return write(fd, buf, count);
}
static
int
__driver_default_socketpair(
	const mycms_system system __attribute__((unused)),
	int domain,
	int type,
	int protocol,
	int sv[2]
) {
	return socketpair(domain, type, protocol, sv);
}
static
int
__driver_default_pidfd_open(
	const mycms_system system __attribute__((unused)),
	pid_t pid,
	unsigned int flags
) {
	return syscall(__NR_pidfd_open, pid, flags);
}
static
pid_t
__driver_default_waitpid(
	const mycms_system system __attribute__((unused)),
	pid_t pid,
	int *wstatus,
	int options
) {
	return waitpid(pid, wstatus, options);
}

#endif

#pragma GCC diagnostic ignored "-Wcast-function-type"
static const struct mycms_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ MYCMS_SYSTEM_DRIVER_ID_util_fclose, (void (*)()) __driver_default_fclose},
	{ MYCMS_SYSTEM_DRIVER_ID_util_fgets, (void (*)()) __driver_default_fgets},
	{ MYCMS_SYSTEM_DRIVER_ID_util_fopen, (void (*)()) __driver_default_fopen},
	{ MYCMS_SYSTEM_DRIVER_ID_util_getenv, (void (*)()) __driver_default_getenv},

#ifdef BUILD_WINDOWS
	{ MYCMS_SYSTEM_DRIVER_ID_util_CloseHandle, (void (*)()) __driver_default_CloseHandle},
	{ MYCMS_SYSTEM_DRIVER_ID_util_ConnectNamedPipe, (void (*)()) __driver_default_ConnectNamedPipe},
	{ MYCMS_SYSTEM_DRIVER_ID_util_CreateEventA, (void (*)()) __driver_default_CreateEventA},
	{ MYCMS_SYSTEM_DRIVER_ID_util_CreateFileA, (void (*)()) __driver_default_CreateFileA},
	{ MYCMS_SYSTEM_DRIVER_ID_util_CreateNamedPipeA, (void (*)()) __driver_default_CreateNamedPipeA},
	{ MYCMS_SYSTEM_DRIVER_ID_util_CreateProcessA, (void (*)()) __driver_default_CreateProcessA},
	{ MYCMS_SYSTEM_DRIVER_ID_util_DuplicateHandle, (void (*)()) __driver_default_DuplicateHandle},
	{ MYCMS_SYSTEM_DRIVER_ID_util_GetCurrentProcess, (void (*)()) __driver_default_GetCurrentProcess},
	{ MYCMS_SYSTEM_DRIVER_ID_util_GetCurrentProcessId, (void (*)()) __driver_default_GetCurrentProcessId},
	{ MYCMS_SYSTEM_DRIVER_ID_util_GetCurrentThreadId, (void (*)()) __driver_default_GetCurrentThreadId},
	{ MYCMS_SYSTEM_DRIVER_ID_util_GetLastError, (void (*)()) __driver_default_GetLastError},
	{ MYCMS_SYSTEM_DRIVER_ID_util_GetOverlappedResult, (void (*)()) __driver_default_GetOverlappedResult},
	{ MYCMS_SYSTEM_DRIVER_ID_util_GetStdHandle, (void (*)()) __driver_default_GetStdHandle},
	{ MYCMS_SYSTEM_DRIVER_ID_util_ReadFile, (void (*)()) __driver_default_ReadFile},
	{ MYCMS_SYSTEM_DRIVER_ID_util_TerminateProcess, (void (*)()) __driver_default_TerminateProcess},
	{ MYCMS_SYSTEM_DRIVER_ID_util_WaitForSingleObject, (void (*)()) __driver_default_WaitForSingleObject},
	{ MYCMS_SYSTEM_DRIVER_ID_util_WriteFile, (void (*)()) __driver_default_WriteFile},
#else
	{ MYCMS_SYSTEM_DRIVER_ID_util__exit, (void (*)()) __driver_default__exit},
	{ MYCMS_SYSTEM_DRIVER_ID_util_close, (void (*)()) __driver_default_close},
	{ MYCMS_SYSTEM_DRIVER_ID_util_dup2, (void (*)()) __driver_default_dup2},
	{ MYCMS_SYSTEM_DRIVER_ID_util_execve, (void (*)()) __driver_default_execve},
	{ MYCMS_SYSTEM_DRIVER_ID_util_fork, (void (*)()) __driver_default_fork},
	{ MYCMS_SYSTEM_DRIVER_ID_util_get_environ, (void (*)()) __driver_default_get_environ},
	{ MYCMS_SYSTEM_DRIVER_ID_util_get_errno, (void (*)()) __driver_default_get_errno},
	{ MYCMS_SYSTEM_DRIVER_ID_util_getrlimit, (void (*)()) __driver_default_getrlimit},
	{ MYCMS_SYSTEM_DRIVER_ID_util_kill, (void (*)()) __driver_default_kill},
	{ MYCMS_SYSTEM_DRIVER_ID_util_pidfd_open, (void (*)()) __driver_default_pidfd_open},
	{ MYCMS_SYSTEM_DRIVER_ID_util_poll, (void (*)()) __driver_default_poll},
	{ MYCMS_SYSTEM_DRIVER_ID_util_read, (void (*)()) __driver_default_read},
	{ MYCMS_SYSTEM_DRIVER_ID_util_socketpair, (void (*)()) __driver_default_socketpair},
	{ MYCMS_SYSTEM_DRIVER_ID_util_ttyname_r, (void (*)()) __driver_default_ttyname_r},
	{ MYCMS_SYSTEM_DRIVER_ID_util_waitpid, (void (*)()) __driver_default_waitpid},
	{ MYCMS_SYSTEM_DRIVER_ID_util_write, (void (*)()) __driver_default_write},
#endif

	{ 0, NULL}
};
#pragma GCC diagnostic pop
#else
static const struct mycms_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ 0, NULL}
};
#endif

int
mycms_util_system_init(
	const mycms_system system
) {
	int ret = 0;

	if (system == NULL) {
		goto cleanup;
	}

	mycms_system_driver_register(system, __DRIVER_ENTRIES);

	ret = 1;

cleanup:

	return ret;
}
