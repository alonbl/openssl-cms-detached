#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef BUILD_WINDOWS
#include <windows.h>
#else
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <mycms/mycms-system.h>

struct mycms_system_s {
	const void *userdata;
	struct mycms_system_driver_s driver;
};

#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT

static
int
__driver_default_cleanse(
	const mycms_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
#if defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(p, size);
#elif defined(HAVE_SECUREZEROMEMORY)
	SecureZeroMemory(p, size);
#else
	memset(p, 0, size);
#endif
	return 1;
}

static
void *
__driver_default_malloc(
	const mycms_system system __attribute__((unused)),
	const size_t size
) {
	return malloc(size);
}
static
void *
__driver_default_realloc(
	const mycms_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
	return realloc(p, size);
}
static
int
__driver_default_free(
	const mycms_system system __attribute__((unused)),
	void * const p
) {
	free(p);
	return 1;
}

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

static
HMODULE
__driver_default_LoadLibraryA(
	const mycms_system system __attribute__((unused)),
	LPCSTR lpLibFileName
) {
	return LoadLibraryA(lpLibFileName);
}
static
BOOL
__driver_default_FreeLibrary(
	const mycms_system system __attribute__((unused)),
	HMODULE hLibModule
) {
	return FreeLibrary(hLibModule);
}
static
FARPROC
__driver_default_GetProcAddress(
	const mycms_system system __attribute__((unused)),
	HMODULE hModule,
	LPCSTR lpProcName
) {
	return GetProcAddress(hModule, lpProcName);
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
__driver_default_dlclose(
	const mycms_system system __attribute__((unused)),
	void *handle
) {
	return dlclose(handle);
}
static
void *
__driver_default_dlopen(
	const mycms_system system __attribute__((unused)),
	const char *filename,
	int flags
) {
	return dlopen(filename, flags);
}
static
void *
__driver_default_dlsym(
	const mycms_system system __attribute__((unused)),
	void *handle,
	const char *symbol
) {
	return dlsym(handle, symbol);
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
static const struct mycms_system_s __MYCMS_SYSTEM_INIT = {
	NULL,
	{
		__driver_default_cleanse,
		__driver_default_malloc,
		__driver_default_realloc,
		__driver_default_free,
		__driver_default_getenv,
		__driver_default_get_environ,
		__driver_default_fopen,
		__driver_default_fclose,
		__driver_default_fgets,
#ifdef BUILD_WINDOWS
		__driver_default_GetLastError,
		__driver_default_GetCurrentProcess,
		__driver_default_GetCurrentProcessId,
		__driver_default_GetCurrentThreadId,
		__driver_default_CloseHandle,
		__driver_default_DuplicateHandle,
		__driver_default_GetOverlappedResult,
		__driver_default_WaitForSingleObject,
		__driver_default_GetStdHandle,
		__driver_default_ReadFile,
		__driver_default_WriteFile,
		__driver_default_CreateNamedPipeA,
		__driver_default_ConnectNamedPipe,
		__driver_default_CreateEventA,
		__driver_default_CreateFileA,
		__driver_default_CreateProcessA,
		__driver_default_TerminateProcess,
		__driver_default_LoadLibraryA,
		__driver_default_FreeLibrary,
		__driver_default_GetProcAddress,
#else
		__driver_default_get_errno,
		__driver_default__exit,
		__driver_default_ttyname_r,
		__driver_default_close,
		__driver_default_dup2,
		__driver_default_dlclose,
		__driver_default_dlopen,
		__driver_default_dlsym,
		__driver_default_execve,
		__driver_default_fork,
		__driver_default_getrlimit,
		__driver_default_kill,
		__driver_default_poll,
		__driver_default_read,
		__driver_default_write,
		__driver_default_socketpair,
		__driver_default_pidfd_open,
		__driver_default_waitpid
#endif
	}
};
#else
static const struct mycms_system_s __MYCMS_SYSTEM_INIT;
#endif

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

mycms_system_driver
mycms_system_get_driver(
	const mycms_system system
) {
	return &system->driver;
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

	ret = system->driver.cleanse(system, p, size);

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

	ret = system->driver.malloc(system, size);

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

	ret = system->driver.realloc(system, p, size);

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

	ret = system->driver.free(system, p);

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
