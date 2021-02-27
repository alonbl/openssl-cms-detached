#ifndef __MYCMS_SYSTEM_H
#define __MYCMS_SYSTEM_H

#ifdef BUILD_WINDOWS
#include <windows.h>
#else
#include <poll.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#define MYCMS_SYSTEM_CONTEXT_SIZE 1024

struct mycms_system_s;
typedef struct mycms_system_s *mycms_system;

struct mycms_system_driver_s {
	int (*cleanse)(
		const mycms_system system,
		void * const p,
		const size_t size
	);

	void *(*malloc)(
		const mycms_system system,
		const size_t size
	);
	void *(*realloc)(
		const mycms_system system,
		void * const p,
		const size_t size
	);
	int (*free)(
		const mycms_system system,
		void * const p
	);

	char *(*getenv)(
		const mycms_system system,
		const char *name
	);
	char **(*get_environ)(
		const mycms_system system
	);

	FILE *(*fopen)(
		const mycms_system system,
		const char *pathname,
		const char *mode
	);
	int (*fclose)(
		const mycms_system system,
		FILE *stream
	);
	char *(*fgets)(
		const mycms_system system,
		char *s,
		int size,
		FILE *stream
	);

#ifdef BUILD_WINDOWS

	DWORD (*GetLastError)(
		const mycms_system system
	);
	HANDLE (*GetCurrentProcess)(
		const mycms_system system
	);
	DWORD (*GetCurrentProcessId)(
		const mycms_system system
	);
	DWORD (*GetCurrentThreadId)(
		const mycms_system system
	);

	BOOL (*CloseHandle)(
		const mycms_system system,
		HANDLE hObject
	);
	BOOL (*DuplicateHandle)(
		const mycms_system system,
		HANDLE hSourceProcessHandle,
		HANDLE hSourceHandle,
		HANDLE hTargetProcessHandle,
		LPHANDLE lpTargetHandle,
		DWORD dwDesiredAccess,
		BOOL bInheritHandle,
		DWORD dwOptions
	);
	BOOL (*GetOverlappedResult)(
		const mycms_system system,
		HANDLE hFile,
		LPOVERLAPPED lpOverlapped,
		LPDWORD lpNumberOfBytesTransferred,
		BOOL bWait
	);
	DWORD (*WaitForSingleObject)(
		const mycms_system system,
		HANDLE hHandle,
		DWORD dwMilliseconds
	);
	HANDLE (*GetStdHandle)(
		const mycms_system system,
		DWORD nStdHandle
	);
	BOOL (*ReadFile)(
		const mycms_system system,
		HANDLE hFile,
		LPVOID lpBuffer,
		DWORD nNumberOfBytesToRead,
		LPDWORD lpNumberOfBytesRead,
		LPOVERLAPPED lpOverlapped
	);
	BOOL (*WriteFile)(
		const mycms_system system,
		HANDLE hFile,
		LPCVOID lpBuffer,
		DWORD nNumberOfBytesToWrite,
		LPDWORD lpNumberOfBytesWritten,
		LPOVERLAPPED lpOverlapped
	);

	HANDLE (*CreateNamedPipeA)(
		const mycms_system system,
		LPCSTR lpName,
		DWORD dwOpenMode,
		DWORD dwPipeMode,
		DWORD nMaxInstances,
		DWORD nOutBufferSize,
		DWORD nInBufferSize,
		DWORD nDefaultTimeOut,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);
	BOOL (*ConnectNamedPipe)(
		const mycms_system system,
		HANDLE hNamedPipe,
		LPOVERLAPPED lpOverlapped
	);

	HANDLE (*CreateEventA)(
		const mycms_system system,
		LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL bManualReset,
		BOOL bInitialState,
		LPCSTR lpName
	);
	HANDLE (*CreateFileA)(
		const mycms_system system,
		LPCSTR lpFileName,
		DWORD dwDesiredAccess,
		DWORD dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD dwCreationDisposition,
		DWORD dwFlagsAndAttributes,
		HANDLE hTemplateFile
	);
	BOOL (*CreateProcessA)(
		const mycms_system system,
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
	);
	BOOL (*TerminateProcess)(
		const mycms_system system,
		HANDLE hProcess,
		UINT uExitCode
	);

	HMODULE (*LoadLibraryA)(
		const mycms_system system,
		LPCSTR lpLibFileName
	);
	BOOL (*FreeLibrary)(
		const mycms_system system,
		HMODULE hLibModule
	);
	FARPROC (*GetProcAddress)(
		const mycms_system system,
		HMODULE hModule,
		LPCSTR lpProcName
	);

#else
	int (*get_errno)(
		const mycms_system system
	);

	void (*_exit)(
		const mycms_system system,
		int status
	);
	int (*ttyname_r)(
		const mycms_system system,
		int fd,
		char *buf,
		size_t buflen
	);

	int (*close)(
		const mycms_system system,
		int fd
	);
	int (*dup2)(
		const mycms_system system,
		int oldfd,
		int newfd
	);

	int (*dlclose)(
		const mycms_system system,
		void *handle
	);
	void *(*dlopen)(
		const mycms_system system,
		const char *filename,
		int flags
	);
	void *(*dlsym)(
		const mycms_system system,
		void *handle,
		const char *symbol
	);

	int (*execve)(
		const mycms_system system,
		const char *pathname,
		char *const argv[],
		char *const envp[]
	);
	pid_t (*fork)(
		const mycms_system system
	);
	int (*getrlimit)(
		const mycms_system system,
		int resource,
		struct rlimit *rlim
	);
	int (*kill)(
		const mycms_system system,
		pid_t pid,
		int sig
	);
	int (*poll)(
		const mycms_system system,
		struct pollfd *fds,
		nfds_t nfds,
		int timeout
	);
	ssize_t (*read)(
		const mycms_system system,
		int fd,
		void *buf,
		size_t count
	);
	ssize_t (*write)(
		const mycms_system system,
		int fd,
		const void *buf,
		size_t count
	);
	int (*socketpair)(
		const mycms_system system,
		int domain,
		int type,
		int protocol,
		int sv[2]
	);
	int (*pidfd_open)(
		const mycms_system system __attribute__((unused)),
		pid_t pid,
		unsigned int flags
	);
	pid_t (*waitpid)(
		const mycms_system system,
		pid_t pid,
		int *wstatus,
		int options
	);

#endif
};
typedef struct mycms_system_driver_s *mycms_system_driver;

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

mycms_system_driver
mycms_system_get_driver(
	const mycms_system system
);

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
