#ifndef __MYCMS_SYSTEM_DRIVER_core_H
#define __MYCMS_SYSTEM_DRIVER_core_H

#ifdef BUILD_WINDOWS
#include <windows.h>
#else
#include <poll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <mycms/mycms-system.h>

#include "mycms-system-driver-ids-util.h"

#pragma GCC diagnostic ignored "-Wcast-function-type"
MYCMS_SYSTEM_DRIVER_FUNC(util, char *, getenv, const char *name)
MYCMS_SYSTEM_DRIVER_FUNC(util, char **, get_environ)
MYCMS_SYSTEM_DRIVER_FUNC(util, FILE *, fopen, const char *pathname, const char *mode)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, fclose, FILE *stream)
MYCMS_SYSTEM_DRIVER_FUNC(util, char *, fgets, char *s, int size, FILE *stream)
#ifdef BUILD_WINDOWS
MYCMS_SYSTEM_DRIVER_FUNC(util, DWORD, GetLastError)
MYCMS_SYSTEM_DRIVER_FUNC(util, HANDLE, GetCurrentProcess)
MYCMS_SYSTEM_DRIVER_FUNC(util, DWORD, GetCurrentProcessId)
MYCMS_SYSTEM_DRIVER_FUNC(util, DWORD, GetCurrentThreadId)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, CloseHandle, HANDLE hObject)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, DuplicateHandle,
	HANDLE hSourceProcessHandle,
	HANDLE hSourceHandle,
	HANDLE hTargetProcessHandle,
	LPHANDLE lpTargetHandle,
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwOptions)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, GetOverlappedResult,
	HANDLE hFile,
	LPOVERLAPPED lpOverlapped,
	LPDWORD lpNumberOfBytesTransferred,
	BOOL bWait)
MYCMS_SYSTEM_DRIVER_FUNC(util, DWORD, WaitForSingleObject,
	HANDLE hHandle,
	DWORD dwMilliseconds
)
MYCMS_SYSTEM_DRIVER_FUNC(util, HANDLE, GetStdHandle, DWORD nStdHandle)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, ReadFile,
	HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, WriteFile,
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
MYCMS_SYSTEM_DRIVER_FUNC(util, HANDLE, CreateNamedPipeA,
	LPCSTR lpName,
	DWORD dwOpenMode,
	DWORD dwPipeMode,
	DWORD nMaxInstances,
	DWORD nOutBufferSize,
	DWORD nInBufferSize,
	DWORD nDefaultTimeOut,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, ConnectNamedPipe,
	HANDLE hNamedPipe,
	LPOVERLAPPED lpOverlapped
)
MYCMS_SYSTEM_DRIVER_FUNC(util, HANDLE, CreateEventA,
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL bManualReset,
	BOOL bInitialState,
	LPCSTR lpName)
MYCMS_SYSTEM_DRIVER_FUNC(util, HANDLE, CreateFileA,
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, CreateProcessA,
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
MYCMS_SYSTEM_DRIVER_FUNC(util, BOOL, TerminateProcess,
	HANDLE hProcess,
	UINT uExitCode)

#else

MYCMS_SYSTEM_DRIVER_FUNC(util, int, get_errno)
MYCMS_SYSTEM_DRIVER_FUNC(util, void, _exit, int status)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, ttyname_r, int fd, char *buf, size_t buflen)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, close, int fd)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, dup2, int oldfd, int newfd)

MYCMS_SYSTEM_DRIVER_FUNC(util, int, execve, const char *pathname, char *const argv[], char *const envp[])
MYCMS_SYSTEM_DRIVER_FUNC(util, pid_t, fork)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, getrlimit, int resource, struct rlimit *rlim)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, kill, pid_t pid, int sig)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, poll, struct pollfd *fds, nfds_t nfds, int timeout)
MYCMS_SYSTEM_DRIVER_FUNC(util, ssize_t, read, int fd, void *buf, size_t count)
MYCMS_SYSTEM_DRIVER_FUNC(util, ssize_t, write, int fd, const void *buf, size_t count)
MYCMS_SYSTEM_DRIVER_FUNC(util, int, socketpair, int domain, int type, int protocol, int sv[2])
MYCMS_SYSTEM_DRIVER_FUNC(util, int, pidfd_open, pid_t pid, unsigned int flags)
MYCMS_SYSTEM_DRIVER_FUNC(util, pid_t, waitpid, pid_t pid, int *wstatus, int options)
#endif

#pragma GCC diagnostic pop

#endif
