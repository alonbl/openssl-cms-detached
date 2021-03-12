include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)
DISTCLEANFILES = \
	libmycms-util.pc \
	$(NULL)
CLEANFILES = \
	mycms-system-driver-ids-util.h \
	mycms-util-all.exports \
	mycms-util-all.exports.tmp \
	$(NULL)

MYCMS_SYSTEM_DRIVER_IMPORTS = \
	fclose \
	fgets \
	fopen \
	get_environ \
	getenv \
	$(NULL)
if BUILD_WINDOWS
MYCMS_SYSTEM_DRIVER_IMPORTS += \
	CloseHandle \
	ConnectNamedPipe \
	CreateEventA \
	CreateFileA \
	CreateNamedPipeA \
	CreateProcessA \
	DuplicateHandle \
	GetCurrentProcess \
	GetCurrentProcessId \
	GetCurrentThreadId \
	GetLastError \
	GetOverlappedResult \
	GetStdHandle \
	ReadFile \
	TerminateProcess \
	WaitForSingleObject \
	WriteFile \
	$(NULL)
else
MYCMS_SYSTEM_DRIVER_IMPORTS += \
	_exit \
	close \
	dup2 \
	execve \
	fork \
	get_errno \
	getrlimit \
	kill \
	pidfd_open \
	poll \
	read \
	socketpair \
	ttyname_r \
	waitpid \
	write \
	$(NULL)
endif
MYCMS_UTIL_COMMON_EXPORTS = \
	mycms-util.exports \
	mycms-util-getpass.exports \
	$(NULL)
MYCMS_UTIL_SELECTIVE_EXPORTS = \
	$(NULL)

BUILT_SOURCES = \
	mycms-system-driver-ids-util.h \
	$(NULL)

dist_noinst_DATA = \
	$(MYCMS_UTIL_COMMON_EXPORTS) \
	$(MYCMS_UTIL_SELECTIVE_EXPORTS) \
	$(NULL)

pkgconfig_DATA = libmycms-util.pc
lib_LTLIBRARIES = libmycms-util.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

libmycms_util_la_DEPENDENCIES = \
	mycms-util-all.exports \
	$(NULL)
libmycms_util_la_SOURCES = \
	mycms-system-driver-util.h \
	mycms-util-getpass.c \
	mycms-util-system.c \
	$(NULL)
nodist_libmycms_util_la_SOURCES = \
	$(NULL)
if BUILD_WINDOWS
nodist_libmycms_util_la_SOURCES += \
	versioninfo.rc \
	$(NULL)
endif
if ENABLE_PINENTRY
libmycms_util_la_SOURCES += \
	mycms-util-pinentry.c \
	mycms-util-pinentry.h \
	$(NULL)
endif
libmycms_util_la_LIBADD = \
	$(builddir)/../libmycms/libmycms.la \
	$(NULL)
libmycms_util_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info @LIBMYCMS_LT_CURRENT@:@LIBMYCMS_LT_REVISION@:@LIBMYCMS_LT_AGE@ \
	-export-symbols "mycms-util-all.exports" \
	-no-undefined \
	$(NULL)

mycms-system-driver-ids-util.h:	\
		Makefile.am \
		$(NULL)
	"$(top_srcdir)/build/mycms-system-driver-id-gen.sh" util $(MYCMS_SYSTEM_DRIVER_IMPORTS) > "$@"
mycms-util-all.exports: \
		$(MYCMS_UTIL_COMMON_EXPORTS) \
		$(MYCMS_UTIL_SELECTIVE_EXPORTS) \
		$(builddir)/Makefile \
		$(top_builddir)/config.h \
		$(NULL)
	rm -f mycms-util-all.exports.tmp
	for f in $(MYCMS_UTIL_COMMON_EXPORTS); do \
		cat "$(srcdir)/$$f" >> mycms-util-all.exports.tmp; \
	done
	mv mycms-util-all.exports.tmp mycms-util-all.exports
