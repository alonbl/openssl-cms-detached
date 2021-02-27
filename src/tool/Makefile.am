include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

if ENABLE_TOOL
bin_PROGRAMS = mycms-tool
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

mycms_tool_SOURCES = \
	getoptutil.c \
	getoptutil.h \
	main.c \
	util.c \
	util.h \
	$(NULL)
nodist_mycms_tool_SOURCES = \
	$(NULL)
if BUILD_WINDOWS
nodist_mycms_tool_SOURCES += \
	versioninfo.rc \
	$(NULL)
endif
mycms_tool_LDADD = \
	$(builddir)/../lib/libmycms.la \
	$(NULL)
