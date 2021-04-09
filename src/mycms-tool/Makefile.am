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
	cmd-common.c \
	cmd-common.h \
	getoptutil.c \
	getoptutil.h \
	main.c \
	util.c \
	util.h \
	$(NULL)
if ENABLE_CMS_SIGN
mycms_tool_SOURCES += \
	cmd-sign.c \
	cmd-sign.h \
	$(NULL)
endif
if ENABLE_CMS_VERIFY
mycms_tool_SOURCES += \
	cmd-verify.c \
	cmd-verify.h \
	$(NULL)
endif
if ENABLE_CMS_ENCRYPT
mycms_tool_SOURCES += \
	cmd-encrypt.c \
	cmd-encrypt.h \
	$(NULL)
endif
if ENABLE_CMS_DECRYPT
mycms_tool_SOURCES += \
	cmd-decrypt.c \
	cmd-decrypt.h \
	$(NULL)
endif
nodist_mycms_tool_SOURCES = \
	$(NULL)
if BUILD_WINDOWS
nodist_mycms_tool_SOURCES += \
	versioninfo.rc \
	$(NULL)
endif
mycms_tool_LDADD = \
	$(builddir)/../libmycms-util/libmycms-util.la \
	$(builddir)/../libmycms/libmycms.la \
	$(NULL)
