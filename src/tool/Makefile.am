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
	pinentry.c \
	pinentry.h \
	util.c \
	util.h \
	$(NULL)
mycms_tool_LDADD = \
	$(builddir)/../lib/libmycms.la \
	$(NULL)
