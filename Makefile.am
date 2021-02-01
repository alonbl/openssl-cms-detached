AUTOMAKE_OPTIONS = foreign dist-bzip2 1.10
ACLOCAL_AMFLAGS = -I m4 --install

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/compile $(srcdir)/aclocal.m4 \
	$(srcdir)/test-driver \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/m4/ltsugar.m4 $(srcdir)/m4/libtool.m4 \
	$(srcdir)/m4/ltversion.m4 $(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4 \
	$(NULL)

EXTRA_DIST = \
	.gitignore \
	$(NULL)

SUBDIRS = \
	include \
	src \
	test \
	$(NULL)

dist_doc_DATA = \
	README.md \
	$(NULL)

dist_noinst_DATA = \
	TODO.md \
	$(NULL)
