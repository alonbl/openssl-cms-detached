AUTOMAKE_OPTIONS = foreign dist-bzip2 1.10
ACLOCAL_AMFLAGS = -I m4 --install

#@AM_DISTCHECK_CONFIGURE_FLAGS-BEGIN
AM_DISTCHECK_CONFIGURE_FLAGS = \
	--enable-certificate-driver-file \
	--enable-certificate-driver-pkcs11 \
	--enable-cms-decrypt \
	--enable-cms-encrypt \
	--enable-cms-sign \
	--enable-cms-verify \
	--enable-io-driver-file \
	--enable-openssl-err-strings \
	--enable-pedantic \
	--enable-strict \
	--enable-tests \
	--enable-tool \
	$(NULL)
#@AM_DISTCHECK_CONFIGURE_FLAGS-END

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
	$(NULL)
if ENABLE_TESTS
SUBDIRS += \
	test \
	$(NULL)
endif

dist_doc_DATA = \
	README.md \
	$(NULL)

dist_noinst_DATA = \
	TODO.md \
	$(NULL)

dist_noinst_SCRIPTS = \
	conf-dev.sh \
	$(NULL)
