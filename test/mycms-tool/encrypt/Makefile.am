MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

CLEANFILES = \
	built.pki \
	$(NULL)

clean-local:
	rm -fr gen

if !BUILD_WINDOWS
check-am: built.pki

TESTS = \
	test-file.sh \
	test-pkcs11.sh \
	$(NULL)
endif

dist_noinst_SCRIPTS = \
	test-file.sh \
	test-pkcs11.sh \
	$(NULL)

dist_noinst_DATA = \
	softhsm2.conf.in \
	test-pkcs11.valgrind.supp \
	$(NULL)

TESTS_ENVIRONMENT = \
	LIBTOOL="$(LIBTOOL)" \
	MYCMS_TOOL="$(top_builddir)/src/mycms-tool/mycms-tool$(EXEEXT)" \
	OPENSSL="$(OPENSSL)" \
	PKCS11_TOOL="$(PKCS11_TOOL)" \
	SOFTHSM2_MODULE="$(SOFTHSM2_MODULE)" \
	SOFTHSM2_UTIL="$(SOFTHSM2_UTIL)" \
	VALGRIND="$(VALGRIND)" \
	builddir="$(builddir)" \
	top_builddir="$(top_builddir)" \
	$(NULL)

built.pki:	Makefile
	rm -fr gen
	mkdir gen
	for i in 1 2 3 4 5; do \
		abs_builddir="$(abs_top_builddir)/test/ca" "$(top_srcdir)/test/ca/issue.sh" encrypt test$$i gen/test$$i.crt gen/test$$i.key; \
	done
	touch built.pki
