MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

CLEANFILES = \
	built.pki \
	$(NULL)

clean-local:
	rm -fr gen

check-am: built.pki

dist_noinst_SCRIPTS = \
	test-file.sh \
	test-pkcs11.sh \
	$(NULL)

dist_noinst_DATA = \
	softhsm2.conf.in \
	test-pkcs11.valgrind.supp \
	$(NULL)

TESTS_ENVIRONMENT = \
	builddir="$(builddir)" \
	top_builddir="$(top_builddir)" \
	MYCMS_TOOL="$(top_builddir)/src/tool/mycms-tool" \
	SOFTHSM2_UTIL="$(SOFTHSM2_UTIL)" \
	PKCS11_TOOL="$(PKCS11_TOOL)" \
	VALGRIND="$(VALGRIND)" \
	LIBTOOL="$(LIBTOOL)" \
	$(NULL)

TESTS = \
	test-file.sh \
	test-pkcs11.sh \
	$(NULL)

built.pki:	Makefile
	rm -fr gen
	mkdir gen
	for i in 1 2 3 4 5; do \
		abs_builddir="$(abs_top_builddir)/test/ca" "$(top_srcdir)/test/ca/issue.sh" encrypt test$$i gen/test$$i.crt gen/test$$i.key; \
	done
	touch built.pki
