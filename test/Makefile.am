MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

dist_noinst_SCRIPTS = \
	test-file.sh \
	test-pkcs11.sh \
	$(NULL)

dist_noinst_DATA = \
	test1.der \
	test1.key \
	test2.der \
	test2.key \
	test3.der \
	test3.key \
	test4.der \
	test4.key \
	test5.der \
	test5.key \
	$(NULL)

TESTS_ENVIRONMENT = \
	MYCMS_TOOL="$(top_builddir)/src/tool/mycms-tool" \
	SOFTHSM2_UTIL="$(SOFTHSM2_UTIL)" \
	PKCS11_TOOL="$(PKCS11_TOOL)" \
	VALGRIND="$(VALGRIND)" \
	$(NULL)
TESTS = \
	test-file.sh \
	test-pkcs11.sh \
	$(NULL)
