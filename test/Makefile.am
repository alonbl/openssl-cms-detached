MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

dist_noinst_SCRIPTS = \
	test.sh \
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
	VALGRIND="$(VALGRIND)" \
	$(NULL)
TESTS = \
	test.sh \
	$(NULL)
