MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

CLEANFILES = \
	built.pki \
	$(NULL)

clean-local:
	rm -fr gen

check-am: built.pki

dist_noinst_DATA = \
	test-file.bat \
	$(NULL)

built.pki:	Makefile
	rm -fr gen
	mkdir gen
	for i in 1; do \
		abs_builddir="$(abs_top_builddir)/test/ca" "$(top_srcdir)/test/ca/issue.sh" sign test$$i gen/test$$i.crt gen/test$$i.key; \
	done
	touch built.pki
