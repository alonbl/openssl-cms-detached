MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)
DISTCLEANFILES = \
	libmycms.pc \
	$(NULL)
CLEANFILES = \
	mycms-all.exports \
	mycms-all.exports.tmp \
	$(NULL)

MYCMS_EXPORTS = \
	mycms-certificate-driver-pkcs11.exports \
	mycms-certificate-driver-file.exports \
	mycms-certificate.exports \
	mycms.exports \
	mycms-decrypt.exports \
	mycms-encrypt.exports \
	$(NULL)

dist_noinst_DATA= \
	$(MYCMS_EXPORTS) \
	$(NULL)

pkgconfig_DATA = libmycms.pc
lib_LTLIBRARIES = libmycms.la

AM_CFLAGS = \
	$(OPENSSL_CFLAGS) \
	$(NULL)
AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

libmycms_la_DEPENDENCIES = \
	mycms-all.exports \
	$(NULL)
libmycms_la_SOURCES= \
	mycms-certificate-driver-file.c \
	mycms-certificate-driver-pkcs11.c \
	mycms-certificate-private.h \
	mycms-certificate.c \
	mycms-decrypt.c \
	mycms-encrypt.c \
	mycms.c \
	$(NULL)
libmycms_la_LIBADD = \
	$(OPENSSL_LIBS) \
	$(NULL)
libmycms_la_LDFLAGS= \
	$(AM_LDFLAGS) \
	-version-info @LIBMYCMS_LT_CURRENT@:@LIBMYCMS_LT_REVISION@:@LIBMYCMS_LT_AGE@ \
	-export-symbols "mycms-all.exports" \
	-no-undefined \
	$(NULL)

mycms-all.exports: \
		$(top_builddir)/config.h \
		$(top_builddir)/Makefile \
		$(MYCMS_EXPORTS) \
		$(NULL)
	cat "$(srcdir)/mycms.exports" > mycms-all.exports.tmp
	cat "$(srcdir)/mycms-certificate.exports" >> mycms-all.exports.tmp
if ENABLE_CMS_DECRYPT
	cat "$(srcdir)/mycms-decrypt.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CMS_ENCRYPT
	cat "$(srcdir)/mycms-encrypt.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CERTIFICATE_DRIVER_PKCS11
	cat "$(srcdir)/mycms-certificate-driver-pkcs11.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CERTIFICATE_DRIVER_FILE
	cat "$(srcdir)/mycms-certificate-driver-file.exports" >> mycms-all.exports.tmp
endif
	mv mycms-all.exports.tmp mycms-all.exports
