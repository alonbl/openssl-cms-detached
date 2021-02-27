include $(top_srcdir)/build/ltrc.inc

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

MYCMS_COMMON_EXPORTS = \
	mycms-certificate.exports \
	mycms-dict.exports \
	mycms-getpass.exports \
	mycms-io.exports \
	mycms-system.exports \
	mycms.exports \
	$(NULL)
MYCMS_SELECTIVE_EXPORTS = \
	mycms-certificate-driver-file.exports \
	mycms-certificate-driver-pkcs11.exports \
	mycms-core-decrypt.exports \
	mycms-core-encrypt.exports \
	mycms-core-sign.exports \
	mycms-core-verify.exports \
	$(NULL)

dist_noinst_DATA = \
	$(MYCMS_COMMON_EXPORTS) \
	$(MYCMS_SELECTIVE_EXPORTS) \
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
libmycms_la_SOURCES = \
	mycms-certificate-private.h \
	mycms-certificate.c \
	mycms-dict.c \
	mycms-getpass.c \
	mycms-io-private.h \
	mycms-io.c \
	mycms-private.h \
	mycms-system.c \
	mycms.c \
	$(NULL)
nodist_libmycms_la_SOURCES = \
	$(NULL)
if BUILD_WINDOWS
nodist_libmycms_la_SOURCES += \
	versioninfo.rc \
	$(NULL)
endif
if ENABLE_PINENTRY
libmycms_la_SOURCES += \
	mycms-pinentry.c \
	mycms-pinentry.h \
	$(NULL)
endif
if ENABLE_CMS_SIGN
libmycms_la_SOURCES += \
	mycms-core-sign.c \
	$(NULL)
endif
if ENABLE_CMS_VERIFY
libmycms_la_SOURCES += \
	mycms-core-verify.c \
	$(NULL)
endif
if ENABLE_CMS_ENCRYPT
libmycms_la_SOURCES += \
	mycms-core-encrypt.c \
	$(NULL)
endif
if ENABLE_CMS_DECRYPT
libmycms_la_SOURCES += \
	mycms-core-decrypt.c \
	$(NULL)
endif
if ENABLE_CERTIFICATE_DRIVER_FILE
libmycms_la_SOURCES += \
	mycms-certificate-driver-file.c \
	$(NULL)
endif
if ENABLE_CERTIFICATE_DRIVER_PKCS11
libmycms_la_SOURCES += \
	mycms-certificate-driver-pkcs11.c \
	pkcs11.h \
	$(NULL)
endif
libmycms_la_LIBADD = \
	$(OPENSSL_LIBS) \
	$(NULL)
libmycms_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info @LIBMYCMS_LT_CURRENT@:@LIBMYCMS_LT_REVISION@:@LIBMYCMS_LT_AGE@ \
	-export-symbols "mycms-all.exports" \
	-no-undefined \
	$(NULL)

mycms-all.exports: \
		$(MYCMS_COMMON_EXPORTS) \
		$(MYCMS_SELECTIVE_EXPORTS) \
		$(builddir)/Makefile \
		$(top_builddir)/config.h \
		$(NULL)
	rm -f mycms-all.exports.tmp
	for f in $(MYCMS_COMMON_EXPORTS); do \
		cat "$(srcdir)/$$f" >> mycms-all.exports.tmp; \
	done
if ENABLE_CMS_SIGN
	cat "$(srcdir)/mycms-core-sign.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CMS_VERIFY
	cat "$(srcdir)/mycms-core-verify.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CMS_ENCRYPT
	cat "$(srcdir)/mycms-core-encrypt.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CMS_DECRYPT
	cat "$(srcdir)/mycms-core-decrypt.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CERTIFICATE_DRIVER_FILE
	cat "$(srcdir)/mycms-certificate-driver-file.exports" >> mycms-all.exports.tmp
endif
if ENABLE_CERTIFICATE_DRIVER_PKCS11
	cat "$(srcdir)/mycms-certificate-driver-pkcs11.exports" >> mycms-all.exports.tmp
endif
	mv mycms-all.exports.tmp mycms-all.exports
