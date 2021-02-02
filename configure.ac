AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [1])
define([PACKAGE_VERSION_MINOR], [28])
define([PACKAGE_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [_master])

AC_INIT([mycms],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([include/mycms.h])
AM_INIT_AUTOMAKE

MYCMS_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
MYCMS_VERSION_MINOR="$(echo PACKAGE_VERSION_MINOR | sed 's/^0*//')"
MYCMS_VERSION_FIX="PACKAGE_VERSION_FIX"

AC_SUBST([MYCMS_VERSION_MAJOR])
AC_SUBST([MYCMS_VERSION_MINOR])
AC_SUBST([MYCMS_VERSION_FIX])

LIBMYCMS_LT_CURRENT="1"
LIBMYCMS_LT_OLDEST="1"
LIBMYCMS_LT_REVISION="0"
LIBMYCMS_LT_AGE="$((${LIBMYCMS_LT_CURRENT}-${LIBMYCMS_LT_OLDEST}))"

AC_CANONICAL_HOST

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compiler warnings])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compiler warnings])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[all-static],
	[AS_HELP_STRING([--enable-all-static],[enable all static mode])],
	,
	[enable_all_static="no"]
)

AC_ARG_ENABLE(
	[tool],
	[AS_HELP_STRING([--disable-tool],[disable tool])],
	,
	[enable_tool="yes"]
)

AC_ARG_ENABLE(
	[openssl-err-strings],
	[AS_HELP_STRING([--disable-openssl-err-strings],[disable openssl error strings])],
	,
	[enable_openssl_err_strings="yes"]
)

AC_ARG_ENABLE(
	[cms-decrypt],
	[AS_HELP_STRING([--disable-cms-decrypt],[disable cms decrypt support])],
	,
	[enable_cms_decrypt="yes"]
)

AC_ARG_ENABLE(
	[cms-encrypt],
	[AS_HELP_STRING([--disable-cms-encrypt],[disable cms encrypt support])],
	,
	[enable_cms_encrypt="yes"]
)

AC_ARG_ENABLE(
	[certificate-driver-file],
	[AS_HELP_STRING([--disable-certificate-driver-file],[disable certificate file driver support])],
	,
	[enable_certificate_driver_file="yes"]
)

AC_ARG_ENABLE(
	[certificate-driver-pkcs11],
	[AS_HELP_STRING([--disable-certificate-driver-pkcs11],[disable certificate pkcs11 driver support])],
	,
	[enable_certificate_driver_pkcs11="yes"]
)

AC_ARG_WITH(
	[test-provider],
	[AS_HELP_STRING([--with-test-provider=lib],[specify providers for test phase])],
	[AC_DEFINE_UNQUOTED([TEST_PROVIDER], ["${withval}"], [Test provider])],
	[AC_DEFINE_UNQUOTED([TEST_PROVIDER], ["/usr/lib/pkcs11/provider.so"], [Test provider])]
)

AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG
LT_INIT

if test "${enable_all_static}" = "yes"; then
	PKG_CHECK_MODULES_STATIC(
		[OPENSSL],
		[libcrypto >= 1.1.0],
		,
		[AC_MSG_ERROR([Cannot locate openssl])]
	)
	# Fix segmentation error per pthread_setspecific is linked but pthread_mutex_lock is not
	if echo "${OPENSSL_LIBS}" | grep -q pthread; then
		OPENSSL_LIBS="${OPENSSL_LIBS} -Wl,-u,pthread_mutex_lock -Wl,-u,pthread_mutex_unlock"
	fi
else
	PKG_CHECK_MODULES(
		[OPENSSL],
		[libcrypto >= 1.1.0],
		,
		[AC_MSG_ERROR([Cannot locate openssl])]
	)
fi

test "${enable_tool}" = "yes" -a "${enable_certificate_driver_file}" != "yes" && \
	AC_MSG_ERROR([Tool requires file certificate driver])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -ansi -pedantic -D__STRICT_ANSI__ -D_ISOC99_SOURCE -D_DEFAULT_SOURCE"
fi

if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_HEADER_STDC
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T

AC_ARG_VAR([VALGRIND], [path to valgrind utility])
AC_CHECK_PROGS([VALGRIND], [valgrind])

test "${enable_all_static}" = "yes" && \
	LDFLAGS="${LDFLAGS} -all-static"

test "${enable_tool}" = "yes" && AC_DEFINE([ENABLE_TOOL], [1], [Enable tool])
test "${enable_openssl_err_strings}" = "yes" && AC_DEFINE([ENABLE_OPENSSL_ERR_STRINGS], [1], [Enable openssl error strings])
test "${enable_cms_decrypt}" = "yes" && AC_DEFINE([ENABLE_CMS_DECRYPT], [1], [Enable cms decrypt])
test "${enable_cms_encrypt}" = "yes" && AC_DEFINE([ENABLE_CMS_ENCRYPT], [1], [Enable cms encrypt])
test "${enable_certificate_driver_file}" = "yes" && AC_DEFINE([ENABLE_CERTIFICATE_DRIVER_FILE], [1], [Enable cms certificate file driver])
if test "${enable_certificate_driver_pkcs11}" = "yes"; then
	AC_DEFINE([ENABLE_CERTIFICATE_DRIVER_PKCS11], [1], [Enable cms pkcs11 file driver])
	AC_CHECK_LIB([dl], [dlopen])
fi

pkgconfigdir="\$(libdir)/pkgconfig"
mycmsincludedir="\$(includedir)/mycms"
AC_SUBST([pkgconfigdir])
AC_SUBST([mycmsincludedir])
AC_SUBST([LIBMYCMS_LT_CURRENT])
AC_SUBST([LIBMYCMS_LT_REVISION])
AC_SUBST([LIBMYCMS_LT_AGE])
AC_SUBST([LIBMYCMS_LT_OLDEST])
AM_CONDITIONAL([ENABLE_TOOL], [test "${enable_tool}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_DECRYPT], [test "${enable_cms_decrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_ENCRYPT], [test "${enable_cms_encrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_CERTIFICATE_DRIVER_FILE], [test "${enable_certificate_driver_file}" = "yes"])
AM_CONDITIONAL([ENABLE_CERTIFICATE_DRIVER_PKCS11], [test "${enable_certificate_driver_pkcs11}" = "yes"])
AC_CONFIG_FILES([
	Makefile
	include/Makefile
	src/Makefile
	src/lib/Makefile
	src/lib/libmycms.pc
	src/tool/Makefile
	test/Makefile
])
AC_OUTPUT
