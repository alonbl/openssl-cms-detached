AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [0])
define([PACKAGE_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [_master])

AC_INIT([mycms],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([include/mycms/mycms.h])
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
	[AS_HELP_STRING([--enable-strict], [enable strict compiler warnings])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic], [enable pedantic compiler warnings])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[all-static],
	[AS_HELP_STRING([--enable-all-static], [enable all static mode])],
	,
	[enable_all_static="no"]
)

AC_ARG_ENABLE(
	[tool],
	[AS_HELP_STRING([--disable-tool], [disable tool])],
	,
	[enable_tool="yes"]
)

AC_ARG_ENABLE(
	[openssl-err-strings],
	[AS_HELP_STRING([--disable-openssl-err-strings], [disable openssl error strings])],
	,
	[enable_openssl_err_strings="yes"]
)

AC_ARG_ENABLE(
	[cms-sign],
	[AS_HELP_STRING([--disable-cms-sign], [disable cms sign support])],
	,
	[enable_cms_sign="yes"]
)

AC_ARG_ENABLE(
	[cms-verify],
	[AS_HELP_STRING([--disable-cms-verify], [disable cms verify support])],
	,
	[enable_cms_verify="yes"]
)

AC_ARG_ENABLE(
	[cms-decrypt],
	[AS_HELP_STRING([--disable-cms-decrypt], [disable cms decrypt support])],
	,
	[enable_cms_decrypt="yes"]
)

AC_ARG_ENABLE(
	[cms-encrypt],
	[AS_HELP_STRING([--disable-cms-encrypt], [disable cms encrypt support])],
	,
	[enable_cms_encrypt="yes"]
)

AC_ARG_ENABLE(
	[io-driver-file],
	[AS_HELP_STRING([--disable-io-driver-file], [disable io file driver support])],
	,
	[enable_io_driver_file="yes"]
)

AC_ARG_ENABLE(
	[certificate-driver-file],
	[AS_HELP_STRING([--disable-certificate-driver-file], [disable certificate file driver support])],
	,
	[enable_certificate_driver_file="yes"]
)

AC_ARG_ENABLE(
	[certificate-driver-pkcs11],
	[AS_HELP_STRING([--disable-certificate-driver-pkcs11], [disable certificate pkcs11 driver support])],
	,
	[enable_certificate_driver_pkcs11="yes"]
)

AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG
LT_INIT

if test "${enable_all_static}" = "yes"; then
	ifdef(
		[PKG_CHECK_MODULES_STATIC],
		[PKG_CHECK_MODULES_STATIC(
			[OPENSSL],
			[libcrypto >= 1.1.0],
			,
			[AC_MSG_ERROR([Cannot locate openssl])]
		)],
		[
			# Old pkg.m4 hack
			saved_PKG_CONFIG="${PKG_CONFIG}"
			PKG_CONFIG="${PKG_CONFIG} --static"
			PKG_CHECK_MODULES(
				[OPENSSL],
				[libcrypto >= 1.1.0],
				,
				[AC_MSG_ERROR([Cannot locate openssl])]
			)
			PKG_CONFIG="${saved_PKG_CONFIG}"
		]
	)
	# Fix segmentation error per pthread_setspecific is linked but pthread_mutex_lock is not
	if echo "${OPENSSL_LIBS}" | grep -q pthread; then
		LDFLAGS="${LDFLAGS} -Wl,-u,pthread_mutex_lock -Wl,-u,pthread_mutex_unlock"
	fi
else
	PKG_CHECK_MODULES(
		[OPENSSL],
		[libcrypto >= 1.1.0],
		,
		[AC_MSG_ERROR([Cannot locate openssl])]
	)
fi

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

AC_PROG_AWK
AC_ARG_VAR([PKCS11_TOOL], [path to pkcs11-tool utility])
AC_PATH_PROGS([PKCS11_TOOL], [pkcs11-tool])
AC_ARG_VAR([SOFTHSM2_UTIL], [path to softhsm2-util utility])
AC_PATH_PROGS([SOFTHSM2_UTIL], [softhsm2-util])
AC_ARG_VAR([VALGRIND], [path to valgrind utility])
AC_PATH_PROGS([VALGRIND], [valgrind])
AC_ARG_VAR([OPENSSL], [path to openssl utility])
AC_PATH_PROGS([OPENSSL], [openssl])
AC_ARG_VAR([EASYRSA], [path to easyrsa utility])
AC_PATH_PROGS([EASYRSA], [easyrsa],, [/usr/share/easy-rsa])

test "${enable_all_static}" = "yes" && \
	LDFLAGS="${LDFLAGS} -all-static"

test "${enable_tool}" = "yes" && AC_DEFINE([ENABLE_TOOL], [1], [Enable tool])
test "${enable_openssl_err_strings}" = "yes" && AC_DEFINE([ENABLE_OPENSSL_ERR_STRINGS], [1], [Enable openssl error strings])
test "${enable_cms_sign}" = "yes" && AC_DEFINE([ENABLE_CMS_SIGN], [1], [Enable cms sign])
test "${enable_cms_verify}" = "yes" && AC_DEFINE([ENABLE_CMS_VERIFY], [1], [Enable cms verify])
test "${enable_cms_decrypt}" = "yes" && AC_DEFINE([ENABLE_CMS_DECRYPT], [1], [Enable cms decrypt])
test "${enable_cms_encrypt}" = "yes" && AC_DEFINE([ENABLE_CMS_ENCRYPT], [1], [Enable cms encrypt])
test "${enable_io_driver_file}" = "yes" && AC_DEFINE([ENABLE_IO_DRIVER_FILE], [1], [Enable io file driver])
test "${enable_certificate_driver_file}" = "yes" && AC_DEFINE([ENABLE_CERTIFICATE_DRIVER_FILE], [1], [Enable cms certificate file driver])
if test "${enable_certificate_driver_pkcs11}" = "yes"; then
	AC_DEFINE([ENABLE_CERTIFICATE_DRIVER_PKCS11], [1], [Enable cms pkcs11 file driver])
	AC_CHECK_LIB([dl], [dlopen])
fi

if test "${enable_tool}" = "yes" -a "${enable_io_driver_file}" != "yes"; then
	AC_MSG_ERROR([IO file driver is required for tool])
fi
if test "${enable_all_static}" = "yes" -a "${enable_certificate_driver_pkcs11}" = "yes"; then
	AC_MSG_ERROR([PKCS11 uses dynamic library])
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
AM_CONDITIONAL([ENABLE_CMS_SIGN], [test "${enable_cms_sign}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_VERIFY], [test "${enable_cms_verify}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_DECRYPT], [test "${enable_cms_decrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_ENCRYPT], [test "${enable_cms_encrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_IO_DRIVER_FILE], [test "${enable_io_driver_file}" = "yes"])
AM_CONDITIONAL([ENABLE_CERTIFICATE_DRIVER_FILE], [test "${enable_certificate_driver_file}" = "yes"])
AM_CONDITIONAL([ENABLE_CERTIFICATE_DRIVER_PKCS11], [test "${enable_certificate_driver_pkcs11}" = "yes"])
AC_CONFIG_FILES([
	Makefile
	include/Makefile
	include/mycms/Makefile
	src/Makefile
	src/lib/Makefile
	src/lib/libmycms.pc
	src/tool/Makefile
	test/Makefile
	test/ca/Makefile
	test/ca/rootca.vars
	test/ca/subca.vars
	test/ca/vars
	test/tool/Makefile
	test/tool/encrypt/Makefile
	test/tool/sign/Makefile
])
AC_OUTPUT
