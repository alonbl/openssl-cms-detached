AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [0])
define([PACKAGE_VERSION_FIX], [0])
define([PACKAGE_VERSION_REVISION], [0])
define([PACKAGE_SUFFIX], [_master])

AC_INIT([mycms], [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([include/mycms/mycms.h])
AM_INIT_AUTOMAKE

MYCMS_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
MYCMS_VERSION_MINOR="PACKAGE_VERSION_MINOR"
MYCMS_VERSION_FIX="PACKAGE_VERSION_FIX"
MYCMS_VERSION_REVISION="PACKAGE_VERSION_REVISION"

AC_SUBST([MYCMS_VERSION_MAJOR])
AC_SUBST([MYCMS_VERSION_MINOR])
AC_SUBST([MYCMS_VERSION_FIX])
AC_SUBST([MYCMS_VERSION_REVISION])

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
	[system-driver-default],
	[AS_HELP_STRING([--disable-system-driver-default], [disable default system driver])],
	,
	[enable_system_driver_default="yes"]
)

AC_ARG_ENABLE(
	[tests],
	[AS_HELP_STRING([--enable-tests], [enable tests])],
	,
	[enable_tests="no"]
)

AC_ARG_ENABLE(
	[tool],
	[AS_HELP_STRING([--enable-tool], [enable tool])],
	,
	[enable_tool="no"]
)

AC_ARG_ENABLE(
	[openssl-err-strings],
	[AS_HELP_STRING([--enable-openssl-err-strings], [enable openssl error strings])],
	,
	[enable_openssl_err_strings="no"]
)

AC_ARG_ENABLE(
	[pinentry],
	[AS_HELP_STRING([--enable-pinentry], [enable pinentry support])],
	,
	[enable_pinentry="no"]
)

AC_ARG_ENABLE(
	[cms-sign],
	[AS_HELP_STRING([--enable-cms-sign], [enable cms sign support])],
	,
	[enable_cms_sign="no"]
)

AC_ARG_ENABLE(
	[cms-verify],
	[AS_HELP_STRING([--enable-cms-verify], [enable cms verify support])],
	,
	[enable_cms_verify="no"]
)

AC_ARG_ENABLE(
	[cms-decrypt],
	[AS_HELP_STRING([--enable-cms-decrypt], [enable cms decrypt support])],
	,
	[enable_cms_decrypt="no"]
)

AC_ARG_ENABLE(
	[cms-encrypt],
	[AS_HELP_STRING([--enable-cms-encrypt], [enable cms encrypt support])],
	,
	[enable_cms_encrypt="no"]
)

AC_ARG_ENABLE(
	[io-driver-file],
	[AS_HELP_STRING([--enable-io-driver-file], [enable io file driver support])],
	,
	[enable_io_driver_file="no"]
)

AC_ARG_ENABLE(
	[certificate-driver-file],
	[AS_HELP_STRING([--enable-certificate-driver-file], [enable certificate file driver support])],
	,
	[enable_certificate_driver_file="no"]
)

AC_ARG_ENABLE(
	[certificate-driver-pkcs11],
	[AS_HELP_STRING([--enable-certificate-driver-pkcs11], [enable certificate PKCS@%:@11 driver support])],
	,
	[enable_certificate_driver_pkcs11="no"]
)

AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG
LT_INIT([win32-dll])
LT_LANG([Windows Resource])

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

AC_CHECK_LIB([dl], [dlopen], [LIBDL_LIBS="-ldl"])

AC_CHECK_HEADERS([ \
	dnfcn.h \
])

AC_CHECK_FUNCS([ \
	explicit_bzero \
])

case "${host}" in
	*-mingw*)
		BUILD_WINDOWS=yes
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		AC_DEFINE([BUILD_WINDOWS], [1], [Build windows])
		AC_DEFINE([HAVE_SECUREZEROMEMORY], [1], [Have SecureZeroMemory])
		;;
esac

AC_PROG_AWK
AC_ARG_VAR([PKCS11_TOOL], [path to pkcs11-tool utility])
AC_PATH_PROGS([PKCS11_TOOL], [pkcs11-tool])
AC_ARG_VAR([VALGRIND], [path to valgrind utility])
AC_PATH_PROGS([VALGRIND], [valgrind])
AC_ARG_VAR([OPENSSL], [path to openssl utility])
AC_PATH_PROGS([OPENSSL], [openssl])
AC_ARG_VAR([EASYRSA], [path to easyrsa utility])
AC_PATH_PROGS([EASYRSA], [easyrsa],, [/usr/share/easy-rsa])
AC_ARG_VAR([SOFTHSM2_UTIL], [path to softhsm2-util utility])
AC_PATH_PROGS([SOFTHSM2_UTIL], [softhsm2-util])
AC_ARG_VAR([SOFTHSM2_MODULE], [path to SoftHSM2 module])

AC_MSG_CHECKING([path to SoftHSM2 module])
if test -z "${SOFTHSM2_MODULE}"; then
	for x in /usr/lib*/softhsm/libsofthsm2.so /usr/lib*/*/softhsm/libsofthsm2.so; do
		if test -r "${x}"; then
			SOFTHSM2_MODULE="${x}"
			break
		fi
	done
fi
AC_MSG_RESULT([${SOFTHSM2_MODULE}])

test "${enable_all_static}" = "yes" && \
	LDFLAGS="${LDFLAGS} -all-static"

test "${enable_system_driver_default}" = "yes" && AC_DEFINE([ENABLE_SYSTEM_DRIVER_DEFAULT], [1], [Enable default system driver])
test "${enable_tool}" = "yes" && AC_DEFINE([ENABLE_TOOL], [1], [Enable tool])
test "${enable_openssl_err_strings}" = "yes" && AC_DEFINE([ENABLE_OPENSSL_ERR_STRINGS], [1], [Enable openssl error strings])
test "${enable_pinentry}" = "yes" && AC_DEFINE([ENABLE_PINENTRY], [1], [Enable pinentry])
test "${enable_cms_sign}" = "yes" && AC_DEFINE([ENABLE_CMS_SIGN], [1], [Enable cms sign])
test "${enable_cms_verify}" = "yes" && AC_DEFINE([ENABLE_CMS_VERIFY], [1], [Enable cms verify])
test "${enable_cms_decrypt}" = "yes" && AC_DEFINE([ENABLE_CMS_DECRYPT], [1], [Enable cms decrypt])
test "${enable_cms_encrypt}" = "yes" && AC_DEFINE([ENABLE_CMS_ENCRYPT], [1], [Enable cms encrypt])
test "${enable_io_driver_file}" = "yes" && AC_DEFINE([ENABLE_IO_DRIVER_FILE], [1], [Enable io file driver])
test "${enable_certificate_driver_file}" = "yes" && AC_DEFINE([ENABLE_CERTIFICATE_DRIVER_FILE], [1], [Enable cms certificate file driver])
if test "${enable_certificate_driver_pkcs11}" = "yes"; then
	AC_DEFINE([ENABLE_CERTIFICATE_DRIVER_PKCS11], [1], [Enable cms pkcs11 file driver])
	LIBS="${LIBS} ${LIBDL_LIBS}"
fi

if test "${enable_tests}" = "yes"; then
	test -z "${OPENSSL}" && \
		AC_MSG_ERROR([openssl is required for test])
	test -z "${EASYRSA}" && \
		AC_MSG_ERROR([easyrsa is required for test])
	test -z "${AWK}" && \
		AC_MSG_ERROR([awk is required for easyrsa])
	if test "${enable_certificate_driver_pkcs11}" = "yes"; then
		test -z "${SOFTHSM2_UTIL}" &&
			AC_MSG_ERROR([softhsm2 is required for PKCS@%:@11 tests])
		test -z "${SOFTHSM2_MODULE}" &&
			AC_MSG_ERROR([softhsm2 module is required for PKCS@%:@11 tests])
		test -z "${PKCS11_TOOL}" &&
			AC_MSG_ERROR([pkcs11-tool (opensc) is required for PKCS@%:@11 tests])
	fi
fi
test "${enable_tool}" = "yes" -a "${enable_io_driver_file}" != "yes" && \
	AC_MSG_ERROR([IO file driver is required for tool])
test "${enable_all_static}" = "yes" -a "${enable_certificate_driver_pkcs11}" = "yes" && \
	AC_MSG_ERROR([PKCS11 uses dynamic library])

pkgconfigdir="\$(libdir)/pkgconfig"
mycmsincludedir="\$(includedir)/mycms"
AC_SUBST([pkgconfigdir])
AC_SUBST([mycmsincludedir])
AC_SUBST([LIBMYCMS_LT_CURRENT])
AC_SUBST([LIBMYCMS_LT_REVISION])
AC_SUBST([LIBMYCMS_LT_AGE])
AC_SUBST([LIBMYCMS_LT_OLDEST])
AM_CONDITIONAL([CROSS_COMPILING], [test "${cross_compiling}" = "yes"])
AM_CONDITIONAL([BUILD_WINDOWS], [test "${BUILD_WINDOWS}" = "yes"])
AM_CONDITIONAL([ENABLE_TESTS], [test "${enable_tests}" = "yes"])
AM_CONDITIONAL([ENABLE_TOOL], [test "${enable_tool}" = "yes"])
AM_CONDITIONAL([ENABLE_PINENTRY], [test "${enable_pinentry}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_SIGN], [test "${enable_cms_sign}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_VERIFY], [test "${enable_cms_verify}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_DECRYPT], [test "${enable_cms_decrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_CMS_ENCRYPT], [test "${enable_cms_encrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_IO_DRIVER_FILE], [test "${enable_io_driver_file}" = "yes"])
AM_CONDITIONAL([ENABLE_CERTIFICATE_DRIVER_FILE], [test "${enable_certificate_driver_file}" = "yes"])
AM_CONDITIONAL([ENABLE_CERTIFICATE_DRIVER_PKCS11], [test "${enable_certificate_driver_pkcs11}" = "yes"])
AC_CONFIG_FILES([
	Makefile
	build/Makefile
	include/Makefile
	include/mycms/Makefile
	src/Makefile
	src/lib/Makefile
	src/lib/libmycms.pc
	src/lib/versioninfo.rc
	src/tool/Makefile
	src/tool/versioninfo.rc
	test/Makefile
	test/ca/Makefile
	test/ca/rootca.vars
	test/ca/subca.vars
	test/ca/vars
	test/tool/Makefile
	test/tool/encrypt/Makefile
	test/tool/sign/Makefile
	test/tool/windows/Makefile
])
AC_OUTPUT
