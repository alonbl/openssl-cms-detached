#!/bin/sh

NULL=

srcdir="$(dirname "$0")"

eval "$(
	sed -n \
		-e '/^#@AM_DISTCHECK_CONFIGURE_FLAGS-BEGIN$/,/^#@AM_DISTCHECK_CONFIGURE_FLAGS-END$/p' \
		"${srcdir}/Makefile.am" |
	sed \
		-e 's/ =/="/' \
		-e 's/$(NULL)/"/'
)"

exec "${srcdir}/configure"  \
	--enable-strict \
	--enable-pedantic \
	${AM_DISTCHECK_CONFIGURE_FLAGS} \
	"${@}" \
	${NULL}
