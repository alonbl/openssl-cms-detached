#!/bin/sh

NULL=

eval "$(
	sed -n \
		-e '/^#@AM_DISTCHECK_CONFIGURE_FLAGS-BEGIN$/,/^#@AM_DISTCHECK_CONFIGURE_FLAGS-END$/p' \
		Makefile.am |
	sed \
		-e 's/ =/="/' \
		-e 's/$(NULL)/"/'
)"

exec ${buildir:-.}/configure  \
	--enable-strict \
	--enable-pedantic \
	${AM_DISTCHECK_CONFIGURE_FLAGS} \
	${NULL}
