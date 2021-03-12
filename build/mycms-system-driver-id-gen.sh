#!/bin/sh

group="$1"; shift

	cat << __EOF__
#ifndef __MYCMS_SYSTEM_PROVIDER_ID_${group}_H
#define __MYCMS_SYSTEM_PROVIDER_ID_${group}_H
__EOF__

while [ -n "$1" ]; do
	sum="$(printf "%s" "$1" | sha1sum)"
	sum="$(expr substr "${sum}" 1 8)"
	cat << __EOF__
#define MYCMS_SYSTEM_DRIVER_ID_${group}_$1 0x${sum}
__EOF__
	shift
done

	cat << __EOF__
#endif
__EOF__
