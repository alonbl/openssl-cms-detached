#!/bin/sh

srcdir="${srcdir:-.}"
MYCMS_TOOL="${MYCMS_TOOL:-mycms-tool}"
VALGRIND="${VALGRIND:-valgrind}"
LIBTOOL="${LIBTOOL:-libtool}"

VALGRIND_CMD="${VALGRIND_CMD:-"${LIBTOOL}" --mode=execute ${VALGRIND}}"

die() {
	local m="$1"
	echo "FATAL: ${m}" >&2
	exit 1
}

skip() {
	local m="$1"
	echo "SKIP: ${m}" >&2
	exit 77
}

MYTMP=
cleanup() {
	rm -fr "${MYTMP}"
}

doval() {
	if [ "${DO_VALGRIND}" = 1 ]; then
		${VALGRIND_CMD} -q --leak-check=full --leak-resolution=high --show-leak-kinds=all "$@"
	else
		"$@"
	fi
}

test_sanity() {
	local PREFIX="${MYTMP}/sanity"
	local CMS="${PREFIX}-cms"
	local CT="${PREFIX}-ct"
	local OUTPT="${PREFIX}-pt"

	echo "Encrypting to test1"
	doval "${MYCMS_TOOL}" encrypt \
		--cms-out="${CMS}" \
		--data-pt="${PT}" \
		--data-ct="${CT}" \
		--to="gen/test1.crt" \
		|| die "sanity.encrypt"
	echo "Decrypting by test1"
	doval "${MYCMS_TOOL}" decrypt \
		--cms-in="${CMS}" \
		--recip-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
		--data-pt="${OUTPT}" \
		--data-ct="${CT}" \
		|| die "sanity.decrypt"
	cmp -s "${PT}" "${CT}" && die "sanity.cmp.ct"
	cmp -s "${PT}" "${OUTPT}" || die "sanity.cmp"

	echo "Decrypting by test2 (should fail)"
	doval "${MYCMS_TOOL}" decrypt \
		--cms-in="${CMS}" \
		--recip-cert="file:cert=gen/test2.crt:key=gen/test2.key" \
		--data-pt="${OUTPT}" \
		--data-ct="${CT}" \
		&& die "sanity.decrypt succeeded with other"

	return 0
}

test_multiple_recepients() {
	local PREFIX="${MYTMP}/mrecip"
	local CMS="${PREFIX}-cms"
	local CT="${PREFIX}-ct1"
	local OUTPT1="${PREFIX}-pt1"
	local OUTPT2="${PREFIX}-pt2"

	echo "Encrypting to test1 and test2"
	doval "${MYCMS_TOOL}" encrypt \
		--cms-out="${CMS}" \
		--data-pt="${PT}" \
		--data-ct="${CT}" \
		--to="gen/test1.crt" \
		--to="gen/test2.crt" \
		|| die "multi-recip.encrypt"
	echo "Decrypting by test1"
	doval "${MYCMS_TOOL}" decrypt \
		--cms-in="${CMS}" \
		--recip-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
		--data-pt="${OUTPT1}" \
		--data-ct="${CT}" \
		|| die "multi-recip.decrypt"
	cmp -s "${PT}" "${OUTPT1}" || die "sanity.cmp"
	echo "Decrypting by test2"
	doval "${MYCMS_TOOL}" decrypt \
		--cms-in="${CMS}" \
		--recip-cert="file:cert=gen/test2.crt:key=gen/test2.key" \
		--data-pt="${OUTPT2}" \
		--data-ct="${CT}" \
		|| die "multi-recip.decrypt"
	cmp -s "${PT}" "${OUTPT2}" || die "sanity.cmp"

	return 0
}

test_add_recepients() {
	local PREFIX="${MYTMP}/addrecip"
	local CMS1="${PREFIX}-cms1"
	local CMS2="${PREFIX}-cms2"
	local CT="${PREFIX}-ct1"
	local OUTPT="${PREFIX}-pt"

	echo "Encrypting to test1 and test2"
	doval "${MYCMS_TOOL}" encrypt \
		--cms-out="${CMS1}" \
		--data-pt="${PT}" \
		--data-ct="${CT}" \
		--to="gen/test1.crt" \
		--to="gen/test2.crt" \
		|| die "add-recip.encrypt"

	echo "Ading to test3 and test4 using test1"
	doval "${MYCMS_TOOL}" encrypt-add \
		--cms-in="${CMS1}" \
		--cms-out="${CMS2}" \
		--recip-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
		--to="gen/test3.crt" \
		--to="gen/test4.crt" \
		|| die "add-recip.encrypt"

	local x
	for x in test1 test2 test3 test4; do
		echo "Decrypting by '${x}'"
		doval "${MYCMS_TOOL}" decrypt \
			--cms-in="${CMS2}" \
			--recip-cert="file:cert=gen/${x}.crt:key=gen/${x}.key" \
			--data-pt="${OUTPT}-${x}" \
			--data-ct="${CT}" \
			|| die "add-recip.decrypt.${x}"
		cmp -s "${PT}" "${OUTPT}-${x}" || die "sanity.cmp"
	done

	echo "Decrypting by test5 (should fail)"
	doval "${MYCMS_TOOL}" decrypt \
		--cms-in="${CMS2}" \
		--recip-cert="file:cert=gen/test5.crt:key=gen/test5.key" \
		--data-pt="${OUTPT}-test5" \
		--data-ct="${CT}" \
		&& die "sanity.decrypt should not succeed"

	return 0
}

[ -x "${MYCMS_TOOL}" ] || skip "no tool"
features="$("${MYCMS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "encrypt" || skip "encrypt feature is not available"
echo "${features}" | grep -q "decrypt" || skip "decrypt feature is not available"
echo "${features}" | grep -q "certificate-driver-file" || skip "certificate-driver-file feature is not available"

MYTMP="$(mktemp -d)"
PT="${MYTMP}/pt"
dd if=/dev/urandom bs=512 count=20 of="${PT}" status=none || die "dd plain"

TESTS="test_sanity test_multiple_recepients test_add_recepients"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done