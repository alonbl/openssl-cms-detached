#!/bin/sh

srcdir="${srcdir:-.}"
MYCMS_TOOL="${MYCMS_TOOL:-mycms-tool}"
SOFTHSM2_UTIL="${SOFTHSM2_UTIL:-softhsm2-util}"
PKCS11_TOOL="${PKCS11_TOOL:-pkcs11-tool}"
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
trap cleanup 0

doval() {
	if [ "${DO_VALGRIND}" = 1 ]; then
		${VALGRIND_CMD} -q --leak-check=full --leak-resolution=high --show-leak-kinds=all --suppressions="${srcdir}/test-pkcs11.valgrind.supp" --gen-suppressions=all "$@"
	else
		"$@"
	fi
}

prepare_token() {
	"${SOFTHSM2_UTIL}" --init-token --free --label token1 --so-pin sosecret --pin secret || die "init-token"
	for o in 1 2 3 4 5; do
		"${PKCS11_TOOL}" \
			--module "${SOFTHSM2_MODULE}" \
			--token-label token1 \
			--login \
			--pin secret \
			--private \
			--id ${o} \
			--label test${o} \
			--type privkey \
			--usage-decrypt \
			--write-object "gen/test${o}.key" \
			|| die "pkcs11-tool.key.${o}"
		"${PKCS11_TOOL}" \
			--module "${SOFTHSM2_MODULE}" \
			--token-label token1 \
			--login \
			--pin secret \
			--id ${o} \
			--label test${o} \
			--type cert \
			--write-object "gen/test${o}.crt" \
			|| die "pkcs11-tool.crt.${o}"
	done

	echo "Token:"
	"${SOFTHSM2_UTIL}" --show-slots
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
		--recip-cert="pkcs11:module=${SOFTHSM2_MODULE}:token-label=token1:cert-label=test1" \
		--recip-cert-pass="pass:secret" \
		--data-pt="${OUTPT}" \
		--data-ct="${CT}" \
		|| die "sanity.decrypt"

	cmp -s "${PT}" "${CT}" && die "sanity.cmp.ct"
	cmp -s "${PT}" "${OUTPT}" || die "sanity.cmp"

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
		--recip-cert="pkcs11:module=${SOFTHSM2_MODULE}:token-label=token1:cert-label=test1" \
		--recip-cert-pass="pass:secret" \
		--to="gen/test3.crt" \
		--to="gen/test4.crt" \
		|| die "add-recip.encrypt"

	local x
	for x in test1 test2 test3 test4; do
		echo "Decrypting by '${x}'"
		doval "${MYCMS_TOOL}" decrypt \
			--cms-in="${CMS2}" \
			--recip-cert="pkcs11:module=${SOFTHSM2_MODULE}:token-label=token1:cert-label=${x}" \
			--recip-cert-pass="pass:secret" \
			--data-pt="${OUTPT}-${x}" \
			--data-ct="${CT}" \
			|| die "add-recip.decrypt.${x}"
		cmp -s "${PT}" "${OUTPT}-${x}" || die "sanity.cmp"
	done

	return 0
}

[ -x "${MYCMS_TOOL}" ] || skip "no tool"
features="$("${MYCMS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "encrypt" || skip "encrypt feature is not available"
echo "${features}" | grep -q "decrypt" || skip "decrypt feature is not available"
echo "${features}" | grep -q "certificate-driver-pkcs11" || skip "certificate-driver-pkcs11 feature is not available"

"${SOFTHSM2_UTIL}" --version > /dev/null || skip "softhsm2-util not found"
"${PKCS11_TOOL}" --version 2>&1 | grep -q "Usage:" || skip "pkcs11-tool not found"

[ -z "${SOFTHSM2_MODULE}" ] && die "Cannot find softhsm module"

MYTMP="$(mktemp -d)"
PT="${MYTMP}/pt"
dd if=/dev/urandom bs=512 count=20 of="${PT}" status=none || die "dd plain"

tokendir="${MYTMP}/token"
mkdir -p "${tokendir}"
sed "s#@TOKENDIR@#${tokendir}#" "${srcdir}/softhsm2.conf.in" > "${MYTMP}/softhsm2.conf"
export SOFTHSM2_CONF="${MYTMP}/softhsm2.conf"

prepare_token

TESTS="test_sanity test_add_recepients"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done
