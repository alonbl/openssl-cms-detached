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
trap cleanup 0

doval() {
	if [ "${MYCMS_DO_VALGRIND}" = 1 ]; then
		${VALGRIND_CMD} -q --leak-check=full --leak-resolution=high --show-leak-kinds=all "$@"
	else
		"$@"
	fi
}

get_keyid() {
	local cert="$1"

	"${OPENSSL}" x509 -noout -in "$1" -inform DER -ext subjectKeyIdentifier |
		sed -e '1d' -e 's/ //g' -e 's/://g'
}

test_sanity() {
	local PREFIX="${MYTMP}/sanity"
	local CMS="${PREFIX}-cms"
	local BADDATA="${PREFIX}-baddata"
	local out
	local test1_keyid
	local test2_keyid

	cp "${DATA}" "${BADDATA}"
	echo 1 >> "${BADDATA}"

	test1_keyid="$(get_keyid gen/test1.crt)" || die "test1.keyid"

	echo "Signing by test1"
	doval "${MYCMS_TOOL}" sign \
		--cms-out="${CMS}" \
		--data-in="${DATA}" \
		--signer-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
		|| die "sanity.sign.test1"

	echo "List signers test1"
	out="$(doval "${MYCMS_TOOL}" verify-list \
		--cms-in="${CMS}" \
		)" || die "sanity.verify-list '${out}'"

	[ "$(echo "${out}" | wc -l)" = 1 ] || die "Incorrect number of keys '${out}'"
	echo "${out}" | grep -iq "^${test1_keyid}$" || die "Keyid mismatch expected '${test1_keyid}' actual '${out}'"

	echo "Verify signature"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS}" \
		--data-in="${DATA}" \
		--cert=gen/test1.crt \
		)" || die "sanity.verify.test1"

	[ "${out}" = "VERIFIED" ] || die "sanity.verify.result '${out}'"

	echo "Verify signature wrong signer"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS}" \
		--data-in="${DATA}" \
		--cert=gen/test2.crt \
		)" || die "sanity.verify.wrong"

	[ "${out}" = "VERIFIED" ] && die "sanity.verify.wrong.result '${out}'"

	echo "Verify signature with bad data"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS}" \
		--data-in="${BADDATA}" \
		--cert=gen/test1.crt \
		)" || die "sanity.verify.bad"

	[ "${out}" = "VERIFIED" ] && die "sanity.verify.bad.result '${out}'"

	return 0
}

test_two() {
	local PREFIX="${MYTMP}/sanity"
	local CMS="${PREFIX}-cms"
	local CMS2="${PREFIX}-cms2"
	local out
	local test1_keyid
	local test2_keyid

	test1_keyid="$(get_keyid gen/test1.crt)" || die "test1.keyid"
	test2_keyid="$(get_keyid gen/test2.crt)" || die "test2.keyid"

	echo "Signing by test1"
	doval "${MYCMS_TOOL}" sign \
		--cms-out="${CMS}" \
		--data-in="${DATA}" \
		--signer-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
		|| die "sanity.sign.test1"

	echo "Signing by test2"
	doval "${MYCMS_TOOL}" sign \
		--cms-in="${CMS}" \
		--cms-out="${CMS2}" \
		--signer-cert="file:cert=gen/test2.crt:key=gen/test2.key" \
		|| die "sanity.sign.test2"

	echo "List signers test2"
	out="$(doval "${MYCMS_TOOL}" verify-list \
		--cms-in="${CMS2}" \
		)" || die "sanity.verify-list.test2 '${out}'"

	[ "$(echo "${out}" | wc -l)" = 2 ] || die "Incorrect number of keys '${out}'"
	echo "${out}" | grep -iq "^${test1_keyid}$" || die "Keyid mismatch expected '${test1_keyid}' actual '${out}'"
	echo "${out}" | grep -iq "^${test2_keyid}$" || die "Keyid mismatch expected '${test2_keyid}' actual '${out}'"

	echo "Verify signature"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS2}" \
		--data-in="${DATA}" \
		--cert="gen/test1.crt" \
		--cert="gen/test2.crt" \
		)" || die "sanity.verify.${x}"

	[ "${out}" = "VERIFIED" ] || die "sanity.verify2.result '${out}'"

	echo "Verify signature single signer"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS2}" \
		--data-in="${DATA}" \
		--cert=gen/test1.crt \
		)" || die "sanity.verify.single"

	[ "${out}" = "VERIFIED" ] || die "sanity.verify.single.result '${out}'"

	echo "Verify signature wrong signer"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS2}" \
		--data-in="${DATA}" \
		--cert=gen/test3.crt \
		)" || die "sanity.verify.wrong"

	[ "${out}" = "VERIFIED" ] && die "sanity.verify.wrong.result '${out}'"

	return 0
}

test_multi_digest() {
	local PREFIX="${MYTMP}/sanity"
	local CMS="${PREFIX}-cms"
	local CMS2="${PREFIX}-cms2"
	local out
	local test1_keyid
	local test2_keyid

	test1_keyid="$(get_keyid gen/test1.crt)" || die "test1.keyid"
	test2_keyid="$(get_keyid gen/test2.crt)" || die "test2.keyid"

	echo "Signing by test1"
	doval "${MYCMS_TOOL}" sign \
		--cms-out="${CMS}" \
		--data-in="${DATA}" \
		--digest=sha256 \
		--digest=sha1 \
		--signer-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
		|| die "sanity.sign.test1"

	echo "Signing by test2"
	doval "${MYCMS_TOOL}" sign \
		--cms-in="${CMS}" \
		--cms-out="${CMS2}" \
		--digest=sha256 \
		--digest=sha1 \
		--signer-cert="file:cert=gen/test2.crt:key=gen/test2.key" \
		|| die "sanity.sign.test2"

	echo "List signers test2"
	out="$(doval "${MYCMS_TOOL}" verify-list \
		--cms-in="${CMS2}" \
		)" || die "sanity.verify-list.test2 '${out}'"

	[ "$(echo "${out}" | wc -l)" = 4 ] || die "Incorrect number of keys '${out}'"
	[ "$(echo "${out}" | grep -i "^${test1_keyid}$" | wc -l)" = 2 ] || die "Invalid number of signers test1 '${out}'"
	[ "$(echo "${out}" | grep -i "^${test2_keyid}$" | wc -l)" = 2 ] || die "Invalid number of signers test1 '${out}'"

	echo "Verify signature"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS2}" \
		--data-in="${DATA}" \
		--cert="gen/test1.crt" \
		--cert="gen/test2.crt" \
		)" || die "sanity.verify.${x}"

	[ "${out}" = "VERIFIED" ] || die "sanity.verify2.result '${out}'"

	return 0
}

[ -x "${MYCMS_TOOL}" ] || skip "no tool"
features="$("${MYCMS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "sign" || skip "sign feature is not available"
echo "${features}" | grep -q "verify" || skip "verify feature is not available"
echo "${features}" | grep -q "certificate-driver-file" || skip "certificate-driver-file feature is not available"

MYTMP="$(mktemp -d)"
DATA="${MYTMP}/data"
dd if=/dev/urandom bs=512 count=20 of="${DATA}" status=none || die "dd plain"

TESTS="test_sanity test_two test_multi_digest"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done
