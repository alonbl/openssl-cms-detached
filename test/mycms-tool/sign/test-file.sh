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
	echo "${out}" | grep -iq "^${test1_keyid} SHA3-256$" || die "Keyid mismatch expected '${test1_keyid}' actual '${out}'"

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
	local PREFIX="${MYTMP}/two"
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
	echo "${out}" | grep -iq "^${test1_keyid} SHA3-256$" || die "Keyid mismatch expected '${test1_keyid}' actual '${out}'"
	echo "${out}" | grep -iq "^${test2_keyid} SHA3-256$" || die "Keyid mismatch expected '${test2_keyid}' actual '${out}'"

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
	local CMS3="${PREFIX}-cms3"
	local out
	local expected
	local digest
	local test1_keyid
	local test2_keyid
	local test3_keyid

	test1_keyid="$(get_keyid gen/test1.crt)" || die "test1.keyid"
	test2_keyid="$(get_keyid gen/test2.crt)" || die "test2.keyid"
	test3_keyid="$(get_keyid gen/test3.crt)" || die "test3.keyid"

	echo "Signing by test1"
	doval "${MYCMS_TOOL}" sign \
		--cms-out="${CMS}" \
		--data-in="${DATA}" \
		--digest=sha3-256 \
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

	echo "Signing by test3"
	doval "${MYCMS_TOOL}" sign \
		--cms-in="${CMS2}" \
		--cms-out="${CMS3}" \
		--digest=sha3-256 \
		--signer-cert="file:cert=gen/test3.crt:key=gen/test3.key" \
		|| die "sanity.sign.test3"

	echo "List signers test2"
	out="$(doval "${MYCMS_TOOL}" verify-list \
		--cms-in="${CMS3}" \
		)" || die "sanity.verify-list.test2 '${out}'"

	[ "$(echo "${out}" | wc -l)" = 6 ] || die "Incorrect number of keys '${out}'"
	expected="\
${test1_keyid} SHA3-256
${test1_keyid} SHA256
${test2_keyid} SHA256
${test1_keyid} SHA1
${test2_keyid} SHA1
${test3_keyid} SHA3-256"
	[ "$(echo "${out}" | sort | tr [a-z] [A-Z])" = "$(echo "${expected}" | sort | tr [a-z] [A-Z])" ] || die "Incorrect output expected='${expected}' actual='${out}'"

	echo "Verify signature"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS3}" \
		--data-in="${DATA}" \
		--cert="gen/test1.crt" \
		--cert="gen/test2.crt" \
		)" || die "sanity.verify.sanity"

	[ "${out}" = "VERIFIED" ] || die "sanity.verify2.result '${out}'"

	for digest in sha1 sha256; do
		for cert in test1 test2; do
			echo "Verify signature with specific digest [${digest}/${cert}]"
			out="$(doval "${MYCMS_TOOL}" verify \
				--cms-in="${CMS3}" \
				--data-in="${DATA}" \
				--digest="${digest}" \
				--cert="gen/${cert}.crt" \
				)" || die "sanity.verify.${digest}.${cert}"

			[ "${out}" = "VERIFIED" ] || die "sanity.verify3.result '${out}'"
		done
	done

	digest=sha3-256
	for cert in test1 test3; do
		echo "Verify signature with specific digest [${digest}/${cert}]"
		out="$(doval "${MYCMS_TOOL}" verify \
			--cms-in="${CMS3}" \
			--data-in="${DATA}" \
			--digest="${digest}" \
			--cert="gen/${cert}.crt" \
			)" || die "sanity.verify.${digest}.${cert}"

		[ "${out}" = "VERIFIED" ] || die "sanity.verify3.result '${out}'"
	done

	for digest in sha1 sha256; do
		echo "Should fail verify with unused digest"
		out="$(doval "${MYCMS_TOOL}" verify \
			--cms-in="${CMS3}" \
			--data-in="${DATA}" \
			--digest="${digest}" \
			--cert="gen/test3.crt" \
			)" || die "sanity.verify.invalid.digest.${digest}"

		[ "${out}" = "VERIFIED" ] && die "sanity.verify.invalid.digest.digest.${digest} '${out}'"
	done

	return 0
}

test_keyopt() {
	local PREFIX="${MYTMP}/keyopt"
	local CMS="${PREFIX}-cms"
	local CMS2="${PREFIX}-cms2"
	local out
	local test1_keyid
	local test2_keyid

	test1_keyid="$(get_keyid gen/test1.crt)" || die "test1.keyid"
	test2_keyid="$(get_keyid gen/test2.crt)" || die "test2.keyid"

	while IFS=":" read padding padding_str; do
		echo "Using ${padding}"

		echo "Signing by test1"
		doval "${MYCMS_TOOL}" sign \
			--cms-out="${CMS}" \
			--data-in="${DATA}" \
			--signer-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
			--keyopt="rsa_padding_mode=${padding}" \
			|| die "keyopt.sign.test1"

		[ 1 -eq $("${OPENSSL}" asn1parse -in "${CMS}" -inform DER | grep "${padding_str}" | wc -l) ] || die "Exected '${padding_str}' for '${padding}'"

		echo "Verify signature"
		out="$(doval "${MYCMS_TOOL}" verify \
			--cms-in="${CMS}" \
			--data-in="${DATA}" \
			--cert="gen/test1.crt" \
			)" || die "keyopt.verify.${x}"

		[ "${out}" = "VERIFIED" ] || die "keyopt.verify2.result '${out}'"

	done << __EOF__
pkcs1:rsaEncryption
pss:rsassaPss
__EOF__


	# second signer does not add signature
	# https://github.com/openssl/openssl/issues/14257
	echo "Checking if openssl bug resolved"

(
	while IFS=":" read padding padding_str; do
		echo "Using ${padding}"

		echo "Signing by test1"
		doval "${MYCMS_TOOL}" sign \
			--cms-out="${CMS}" \
			--data-in="${DATA}" \
			--signer-cert="file:cert=gen/test1.crt:key=gen/test1.key" \
			--keyopt="rsa_padding_mode=${padding}" \
			|| die "keyopt.sign.test1"

		echo "Signing by test2"
		doval "${MYCMS_TOOL}" sign \
			--cms-in="${CMS}" \
			--cms-out="${CMS2}" \
			--signer-cert="file:cert=gen/test2.crt:key=gen/test2.key" \
			--keyopt="rsa_padding_mode=${padding}" \
			|| die "sanity.sign.test2"

		[ 2 -eq $("${OPENSSL}" asn1parse -in "${CMS2}" -inform DER | grep "${padding_str}" | wc -l) ] || die "Exected '${padding_str}' for '${padding}'"

		echo "Verify signature"
		out="$(doval "${MYCMS_TOOL}" verify \
			--cms-in="${CMS2}" \
			--data-in="${DATA}" \
			--cert="gen/test1.crt" \
			--cert="gen/test2.crt" \
			)" || die "keyopt.verify2.${x}"

		[ "${out}" = "VERIFIED" ] || die "keyopt.verify2.result '${out}'"

	done << __EOF__
pkcs1:rsaEncryption
pss:rsassaPss
__EOF__

) && echo "OPENSSL KEYOPT BUG RESOLVED!" || echo "OPENSSL KEYOPT BUG exists"

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

TESTS="test_sanity test_two test_multi_digest test_keyopt"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done
