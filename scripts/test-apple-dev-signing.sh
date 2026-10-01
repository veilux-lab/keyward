#!/bin/bash
# Does a rebuilt daemon, signed with the same identity, read an item the previous
# build stored without a dialog? See doc/handoff-apple-development-signing.md.
#
# Usage: scripts/test-apple-dev-signing.sh "Apple Development: you@example.com (TEAMID)"
set -u

IDENTITY=${1:?usage: $0 "<codesigning identity from: security find-identity -v -p codesigning>"}
cd "$(dirname "$0")/.." || exit 1

T=$(mktemp -d /tmp/kwsig.XXXX) && chmod 700 "$T" || exit 1
export KEYWARD_SOCKET="$T/d.sock" KEYWARD_SERVICE=keyward-signing-test
ITEM=signing-probe
VALUE="not-a-real-secret-$RANDOM$RANDOM"
pid=

now() { perl -MTime::HiRes=time -e 'printf "%.2f", time'; }

startd() {
	rm -f "$KEYWARD_SOCKET"
	"$T/$1" daemon >>"$T/daemon.log" 2>&1 &
	pid=$!
	for _ in $(seq 50); do [ -S "$KEYWARD_SOCKET" ] && return 0; sleep 0.1; done
	echo "daemon $1 did not start; log:"; cat "$T/daemon.log"; return 1
}

# A daemon blocked on a dialog ignores SIGINT until the dialog is answered.
stopd() {
	[ -n "$pid" ] || return 0
	kill -INT "$pid" 2>/dev/null
	for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
	kill -9 "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	pid=
}

# Deleting needs no authorisation, so cleanup never puts up a dialog.
cleanup() {
	stopd
	/usr/bin/security delete-generic-password -s "$KEYWARD_SERVICE" -a "$ITEM" >/dev/null 2>&1
	rm -rf "$T"
}
trap cleanup EXIT

# The child compares the value itself, so it is never printed.
probe() {
	startd "$1" || return 1
	local s e r
	s=$(now)
	# shellcheck disable=SC2016 # expanded by the child, after resolution
	if KW_PROBE="cap://$ITEM" "$T/kw" run -- sh -c '[ "$KW_PROBE" = "$1" ]' _ "$VALUE" 2>>"$T/client.log"; then
		r=READ
	else
		r=BLOCKED
	fi
	e=$(now)
	stopd
	printf '%-14s %-8s %ss\n' "$1" "$r" "$(perl -e "printf '%.2f', $e - $s")"
}

echo "== environment"
echo "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
go version

echo "== build"
for b in kwd-a kwd-b kwd-unsigned kw; do
	go build -o "$T/$b" -ldflags "-X github.com/nwokolo24/keyward/internal/cli.Version=$b" ./cmd/keyward || exit 1
done

echo "== sign (a codesign dialog here is for your signing key: Allow)"
for b in kwd-a kwd-b; do
	codesign --force --sign "$IDENTITY" --identifier com.nwokolo24.keyward "$T/$b" || exit 1
done
cdhash() { codesign -dv --verbose=4 "$T/$1" 2>&1 | sed -n 's/^CDHash=//p' | head -1; }
for b in kwd-a kwd-b kwd-unsigned; do
	team=$(codesign -dv --verbose=4 "$T/$b" 2>&1 | sed -n 's/^TeamIdentifier=//p')
	printf '%-14s cdhash=%s team=%s\n' "$b" "$(cdhash "$b")" "$team"
done
echo "requirement:  $(codesign -dr - "$T/kwd-b" 2>/dev/null | sed -n 's/^#* *designated => //p')"
a=$(cdhash kwd-a)
if [ -z "$a" ] || [ "$a" = "$(cdhash kwd-b)" ]; then
	echo "kwd-a and kwd-b are not distinct builds, so the test would prove nothing"; exit 1
fi

echo "== store one dummy item with kwd-a"
/usr/bin/security delete-generic-password -s "$KEYWARD_SERVICE" -a "$ITEM" >/dev/null 2>&1
startd kwd-a || exit 1
printf '%s' "$VALUE" | "$T/kw" add "$ITEM" || exit 1
stopd

echo "== read (any keyward dialog from here on: Deny)"
probe kwd-a
probe kwd-b
probe kwd-unsigned

echo "== client errors"
cat "$T/client.log" 2>/dev/null
