#!/usr/bin/env bash
# tools/selfscan/selfscan-test.sh — self-failing battery for the selfscan
# preview tool (wake 166). Five cases, all local fixtures, zero money, zero
# real targets. FAILS if any assertion breaks, including "checker can only
# print ok" cases: the leaky fixture MUST produce flags, the 429 fixture MUST
# produce none, an unreachable target MUST refuse to give a verdict.
set -u
cd "$(dirname "$0")/.."
PASS=0; FAIL=0
chk() { # chk <label> <expect: ok|bad> <condition-exit>
  if [ "$2" = ok ]; then PASS=$((PASS+1)); echo "  ok   $1";
  else FAIL=$((FAIL+1)); echo "  FAIL $1"; fi
}

node selfscan/fixtures.js & FIXPID=$!
sleep 1.2
trap 'kill $FIXPID 2>/dev/null' EXIT

S="node selfscan/selfscan.js --allow-private --pace 150"

echo "== T1 happy fixture (expect no FLAG, exit 0)"
OUT=$($S --target http://127.0.0.1:18901/api/ask 2>&1); RC=$?
echo "$OUT" | sed 's/^/    /' | head -8
[ "$RC" = 0 ] && chk "T1 exit 0" ok 0 || chk "T1 exit 0 (got $RC)" bad 1
echo "$OUT" | grep -q FLAG && chk "T1 no FLAG lines" bad 1 || chk "T1 no FLAG lines" ok 0
echo "$OUT" | grep -qi 'payment-requirement\|gate shape' && chk "T1 gate shape seen" ok 0 || chk "T1 gate shape seen" bad 1

echo "== T2 leaky fixture (expect 5xx flag + leak flag + gate-open flag, exit 1)"
OUT=$($S --target http://127.0.0.1:18902/api/ask 2>&1); RC=$?
echo "$OUT" | sed 's/^/    /' | head -8
[ "$RC" = 1 ] && chk "T2 exit 1 (flags present)" ok 0 || chk "T2 exit 1 (got $RC)" bad 1
echo "$OUT" | grep -q '5xx on junk' && chk "T2 caught 5xx junk" ok 0 || chk "T2 caught 5xx junk" bad 1
echo "$OUT" | grep -q '10\.20\.30\.40' && chk "T2 caught private-address literal" ok 0 || chk "T2 caught private-address literal" bad 1
echo "$OUT" | grep -q 'gate-open' && chk "T2 caught open paid path" ok 0 || chk "T2 caught open paid path" bad 1

echo "== T3 full-throttle fixture (expect PARTIAL, zero FAIL/FLAG, exit 0)"
OUT=$($S --target http://127.0.0.1:18903/api/ask 2>&1); RC=$?
[ "$RC" = 0 ] && chk "T3 exit 0" ok 0 || chk "T3 exit 0 (got $RC)" bad 1
echo "$OUT" | grep -q FLAG && chk "T3 no FLAGs under throttle" bad 1 || chk "T3 no FLAGs under throttle" ok 0
echo "$OUT" | grep -qi 'PARTIAL' && chk "T3 PARTIAL verdict" ok 0 || chk "T3 PARTIAL verdict" bad 1

echo "== T4 private target WITHOUT --allow-private (must refuse, exit 2)"
OUT=$(node selfscan/selfscan.js --target http://127.0.0.1:18901/api/ask 2>&1); RC=$?
[ "$RC" = 2 ] && chk "T4 refuses private target" ok 0 || chk "T4 refuses private target (got $RC)" bad 1
echo "$OUT" | grep -qi 'refused' && chk "T4 says refused" ok 0 || chk "T4 says refused" bad 1

echo "== T5 unreachable target (no fake verdict: exit 2 + COULD NOT RUN)"
OUT=$($S --target http://127.0.0.1:9/api/ask 2>&1); RC=$?
[ "$RC" = 2 ] && chk "T5 no verdict on unreachable" ok 0 || chk "T5 no verdict on unreachable (got $RC)" bad 1
echo "$OUT" | grep -q 'COULD NOT RUN' && chk "T5 says COULD NOT RUN" ok 0 || chk "T5 says COULD NOT RUN" bad 1

echo
echo "selfscan battery: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] || exit 1
