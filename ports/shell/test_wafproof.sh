#!/usr/bin/env bash
# Minimal test harness for the shell port. No external test framework.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WP="$HERE/wafproof.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fails=0
check() { # description expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1 (expected '$2', got '$3')"
    fails=$((fails+1))
  fi
}

# Build a ruleset and a labeled corpus (tab-separated).
printf 'xss\t<script\n' >  "$TMP/rules.tsv"
printf 'sqli\tUNION[[:space:]]+SELECT\n' >> "$TMP/rules.tsv"
printf 'pt\t\\.\\./\n' >> "$TMP/rules.tsv"

{
  printf 'malicious\txss\t<script>alert(1)</script>\n'
  printf 'malicious\tsqli\t1 UNION SELECT a,b\n'
  printf 'malicious\tpt\t../../etc/passwd\n'
  printf 'benign\txss\tI scripted a film\n'
  printf 'benign\tsqli\tselect a union rep\n'
} > "$TMP/corpus.tsv"

out="$(bash "$WP" "$TMP/rules.tsv" "$TMP/corpus.tsv")"
get() { echo "$out" | grep "^$1=" | cut -d= -f2; }

check "TP counts all 3 malicious" 3 "$(get TP)"
check "FN is zero"                0 "$(get FN)"
check "TN leaves benign alone"    2 "$(get TN)"
check "FP is zero (well-tuned)"   0 "$(get FP)"
check "TOTAL is 5"                5 "$(get TOTAL)"
check "RECALL is 100pct"          100 "$(get RECALL_PCT)"
check "PRECISION is 100pct"       100 "$(get PRECISION_PCT)"
check "FPR is 0pct"               0 "$(get FPR_PCT)"

# Overbroad rule should produce a false positive and drop precision.
printf 'sqli\tselect\n' > "$TMP/broad.tsv"
out="$(bash "$WP" "$TMP/broad.tsv" "$TMP/corpus.tsv")"
fp="$(get FP)"
if [ "$fp" -ge 1 ]; then echo "ok   - overbroad rule yields FP"; else echo "FAIL - overbroad rule should yield FP"; fails=$((fails+1)); fi

# Missing files should error (exit 2).
if bash "$WP" /no/such "$TMP/corpus.tsv" >/dev/null 2>&1; then
  echo "FAIL - missing ruleset should exit non-zero"; fails=$((fails+1))
else
  echo "ok   - missing ruleset errors"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "all shell-port tests passed"
  exit 0
else
  echo "$fails shell-port test(s) FAILED"
  exit 1
fi
