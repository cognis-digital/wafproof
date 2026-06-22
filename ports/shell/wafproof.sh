#!/usr/bin/env bash
# wafproof shell port — CORE check in POSIX-ish bash.
#
# Defensive measurement only. Sends nothing anywhere. Reads a newline-delimited
# ruleset and a labeled corpus, runs each corpus line against each rule (ERE via
# grep -E), and prints the confusion counts and recall/precision.
#
# Ruleset file lines:  CATEGORY<TAB>ERE_PATTERN          (lines starting # ignored)
# Corpus file lines:   LABEL<TAB>CATEGORY<TAB>TEXT       (LABEL = malicious|benign)
#
# Usage: wafproof.sh RULESET CORPUS
# Exit:  0 always (it is a measurement); metrics go to stdout as KEY=VALUE lines.

set -euo pipefail

die() { echo "wafproof: $*" >&2; exit 2; }

[ "$#" -eq 2 ] || die "usage: wafproof.sh RULESET CORPUS"
RULESET="$1"
CORPUS="$2"
[ -f "$RULESET" ] || die "ruleset not found: $RULESET"
[ -f "$CORPUS" ] || die "corpus not found: $CORPUS"

# Load patterns (skip blank/comment lines).
patterns=()
while IFS=$'\t' read -r _cat pat || [ -n "${pat:-}" ]; do
  case "$_cat" in ''|\#*) continue ;; esac
  [ -n "$pat" ] && patterns+=("$pat")
done < "$RULESET"

[ "${#patterns[@]}" -gt 0 ] || die "ruleset contains no rules"

# detect: returns 0 (match) if ANY pattern matches the text argument.
detect() {
  local text="$1" p
  for p in "${patterns[@]}"; do
    if printf '%s' "$text" | grep -Eq -- "$p"; then
      return 0
    fi
  done
  return 1
}

tp=0; fp=0; fn=0; tn=0
while IFS=$'\t' read -r label _cat text || [ -n "${text:-}" ]; do
  case "$label" in ''|\#*) continue ;; esac
  if detect "$text"; then flagged=1; else flagged=0; fi
  if [ "$label" = "malicious" ]; then
    if [ "$flagged" -eq 1 ]; then tp=$((tp+1)); else fn=$((fn+1)); fi
  else
    if [ "$flagged" -eq 1 ]; then fp=$((fp+1)); else tn=$((tn+1)); fi
  fi
done < "$CORPUS"

# safe integer-percent (x100) to avoid bc dependency
pct() { # numerator denominator -> integer percent
  local n="$1" d="$2"
  if [ "$d" -eq 0 ]; then echo 0; else echo $(( n * 100 / d )); fi
}

echo "TP=$tp"
echo "FP=$fp"
echo "FN=$fn"
echo "TN=$tn"
echo "TOTAL=$(( tp + fp + fn + tn ))"
echo "RECALL_PCT=$(pct $tp $(( tp + fn )))"
echo "PRECISION_PCT=$(pct $tp $(( tp + fp )))"
echo "FPR_PCT=$(pct $fp $(( fp + tn )))"
