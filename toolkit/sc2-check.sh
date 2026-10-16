#!/bin/sh
# sc2-check.sh <preimage> <reference> <title> [timestamp-dir] [roots-dir]
# The annual drill. It VERIFIES; it does not merely look.
#   e.g.  ./sc2-check.sh commitment.txt commitment-reference.txt commitment-title.txt timestamps roots
set -eu
P="${1:?usage: sc2-check.sh <preimage> <reference> <title> [timestamp-dir] [roots-dir]}"
R="${2:?reference file}"; T="${3:?title file}"; D="${4:-timestamps}"; ROOTS="${5:-roots}"; ok=0
here=$(dirname "$0")
echo "== annual integrity drill  $(date -u +%Y-%m-%d) =="

printf '1. preimage readable ................ '
if [ -r "$P" ]; then echo "yes ($(wc -c < "$P" | tr -d ' ') bytes)"; else echo "*** MISSING ***"; ok=1; fi

printf '2. digests match reference .......... '
if python3 "$here/sc2-verify.py" "$P" "$(cat "$R")" 2>/dev/null | grep -q "RESULT: MATCH"; then
  echo "MATCH (all four)"; else echo "*** NO MATCH ***"; ok=1; fi

# Publication binding: the short form (post title) is SHA3-512 of the reference with every
# whitespace run collapsed to one space and the ends trimmed, so it survives any venue's
# line handling.
printf '3. reference matches the short form . '
if [ -r "$T" ]; then
  want=$(sed 's/^SC2 REF-SHA3-512=//' "$T" | tr -d '\n\r ')
  have=$(tr -s '[:space:]' ' ' < "$R" | sed 's/^ *//; s/ *$//' | tr -d '\n' \
         | openssl dgst -sha3-512 -r | cut -d' ' -f1)
  if [ "$want" = "$have" ]; then echo "yes"; else echo "*** NO -- not the reference that was published ***"; ok=1; fi
else echo "*** no $T ***"; ok=1; fi

# The short form ignores whitespace, but the timestamp tokens and the .ots proof were made
# over the EXACT bytes. A stray space or newline kills them while step 3 still passes.
printf '4. reference bytes exact ............ '
IMP="${R%-reference.txt}-imprint.txt"
if [ -r "$IMP" ]; then
  wb=$(sed 's/.*: //' "$IMP" | tr -d '\n\r ')
  hb=$(openssl dgst -sha512 -r "$R" | cut -d' ' -f1)
  if [ "$wb" = "$hb" ]; then echo "yes (as timestamped)"
  else echo "*** BYTES CHANGED -- restore $R from backup, or every timestamp is dead ***"; ok=1; fi
else echo "*** no $IMP ***"; ok=1; fi

printf '5. Bitcoin anchor (OpenTimestamps) .. '
OTS="$R.ots"   # the proof is over the PUBLIC reference, never over the secret
HDR="$D/btc-header.txt"
if [ ! -f "$OTS" ]; then echo "*** no $OTS ***"; ok=1
elif ! python3 -c 'import opentimestamps' 2>/dev/null; then
  echo "cannot check: pip install opentimestamps-client"; ok=1
elif [ ! -s "$HDR" ]; then
  echo "*** no archived block header ($HDR): do runbook step 8 ***"; ok=1
else
  out=$(python3 "$here/sc2-btc.py" "$R" "$OTS" "$HDR" 2>&1) && rc=0 || rc=$?
  case "$rc" in
    0) echo "MATCH, offline"
       echo "$out" | sed -n 's/^block \([0-9]*\): MATCH.*/     block \1/p; s/^ *block hash : /     hash  /p' ;;
    2) echo "*** nothing verifiable:"; echo "$out" | grep -E 'no archived header|no Bitcoin attestation' | sed 's/^/     /'; ok=1 ;;
    *) echo "*** FAILED ***"; echo "$out" | sed 's/^/     /'; ok=1 ;;
  esac
fi

echo '6. timestamp tokens, at their own stamping time, with archived CRLs:'
tsout=$(sh "$here/sc2-tsverify.sh" "$D" "$ROOTS" 2>&1) && tsrc=0 || tsrc=$?
printf '%s\n' "$tsout"
tsgood=$(printf '%s\n' "$tsout" | sed -n 's/.*=> \([0-9]*\) of [0-9]* token.*/\1/p')
tsall=$(printf '%s\n' "$tsout" | sed -n 's/.*=> [0-9]* of \([0-9]*\) token.*/\1/p')
if [ "$tsrc" -ne 0 ]; then ok=1
elif [ -n "$tsall" ] && [ "$tsgood" != "$tsall" ]; then
  echo "  *** only $tsgood of $tsall tokens verify. Put each missing anchor in $ROOTS (runbook 5b),"
  echo "      or restore the damaged files from a backup."
  ok=1
fi

echo
echo "By hand (runbook step 11): confirm the block hash above on one explorer; rewrite the"
echo "archival copies; re-archive your public URLs and profile pages; stamp this year's"
echo "renewal manifest; look again for a free post-quantum (ML-DSA/SLH-DSA) timestamp service."
if [ -d release-kit ]; then
  echo "Automatic release: ask your custodian whether they still have the sealed envelope and"
  echo "the letter, still agree, and still use the same e-mail address; check that you still"
  echo "hold both copies of your cancellation codes."
fi
if [ -d autorelease-repo ]; then
  echo "Automatic release (step 10A): open the private repository's Actions tab, and GitLab's"
  echo "pipelines page if you use step 10A-h. The last twelve scheduled runs (one a month, on the"
  echo "day the kit's README.md gives) must be there, green unless one is a check-in or a reminder, and"
  echo "the last yearly check-in e-mail must have arrived. Check that sc2/log.txt holds every notice"
  echo "your custodian reported valid, and that each platform's e-mail for a red run still"
  echo "reaches you: add a line that says only  test  to sc2/log.txt, push, run each job by"
  echo "hand (each must turn red and e-mail you; such a line never counts as a notice), then"
  echo "remove the line and push."
fi
if [ $ok -eq 0 ]; then echo "STATUS: all checks passed."; else echo "STATUS: ACTION REQUIRED above."; fi
exit $ok
