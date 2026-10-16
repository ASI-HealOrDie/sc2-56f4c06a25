#!/bin/sh
# sc2-make.sh  Q_FILE A_FILE T_FILE OUT ENTROPY_FILE [NOTE_FILE]
# Builds the sealed commitment preimage, the public two-line reference, its short form
# (the "title") and the byte-imprint record. ENTROPY_FILE is REQUIRED and must pass
# sc2-nonce.py's assessment. NOTE_FILE (optional) is one line of PUBLIC text appended to
# line 1 of the reference -- e.g. the question itself, or "my only SC2 record" -- and is
# checked so that it cannot leak the answer or confuse the verifier.
set -eu

usage() { echo "usage: $0 Q_FILE A_FILE T_FILE OUT ENTROPY_FILE [NOTE_FILE]" >&2; exit 2; }
[ $# -eq 5 ] || [ $# -eq 6 ] || usage
Q="$1"; A="$2"; T="$3"; OUT="$4"; ENT="$5"; NOTE="${6:-}"
HERE=$(dirname "$0")
REF="${OUT%.txt}-reference.txt"
TIT="${OUT%.txt}-title.txt"
IMP="${OUT%.txt}-imprint.txt"

# Never destroy an existing artefact. The reference and the title are as irreplaceable
# as the commitment: a second build used to overwrite them silently while leaving the
# commitment protected, so you could publish a reference for a file you had discarded.
for f in "$OUT" "$REF" "$TIT" "$IMP"; do
  [ -e "$f" ] && { echo "REFUSING: $f already exists. Move it aside deliberately." >&2; exit 1; }
done
[ -s "$ENT" ] || { echo "FATAL: entropy file '$ENT' missing or empty. Physical entropy is" >&2
                   echo "       mandatory: without it the nonce rests on a ~256-bit OS seed" >&2
                   echo "       and your answer is a 2^128 Grover search." >&2; exit 1; }

RULES='R1 The committed answer is exactly the byte string in field A, of length ALEN bytes, and nothing else. R2 No prefix, suffix, substring, superstring, reordering, translation, abbreviation, expansion or alternative reading of A is the committed answer. R3 Comparison is byte-exact and therefore case-sensitive. R4 All text in this file is UTF-8 encoded and Unicode-normalised to NFC. R5 All LEN values count BYTES of the UTF-8 encoding, not characters or code points. R6 Line separator is a single LF (0x0A). There is no CR anywhere and no trailing newline after the final END line. R7 No field may contain an LF byte, so each field occupies exactly one line and the first line beginning with a given field name is the only one. R8 There is exactly one correct answer to Q and it is A. R9 Field Q is the complete question; no context outside this file forms part of the question. R10 Field N is secret random padding with no meaning. R11 Each entry in T names a public event that already existed when this file was created, so this file was created no earlier than the latest of them.'

blen() { wc -c < "$1" | tr -d ' '; }
slen() { printf '%s' "$1" | wc -c | tr -d ' '; }

# --- input validation: every rule the file asserts about itself is now checked ---
for f in "$Q" "$A" "$T" $NOTE; do
  [ -s "$f" ] || { echo "FATAL: $f is missing or empty." >&2; exit 1; }
  [ "$(tail -c1 "$f" | wc -l)" -eq 0 ] || {
    echo "FATAL: $f ends with a newline. Rebuild it with printf, not echo." >&2; exit 1; }
  # R6/R7: no CR anywhere, no LF anywhere inside a field.
  # (The old od|tr|grep '0d' test false-positived on any byte ending 0 followed by any
  #  byte starting d -- e.g. a space before a Cyrillic letter.)
  python3 - "$f" <<'PY' || exit 1
import sys, unicodedata
p = sys.argv[1]; b = open(p, "rb").read()
if b"\r" in b: sys.exit("FATAL: %s contains a CR (0x0D) byte." % p)
if b"\n" in b: sys.exit("FATAL: %s contains an LF (0x0A) byte. Rule R7 forbids it: an\n"
                        "       embedded newline lets one field forge another, so the sealed\n"
                        "       record could assert two answers." % p)
try:
    s = b.decode("utf-8")
except UnicodeDecodeError as e:
    sys.exit("FATAL: %s is not valid UTF-8 (%s)." % (p, e))
bad = sorted({c for c in s if unicodedata.category(c) in ("Cf", "Cc", "Co")})
odd = sorted({c for c in s if unicodedata.category(c) in ("Zs", "Zl", "Zp") and c != " "})
if odd:
    sys.exit("FATAL: %s contains a non-standard space (%s): a no-break or thin space, often\n"
             "       inserted automatically before : ; ? ! by French keyboards and editors. It\n"
             "       looks like a space but is a different byte, so the sealed text would not be\n"
             "       what you see, and in the public note it would make the short form differ\n"
             "       between systems. Retype it with an ordinary space."
             % (p, ", ".join("U+%04X" % ord(c) for c in odd)))
if bad:
    sys.exit("FATAL: %s contains invisible or format characters (%s).\n"
             "       Rule R3 makes the comparison byte-exact, so the sealed answer would not\n"
             "       be the string you can see. Retype the field instead of pasting it.\n"
             "       (If your script genuinely needs ZWJ/ZWNJ, remove Cf from this check\n"
             "        deliberately and record why.)"
             % (p, ", ".join("U+%04X" % ord(c) for c in bad)))
if unicodedata.normalize("NFC", s) != s:
    sys.exit("FATAL: %s is not in Unicode NFC form, but rule R4 asserts that it is.\n"
             "       Normalise it, then rebuild it with printf so it keeps no trailing LF."
             % p)
PY
done

# --- the optional public note: it is PUBLISHED, so it must not reveal the answer, and it
#     must not contain a digest label that the verifier would read as part of the reference.
NOTETXT=""
if [ -n "$NOTE" ]; then
  python3 - "$NOTE" "$A" "$Q" <<'PY' || exit 1
import re, sys, unicodedata
note, ans, q = (open(p, encoding="utf-8").read() for p in sys.argv[1:4])
norm = lambda x: " ".join(unicodedata.normalize("NFKC", x).casefold().split())
has = lambda hay, needle: re.search(r"(?<!\w)%s(?!\w)" % re.escape(norm(needle)), norm(hay))
if re.search(r"(?i)(S3A|S3B|B2|S5)=", "".join(note.split())):
    sys.exit("FATAL: the note contains S3A=/S3B=/B2=/S5=, which the verifier reads as a digest.")
if has(note, ans):
    if not has(q, ans):
        sys.exit("FATAL: the note contains the ANSWER as a word. The note is published; the answer is not.")
    sys.stderr.write("note: the answer appears in the note, but also in the question (e.g. a list of\n"
                     "      options), so the note reveals nothing the question does not. Check that.\n")
if len(note.encode()) > 600:
    sys.exit("FATAL: the note is over 600 bytes; keep the public reference short.")
PY
  NOTETXT=" NOTE: $(cat "$NOTE")"
fi

# --- nonce: physical entropy, assessed, MANDATORY ---
# sc2-nonce.py exits 0 only when the assessment passes. Anything else aborts the build.
# There is deliberately no fallback: a nonce this script could produce on its own could
# not satisfy the hiding requirement, so producing one would only be a way to fail quietly.
[ -f "$HERE/sc2-nonce.py" ] || { echo "FATAL: sc2-nonce.py not found beside $0." >&2; exit 1; }
set +e
NONCE=$(python3 "$HERE/sc2-nonce.py" "$ENT")
NRC=$?
set -e
case "$NRC" in
  0) ;;
  3) echo "FATAL: no physical entropy supplied. Build refused." >&2; exit 1 ;;
  4) echo "FATAL: the entropy file did not pass assessment (see above). Build refused." >&2
     echo "       Re-roll or re-shuffle; do not proceed with what you have." >&2; exit 1 ;;
  *) echo "FATAL: sc2-nonce.py exited $NRC. Build refused." >&2; exit 1 ;;
esac
[ ${#NONCE} -eq 768 ] || { echo "FATAL: nonce is ${#NONCE} hex chars, expected 768 (384 bytes)." >&2; exit 1; }

QL=$(blen "$Q"); AL=$(blen "$A"); TL=$(blen "$T"); RL=$(slen "$RULES"); NL=$(slen "$NONCE")
{
  printf 'SC2\n'
  printf 'SPEC=SHA3-512("SC2-A\\n"+F)+SHA3-512("SC2-B\\n"+F)+BLAKE2b-512(F)+SHA-512(F);UTF-8;NFC;LF;NO-TRAILING-NEWLINE\n'
  printf 'QLEN=%s\n' "$QL"; printf 'Q='; cat "$Q"; printf '\n'
  printf 'RLEN=%s\n' "$RL"; printf 'R=%s\n' "$RULES"
  printf 'ALEN=%s\n' "$AL"; printf 'A='; cat "$A"; printf '\n'
  printf 'NLEN=%s\n' "$NL"; printf 'N=%s\n' "$NONCE"
  printf 'TLEN=%s\n' "$TL"; printf 'T='; cat "$T"; printf '\n'
  printf 'END'
} > "$OUT"
chmod 400 "$OUT"

hexd() { openssl dgst -"$1" -r | cut -d' ' -f1; }
S3A=$( { printf 'SC2-A\n'; cat "$OUT"; } | hexd sha3-512 )
S3B=$( { printf 'SC2-B\n'; cat "$OUT"; } | hexd sha3-512 )
B2=$(  hexd blake2b512 < "$OUT" )
S5=$(  hexd sha512     < "$OUT" )
CASE=$(printf '%s' "$S3A" | cut -c1-10 | tr 'a-f' 'A-F')
{
  printf 'SC2/%s sealed record; question, rules and answer are inside it; opened when I choose. Short form: SC2 REF-SHA3-512 is SHA3-512 of these two lines with every run of whitespace made one space and the ends trimmed.%s\n' "$CASE" "$NOTETXT"
  printf 'S3A=%s S3B=%s B2=%s S5=%s\n' "$S3A" "$S3B" "$B2" "$S5"
} > "$REF"
# The title must survive the venue. Reddit renders a single newline as a space, a hard
# break needs two trailing spaces or a backslash, the rich-text editor emits a blank line,
# and the raw selftext carries no trailing newline -- five encodings of the same two lines,
# five different digests, only one of which matches a hash over the exact file bytes. So
# hash a whitespace-canonical form: collapse every run of whitespace to one space, trim.
# This is not a weakening: sc2-verify.py already ignores whitespace when reading the
# reference, so this is simply the same notion of "the same reference" applied to the title.
canon() { tr -s '[:space:]' ' ' < "$1" | sed 's/^ *//; s/ *$//' | tr -d '\n'; }
TITLEHASH=$(canon "$REF" | openssl dgst -sha3-512 -r | cut -d' ' -f1)
printf 'SC2 REF-SHA3-512=%s\n' "$TITLEHASH" > "$TIT"
# The title is over the CANONICAL form, so it survives Reddit -- but that means it no
# longer detects whitespace-only damage to reference.txt, and the TSA tokens are computed
# over the EXACT bytes. Record the byte-hash separately so the drill can check both.
printf 'SHA-512 of %s exactly as timestamped: %s\n' "$REF" \
  "$(openssl dgst -sha512 -r "$REF" | cut -d' ' -f1)" > "$IMP"

echo "preimage : $OUT ($(blen "$OUT") bytes, mode 400)  <-- THE SECRET, never publish"
echo "reference: $REF  <-- the public reference: these TWO LINES, published as they are"
echo "imprint  : $IMP  <-- byte-hash of the reference, as the TSAs will sign it"
echo "short    : $TIT ($(slen "$(cat "$TIT")") chars) <-- the SHORT FORM: fits any post title"
echo "  line 1: $(head -1 "$REF" | tr -d '\n' | wc -c | tr -d ' ') chars"
echo "  line 2: $(tail -1 "$REF" | tr -d '\n' | wc -c | tr -d ' ') chars"
echo "  hex master will be $(( ($(blen "$OUT") * 2 + 63) / 64 )) lines"
echo
echo "NOW DELETE $ENT. It is not needed for anything, and while it exists it is as"
echo "sensitive as the secret: with it, the nonce's secrecy falls back to the OS seed alone."
echo
cat "$TIT"; cat "$REF"
