#!/usr/bin/env python3
"""SC2 verifier -- STRICT. Python stdlib only.
All four digests must be present in the reference AND all four must match.
A reference with a digest missing is REJECTED, not accepted."""
import hashlib, base64, sys, re, unicodedata
EXPECT = ("S3A", "S3B", "B2", "S5")

def digests(P):
    return {"S3A": hashlib.sha3_512(b"SC2-A\n"+P).digest(),
            "S3B": hashlib.sha3_512(b"SC2-B\n"+P).digest(),
            "B2" : hashlib.blake2b(P, digest_size=64).digest(),
            "S5" : hashlib.sha512(P).digest()}

LABEL = re.compile(r'(?i)(S3A|S3B|B2|S5)=')

def parse(s):
    """Tokenise on labels, then require each value run to be EXACTLY one digest.

    Not a regex with a right-hand anchor: the labels B2 and S5 begin with characters that
    are themselves hex digits, so a negative lookahead like (?![0-9a-fA-F]) fails on the
    honest reference -- after S3B's 128 hex characters the next character is the 'B' of
    'B2=' -- and silently falls through to the base64 branch, reporting NO MATCH on a valid
    commitment. Splitting on labels has no such failure mode.

    Whitespace and invisible characters are removed first: zero-width spaces, soft hyphens
    and BOMs are injected by web pages and PDFs on copy, and reporting those as a truncated
    reference reads as tampering when it is a clipboard artefact."""
    invis = [c for c in s if unicodedata.category(c) in ("Cf", "Cc") and c not in "\t\n\r"]
    flat = "".join(c for c in s
                   if not c.isspace() and unicodedata.category(c) not in ("Cf", "Cc"))
    if invis:
        print("  note: removed %d invisible character(s) (%s) -- a copy-paste artefact, "
              "not tampering." % (len(invis), ", ".join(sorted({"U+%04X" % ord(c) for c in invis}))))
    parts = LABEL.split(flat)          # parts[0] is line 1's prose and is ignored by design
    out, dup, mal = {}, set(), set()
    for i in range(1, len(parts) - 1, 2):
        k, val = parts[i].upper(), parts[i + 1]
        if re.fullmatch(r'[0-9a-fA-F]{128}', val):
            b = bytes.fromhex(val)
        elif re.fullmatch(r'[A-Za-z0-9+/]{86}={0,2}', val):
            b = base64.b64decode(val + "=" * (-len(val) % 4))
        else:
            mal.add(k); continue        # too long or too short: not a digest, not a guess
        if k in out and out[k] != b:
            dup.add(k)
        out[k] = b
    return out, dup, mal

P = open(sys.argv[1], "rb").read()
ref, dup, mal = parse(sys.argv[2])
mine = digests(P)
print("preimage: %d bytes" % len(P))
if dup:
    print("\nREJECTED: the reference contains CONTRADICTORY values for %s."
          % ", ".join(sorted(dup)))
    print("An ambiguous reference is not a reference. Refusing to guess.")
    sys.exit(2)
if mal:
    print("\nREJECTED: malformed value for %s -- not exactly 128 hex characters or 86 "
          "base64 characters." % ", ".join(sorted(mal)))
    print("A digest with a character added or dropped is not a digest. Refusing to guess.")
    sys.exit(2)
missing = [k for k in EXPECT if k not in ref]
bad     = [k for k in EXPECT if k in ref and mine[k] != ref[k]]
for k in EXPECT:
    st = "ABSENT" if k in missing else ("MISMATCH" if k in bad else "match")
    print("  %-4s %-9s %s" % (k, st, mine[k].hex()[:32] + "..."))
if missing:
    print("\nREJECTED: reference is incomplete -- %s not present." % ", ".join(missing))
    print("A truncated reference proves nothing. All four values are mandatory.")
    sys.exit(2)
if bad:
    if len(bad) < len(EXPECT):
        print("\n%d of 4 match. A partial match points to a TRANSCRIPTION error in %s,"
              % (len(EXPECT)-len(bad), ", ".join(bad)))
        print("not to a tampered file -- recheck those characters. But it is NOT a pass.")
    print("\nRESULT: NO MATCH"); sys.exit(1)
print("\nRESULT: MATCH  (all four digests, three algorithm families)"); sys.exit(0)
