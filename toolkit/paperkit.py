#!/usr/bin/env python3
"""Paper backup of the preimage: UPPERCASE HEX, 64 characters per line, and a 4-character
checksum per line, so that a reading or typing error is caught and located instead of
silently corrupting the whole file.

  python3 paperkit.py FILE [OUT]          render FILE as a master sheet (default OUT: paper.txt)
  python3 paperkit.py --decode TYPED OUT  rebuild the exact bytes from a master sheet that was
                                          typed back by hand, or scanned and run through OCR.
                                          Writes OUT only if every line checks out.
"""
import hashlib, itertools, re, sys
W = 64


def lsum(i, s):
    return hashlib.sha3_256(("%03d|%s" % (i, s)).encode()).hexdigest()[:4].upper()


def render(data):
    h = data.hex().upper()
    return ["%03d %s %s" % (i + 1, h[i * W:(i + 1) * W], lsum(i + 1, h[i * W:(i + 1) * W]))
            for i in range((len(h) + W - 1) // W)]


# --- reading a sheet back ------------------------------------------------------------------
# Hex is only 0-9 and A-F, so any other letter is a misreading of a hex character.
SURE = {"O": "0", "o": "0", "Q": "0", "I": "1", "i": "1", "l": "1", "L": "1", "|": "1",
        "S": "5", "s": "5", "Z": "2", "z": "2"}        # one sensible reading
MAYBE = {"G": "6C", "g": "96", "q": "9"}                 # several: the line checksum decides
# Hex characters that look alike in print. When a line fails its checksum, ONE swap within
# these pairs is tried; a repair is always reported so that it can be checked on the paper.
SWAP = {"8": "B", "B": "8", "0": "D", "D": "0", "1": "7", "7": "1", "E": "F", "F": "E"}
HEX = set("0123456789ABCDEF")
NUMFIX = str.maketrans({"O": "0", "o": "0", "I": "1", "i": "1", "l": "1", "|": "1"})
ROW = re.compile(r"^\s*([0-9OoIil|]{3})\s+(.+?)\s*$")
MAX_TRIES = 4096


def readings(s):
    """Every hex string the characters of s could stand for, plus the unreadable ones."""
    opts, unreadable = [], []
    for c in s:
        u = c.upper() if c in "abcdef" else c
        if u in HEX:
            opts.append(u)
        elif c in SURE:
            opts.append(SURE[c])
        elif c in MAYBE:
            opts.append(MAYBE[c])
        else:
            unreadable.append(c)
    return opts, unreadable


def solve(n, opts, swaps):
    """All (string, note) readings of a row that pass line n's checksum."""
    combos = 1
    for o in opts:
        combos *= len(o)
    if combos > MAX_TRIES:
        return None
    hits = []
    for pick in itertools.product(*opts):
        s = "".join(pick)
        if lsum(n, s[:-4]) == s[-4:]:
            hits.append((s, None))
    if hits or not swaps:
        return hits
    for pick in itertools.product(*opts):
        s = "".join(pick)
        for p, c in enumerate(s):
            if c in SWAP:
                t = s[:p] + SWAP[c] + s[p + 1:]
                if lsum(n, t[:-4]) == t[-4:]:
                    hits.append((t, "character %d was read as '%s'; only '%s' passes the "
                                 "checksum" % (p + 1, c, SWAP[c])))
    return hits


def note_for(raw, s):
    """Describe how ambiguous characters were resolved. Characters are counted from the
    first one after the line number, ignoring spaces."""
    return ", ".join("character %d ('%s') read as '%s'" % (p + 1, c, s[p])
                     for p, c in enumerate(raw) if c in MAYBE)


def decode(text):
    """Returns (bytes or None, report lines). Produces bytes only if every line from 001 to
    the last is present and passes its checksum, and the result matches the sheet's header."""
    report, rows = [], []
    want_sha3 = want_bytes = want_lines = None
    for raw in text.splitlines():
        m = re.search(r"SHA3-512 of preimage\s*:\s*(.*)", raw)
        if m:
            h = "".join(SURE.get(c, c) for c in m.group(1) if not c.isspace()).lower()
            if re.fullmatch(r"[0-9a-f]{128}", h):
                want_sha3 = h
            continue
        m = re.search(r"bytes:\s*(\d+)\s.*lines:\s*(\d+)", raw)
        if m:
            want_bytes, want_lines = int(m.group(1)), int(m.group(2))
            continue
        m = ROW.match(raw)
        if not m or not any(ch.isdigit() for ch in m.group(1)):
            continue
        rest = "".join(m.group(2).split())
        if sum(ch.upper() in HEX for ch in rest) * 2 < len(rest) or len(rest) < 5:
            continue                                   # prose, not a row of the sheet
        rows.append((int(m.group(1).translate(NUMFIX)), rest))
    if not rows:
        return None, ["no master-sheet lines found (expected lines like '001 <64 hex> <4 hex>')"]

    good, failed, flagged = {}, [], set()              # good[n] = 64-char body
    for n, rest in rows:
        opts, unreadable = readings(rest)
        if unreadable:
            report.append("line %03d: cannot read %s -- re-read that line"
                          % (n, ", ".join("'%s'" % c for c in sorted(set(unreadable)))))
            flagged.add(n)
            continue
        hits = solve(n, opts, swaps=True)
        if hits is None:
            report.append("line %03d: too many unclear characters -- re-read that line" % n)
            flagged.add(n)
            continue
        if len(hits) > 1:
            report.append("line %03d: more than one reading passes its checksum -- re-read it" % n)
            flagged.add(n)
            continue
        if not hits:
            failed.append((n, rest, opts))
            continue
        s, swapped = hits[0]
        if n in good:
            if good[n] != s[:-4]:
                report.append("line %03d appears twice with different contents -- re-read both" % n)
                good[n] = None
            continue
        good[n] = s[:-4]
        how = "; ".join(x for x in (note_for(rest, s), swapped) if x)
        if how:
            report.append("line %03d repaired: %s -- check it on the paper" % (n, how))

    last = max([want_lines or 0] + [n for n in good])
    for n, rest, opts in failed:                       # a misread line NUMBER?
        cands = [m for m in range(1, last + 1) if m not in good and solve(m, opts, False)]
        if len(cands) == 1:
            m = cands[0]
            s = solve(m, opts, False)[0][0]
            good[m] = s[:-4]
            report.append("the line numbered %03d on the sheet is line %03d (its number was "
                          "misread)" % (n, m))
        else:
            report.append("line %03d fails its checksum -- re-read that line" % n)
            flagged.add(n)
    if want_lines is not None and want_lines < last:
        report.append("the header says %d lines, but line %03d is present and checks out: the "
                      "header was misread" % (want_lines, last))
    missing = [n for n in range(1, last + 1) if n not in good]
    for n in missing:
        if n not in flagged:
            report.append("line %03d is missing" % n)
    short = [n for n in range(1, last) if n in good and good[n] is not None and len(good[n]) != W]
    for n in short:
        report.append("line %03d is %d characters long, not 64" % (n, len(good[n])))
    unresolved = [n for n in flagged if n not in good]
    if missing or short or unresolved or any(good[n] is None for n in good) \
            or len(good[last]) % 2:
        return None, report

    data = bytes.fromhex("".join(good[n] for n in range(1, last + 1)))
    got = hashlib.sha3_512(data).hexdigest()
    report.append("all %d lines pass their checksums; %d bytes rebuilt" % (last, len(data)))
    if want_bytes is not None and want_bytes != len(data):
        report.append("*** the header says %d bytes" % want_bytes)
        return None, report
    if want_sha3:
        if got != want_sha3:
            report.append("*** the SHA3-512 of the result differs from the one read from the "
                          "header. If that header line was misread, correct or delete it and "
                          "run again; the digests on VERIFY-PUBLIC are the final check anyway.")
            return None, report
        report.append("SHA3-512 of the result equals the one printed on the sheet")
    else:
        report.append("SHA3-512 of the result: " + got)
    return data, report


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--decode":
        if len(sys.argv) != 4:
            sys.exit("usage: paperkit.py --decode TYPED_SHEET.txt OUTPUT_FILE")
        data, report = decode(open(sys.argv[2], encoding="utf-8", errors="replace").read())
        for r in report:
            print(r)
        if data is None:
            print("NOT WRITTEN: fix the lines above and run again.")
            sys.exit(1)
        open(sys.argv[3], "wb").write(data)
        print("wrote %s -- now check it with the commands on VERIFY-PUBLIC" % sys.argv[3])
        sys.exit(0)
    data = open(sys.argv[1], 'rb').read()
    lines = render(data)
    hdr = ["SEALED COMMITMENT SC2 -- PAPER MASTER",
           "bytes: %d   hex chars: %d   lines: %d" % (len(data), len(data) * 2, len(lines)),
           "SHA3-512 of preimage: " + hashlib.sha3_512(data).hexdigest(),
           "SHA-256 of preimage : " + hashlib.sha256(data).hexdigest() + "  (repair aid)"]
    out = sys.argv[2] if len(sys.argv) > 2 else 'paper.txt'
    open(out, 'w').write("\n".join(hdr + ["-" * 74] + lines) + "\n")
    for l in hdr: print(l)
    print("-" * 74)
    for l in lines[:3]: print(l)
    print("    ... %d more lines ..." % (len(lines) - 5))
    for l in lines[-2:]: print(l)
    # prove the exact round trip, through the same decoder a reader of the sheet would use
    back, rep = decode("\n".join(hdr + lines))
    print("-" * 74)
    print("round-trip from paper -> bytes identical:", back == data,
          " problems:", [r for r in rep if not r.startswith(("all ", "SHA3-512"))])
