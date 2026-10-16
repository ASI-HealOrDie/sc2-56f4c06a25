#!/usr/bin/env python3
"""Nonce generator with HONEST entropy accounting.

  python3 sc2-nonce.py                 -> OS randomness only  (EXIT 3: not acceptable)
  python3 sc2-nonce.py entropy.txt     -> physical entropy, assessed  (EXIT 0 only if it passes)

WHAT THIS TOOL CANNOT DO
  Statistical tests detect *gross* defects. They cannot tell physical randomness from a
  deterministic sequence with a uniform marginal. A seeded PRNG, a phone "dice roller"
  app, an online dice site and the base-6 expansion of sqrt(2) all sail through every
  check below with full credit. If your symbols did not come from a physical object you
  shook with your own hands, this tool will lie to you and nothing downstream can catch
  it. That is the one step in the whole procedure with no technical safeguard.

EXIT CODES  (sc2-make.sh keys on these; do not remove them)
  0  physical entropy assessed at >= NEED bits, all checks passed
  3  no entropy file given
  4  entropy file present but failed its checks, or fell short of NEED bits
"""
import hashlib, os, sys, secrets, time, math, zlib, collections

NEED_BITS = 3072   # 2048 published digest bits + 1024 margin -> advantage 2^-512.
# HARD FLOOR 2304. Below 2048 the answer is UNIQUELY DETERMINED by the published digests
# and is hidden only by computation -- a future break of the hash then recovers it, which
# is exactly what the "no recoverable trace even under a cryptographic break" requirement
# forbids. Statistical hiding needs 2048 + 2s bits for s bits of statistical security:
# 2304 -> 2^-128, 2560 -> 2^-256, 3072 -> 2^-512.
NEED = NEED_BITS // 8            # 384 bytes
RANKS, SUITS = "A23456789TJQK", "SHDC"
DECK = {r + s for r in RANKS for s in SUITS}
FACTORY = [r + s for s in SUITS for r in RANKS]      # a deck straight out of the box
FACTORY_R = [r + s for r in RANKS for s in SUITS]    # the other common factory layout
LOG2_52FACT = math.log2(math.factorial(52))   # 225.581...


def mcv_min_entropy(symbols):
    """NIST SP 800-90B 'most common value' estimator: 99% upper confidence bound on
    p_max, then H_min = -log2(p_upper). Conservative and, unlike -log2(p_hat), not
    biased against honest finite samples."""
    n = len(symbols)
    c = collections.Counter(symbols)
    ph = max(c.values()) / n
    pu = min(1.0, ph + 2.576 * math.sqrt(ph * (1 - ph) / (n - 1))) if n > 1 else 1.0
    return -math.log2(pu), c, ph


def chi2_upper(df):
    """~99.9th percentile of chi-square, Wilson-Hilferty. Keeps false rejection ~0.1%."""
    return df * (1 - 2 / (9 * df) + 3.090 * math.sqrt(2 / (9 * df))) ** 3


def _adjacency(block):
    """Unordered adjacent pairs. Unordered, not ordered: a deck recorded backwards adds no
    entropy but shares zero ORDERED pairs with its source, so ordered pairs miss it."""
    return {frozenset((block[i], block[i + 1])) for i in range(51)}


def assess_cards(tokens, need=NEED_BITS):
    """Credit log2(52!) per verified complete-deck permutation that is also INDEPENDENT of
    the blocks already credited. Counting permutations alone is not an entropy estimate:
    fourteen copies of one shuffle, fourteen cuts of one shuffle, and fourteen decks in
    factory order are all fourteen valid permutations and are worth 225.6, 225.6 and 0 bits
    respectively."""
    notes, blocks, bad = [], [], 0
    for i in range(0, len(tokens) - 51, 52):
        b = tokens[i:i + 52]
        if set(b) == DECK and len(set(b)) == 52:
            blocks.append(b)
        else:
            bad += 1
    credited, rejected = [], []
    for b in blocks:
        if b in (FACTORY, FACTORY[::-1], FACTORY_R, FACTORY_R[::-1]):
            rejected.append("a deck in factory order -- this was not shuffled"); continue
        a = _adjacency(b)
        # two independent shuffles share 51/52 ~= 1 adjacent pair on average; a cut shares
        # 50 of 51, a single riffle about half, a copy all of them.
        clash = next((len(_adjacency(p) & a) for p in credited if len(_adjacency(p) & a) >= 10), None)
        if clash is not None:
            rejected.append("a near-duplicate of an earlier block (shares %d of 51 adjacent "
                            "pairs) -- cutting, reversing or re-recording a deck adds almost "
                            "no entropy" % clash); continue
        credited.append(b)
    notes.append("%d tokens = %d complete blocks (%d malformed), %d credited as independent"
                 % (len(tokens), len(blocks), bad, len(credited)))
    notes.append("credit is %.2f bits per independent full-deck permutation (log2 52!)" % LOG2_52FACT)
    if bad:
        notes.append("NOTE: a malformed block is credited zero. Check for typos, duplicates "
                     "or a missing card.")
    for r in rejected:
        notes.append("REJECTED BLOCK: " + r)
    bits = len(credited) * LOG2_52FACT
    ok = bits >= need
    if not ok:
        notes.append("FAIL: %d independent decks = %.0f bits, need %d (%d decks)"
                     % (len(credited), bits, need, math.ceil(need / LOG2_52FACT)))
    return bits, notes, ok


def assess_symbols(sym, need=NEED_BITS):
    """For dice and similar fixed-alphabet sources."""
    notes, ok = [], True
    n = len(sym)
    if n == 0:
        return 0.0, ["no symbols"], False
    hmin, cnt, ph = mcv_min_entropy(sym)
    k = len(cnt)
    bits = n * hmin
    notes.append("%d symbols, %d distinct, most common %.1f%% of the time" % (n, k, ph * 100))
    notes.append("min-entropy %.3f bits/symbol (NIST MCV, 99%% bound; fair d6 = 2.585 ideal)"
                 % hmin)
    if k < 4:
        notes.append("FAIL: fewer than 4 distinct symbols"); ok = False
    if k > 1:
        exp = n / k
        chi = sum((v - exp) ** 2 / exp for v in cnt.values())
        lim = chi2_upper(k - 1)
        if chi > lim:
            notes.append("FAIL: distribution far from uniform (chi2=%.0f, limit %.0f, df=%d)"
                         % (chi, lim, k - 1)); ok = False
        else:
            notes.append("uniformity ok (chi2=%.0f, limit %.0f)" % (chi, lim))
    run = mx = 1
    for i in range(1, n):
        run = run + 1 if sym[i] == sym[i - 1] else 1
        mx = max(mx, run)
    lim = max(6, int(2 * math.log(n, max(k, 2))) + 4)
    if mx > lim:
        notes.append("FAIL: longest repeated run %d (limit %d)" % (mx, lim)); ok = False
    raw = "".join(sym).encode() if isinstance(sym[0], str) else bytes(sym)
    cbits = len(zlib.compress(raw, 9)) * 8
    floor = 0.7 * n * hmin
    if hmin > 0 and cbits < floor:
        notes.append("FAIL: compresses to %d bits, below the %d its own symbol distribution "
                     "implies -- there is structure in the sequence" % (cbits, floor)); ok = False
    else:
        notes.append("compression ok (%d bits, floor %d)" % (cbits, floor))
    if ok and bits < need:
        notes.append("FAIL: %.0f bits assessed, need %d -- roll about %d more"
                     % (bits, need, math.ceil((need - bits) / max(hmin, 0.1))))
        ok = False
    return (bits if ok else 0.0), notes, ok


def assess(raw, need=NEED_BITS):
    """Route by source type. Card codes and dice digits need different models: the
    per-character uniformity test is meaningless for card codes, where suit letters
    appear 13x per deck and rank letters 4x -- non-uniform by construction."""
    text = raw.decode("utf-8", "replace")
    tokens = text.split()
    # "10H" is accepted for the ten and normalised to "TH".
    norm = ["T" + t[2:] if t.startswith("10") else t for t in (x.upper() for x in tokens)]
    if norm and sum(1 for t in norm if t in DECK) >= 0.9 * len(norm):
        bits, notes, ok = assess_cards(norm, need)
        notes.append("credit assumes the runbook protocol: each recorded deck smooshed face "
                     "down >= 60 s, then riffled >= 10 times. Under the Bayer-Diaconis model "
                     "10 riffles leave >= 223.7 bits per deck; 7 riffles leave only 212.3.")
        return "cards", bits, notes, ok
    sym = [c for c in text if not c.isspace()]
    return ("symbols",) + assess_symbols(sym, need)


def main():
    df = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else None
    e = sys.stderr
    src = [("OS CSPRNG (os.urandom)", os.urandom(64)),
           ("OS CSPRNG (secrets)", secrets.token_bytes(64)),
           ("timing jitter (weakly indep.)",
            b"".join(str(time.perf_counter_ns()).encode() for _ in range(64)))]
    try:
        import subprocess
        src.insert(2, ("OS CSPRNG (openssl rand)", subprocess.check_output(["openssl", "rand", "64"])))
    except Exception:
        pass
    e.write("entropy inputs\n")
    e.write("  NOTE: os.urandom, secrets and openssl rand ALL draw from the same kernel\n")
    e.write("        CSPRNG. They are ONE source, not three.\n")
    for nm, d in src:
        e.write("    %-32s %4d bytes\n" % (nm, len(d)))

    rc, phys = 3, 0.0
    if df:
        raw = open(df, "rb").read()
        kind, phys, notes, ok = assess(raw)
        src.append(("physical: %s" % df, raw))
        e.write("\nphysical entropy assessment of %s  [mode: %s]\n" % (df, kind))
        for x in notes:
            e.write("    %s\n" % x)
        e.write("    credited: %.0f bits of the %d required\n" % (phys, NEED_BITS))
        rc = 0 if ok else 4

    blob = b"".join(b"|%s|%d|" % (nm.encode(), len(d)) + d for nm, d in src)
    out = hashlib.shake_256(blob).digest(NEED)   # XOF: one call, no counter construction

    e.write("\nnonce: %d bytes / %d bits\n" % (NEED, NEED_BITS))
    if rc == 0:
        e.write("VERDICT: %.0f bits of assessed physical entropy -> STATISTICAL hiding\n"
                "         (margin %d bits over the 2048 published; advantage 2^-%d).\n"
                % (phys, NEED_BITS - 2048, (NEED_BITS - 2048) // 2))
        e.write("         This assumes your symbols were PHYSICAL. No test can confirm that.\n")
    elif rc == 4:
        e.write("VERDICT: REJECTED. The input failed its checks or fell short.\n"
                "         Exiting %d. sc2-make.sh will refuse to build.\n" % rc)
    else:
        e.write("VERDICT: NO PHYSICAL ENTROPY. The nonce would derive from a ~256-bit OS\n"
                "         seed; recovering your answer is then a 2^128 Grover search,\n"
                "         below your own 2^234 adversary bar. Exiting %d.\n" % rc)
    print(out.hex())
    sys.exit(rc)


if __name__ == "__main__":     # importable: sc2-release.py uses assess()
    main()
