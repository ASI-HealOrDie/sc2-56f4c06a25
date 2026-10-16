#!/usr/bin/env python3
"""sc2-btc.py -- check an OpenTimestamps proof against an ARCHIVED Bitcoin block header,
offline, without a Bitcoin node.

  python3 sc2-btc.py FILE FILE.ots HEADERS.txt
  python3 sc2-btc.py --decode HEADERHEX        (stdlib only: print a header's fields)

HEADERS.txt holds one line per block: "<height> <160 hex chars = the 80-byte header>".
Lines starting with # are ignored.

What it checks, for every Bitcoin attestation in the proof:
  1. FILE hashes to the digest the .ots proof starts from (right file, right proof);
  2. the proof's path from that digest ends at the merkle root inside the archived header;
  3. the header carries valid proof-of-work for its own difficulty target, and at least the
     minimum any real block at that height carries (see MIN_WORK below);
  4. it prints the header's double-SHA-256 = the BLOCK HASH, and the block time.

What it cannot check: that this block is the one the Bitcoin network accepted at that
height. That is a fact about consensus, not mathematics. You confirm it by comparing the
printed block hash with any two independent explorers or nodes -- today, in 2038, or
whenever. The block hash is the one value worth writing on paper.

Why `ots verify` is not used: it needs a running Bitcoin Core node and exits with an error
without one. `ots --no-bitcoin verify` prints "check that Bitcoin block N has merkleroot M"
and leaves the check to you; this script performs exactly that check.

Exit codes: 0 at least one attestation matches an archived header with valid PoW
            1 a mismatch (wrong file, wrong header, bad or too little PoW)
            2 nothing to check (only pending attestations, or no header for the height)
            3 the opentimestamps library is not installed (pip install opentimestamps-client)
"""
import sys, hashlib, datetime

# A header can declare any difficulty it likes, so "valid proof-of-work for its own target"
# alone is cheap to fake. Bitcoin's difficulty has not been below 6.1e13 (about 2^77.8 hashes
# per block) since height 812,448 (October 2023; mempool.space difficulty-adjustment data,
# read 5 October 2026). Headers at those heights must therefore show at least 2^74 hashes of
# work: more than 8 times below any real block, yet a real cost to forge. This does not show
# that the block is the one the network accepted; only its hash, compared with the chain, does.
MIN_WORK = [(812448, 74)]          # (from height, minimum log2 of the work)


def min_work(height):
    return max([w for h, w in MIN_WORK if height >= h] or [0])


def dsha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def decode_header(hx):
    h = bytes.fromhex(hx.strip())
    if len(h) != 80:
        raise ValueError("a block header is exactly 80 bytes (160 hex chars); got %d" % len(h))
    bits = int.from_bytes(h[72:76], "little")
    exp, mant = bits >> 24, bits & 0x007FFFFF
    target = mant << (8 * (exp - 3)) if exp > 3 else mant >> (8 * (3 - exp))
    hval = int.from_bytes(dsha256(h), "little")
    return {
        "raw": h,
        "block_hash": dsha256(h)[::-1].hex(),            # display order, as explorers show it
        "merkle_internal": h[36:68],                      # byte order used inside the proof
        "merkle_display": h[36:68][::-1].hex(),
        "time": datetime.datetime.fromtimestamp(int.from_bytes(h[68:72], "little"),
                                                datetime.timezone.utc),
        "pow_ok": target > 0 and hval <= target,
        "work_log2": 256 - (target.bit_length() if target else 256),
    }


def main(argv):
    if len(argv) == 3 and argv[1] == "--decode":
        d = decode_header(argv[2])
        print("block hash  : %s" % d["block_hash"])
        print("merkle root : %s (display order)" % d["merkle_display"])
        print("block time  : %s  (set by the miner; network rules allow ~2 h of slack)"
              % d["time"].strftime("%Y-%m-%d %H:%M:%S UTC"))
        print("proof of work valid for its own target: %s (~2^%d hashes)"
              % ("yes" if d["pow_ok"] else "NO", d["work_log2"]))
        return 0 if d["pow_ok"] else 1
    if len(argv) != 4:
        print(__doc__); return 2

    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    except ImportError:
        print("the opentimestamps library is missing:  pip install opentimestamps-client")
        print("Manual route: `ots --no-bitcoin verify FILE.ots` prints the block height and the")
        print("merkle root; `python3 sc2-btc.py --decode <header>` prints the header's merkle root.")
        return 3

    fpath, otspath, hpath = argv[1:]
    with open(otspath, "rb") as f:
        dtf = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
    with open(fpath, "rb") as f:
        actual = dtf.file_hash_op.hash_fd(f)
    if actual != dtf.file_digest:
        print("*** the .ots proof is NOT for this file: digests differ")
        return 1
    print("file digest matches the proof (%s)" % dtf.file_hash_op.TAG_NAME)

    headers = {}
    for ln in open(hpath, encoding="ascii"):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        height, hx = ln.split()[:2]
        headers[int(height)] = hx

    btc, pending = [], []
    for msg, att in dtf.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            btc.append((att.height, msg))
        elif isinstance(att, PendingAttestation):
            pending.append(att.uri)
    for u in sorted(set(pending)):
        print("note: pending attestation still present (%s) -- harmless once a Bitcoin "
              "attestation verifies" % u)
    if not btc:
        print("*** no Bitcoin attestation in the proof: run  ots upgrade %s" % otspath)
        return 2

    good = bad = 0
    for height, msg in sorted(set(btc)):
        if height not in headers:
            print("block %d: no archived header for this height -- add it to %s" % (height, hpath))
            continue
        d = decode_header(headers[height])
        if d["merkle_internal"] != msg:
            print("*** block %d: proof ends at merkle root %s, header has %s -- NO MATCH"
                  % (height, msg[::-1].hex(), d["merkle_display"]))
            bad += 1; continue
        if not d["pow_ok"]:
            print("*** block %d: header merkle root matches but its proof-of-work is INVALID"
                  % height)
            bad += 1; continue
        if d["work_log2"] < min_work(height):
            print("*** block %d: the header claims only ~2^%d hashes of work; every real block at"
                  " this height has more than 2^%d -- a forged or wrong header"
                  % (height, d["work_log2"], min_work(height)))
            bad += 1; continue
        good += 1
        print("block %d: MATCH -- the proof ends at this header's merkle root" % height)
        print("   block hash : %s" % d["block_hash"])
        print("   block time : %s" % d["time"].strftime("%Y-%m-%d %H:%M:%S UTC"))
        print("   valid proof-of-work (~2^%d hashes for this block alone%s)" % (d["work_log2"],
              ", above the 2^%d minimum for this height" % min_work(height) if min_work(height) else ""))
        print("   NOW CONFIRM by hand that block %d has this hash on two independent"
              " explorers or nodes." % height)
    if bad:
        return 1
    return 0 if good else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
