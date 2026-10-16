#!/bin/sh
# sc2-selftest.sh -- run this BEFORE day one, on the machine you will use, and on disclosure
# day on the machine that verifies. It exercises every script offline, in a fresh temporary
# directory, with SYNTHETIC test data (never your real inputs), and checks that the
# outputs agree with independent computations. It deletes nothing.
#
# Synthetic entropy here comes from Python's random module. That is fine for a TEST and
# would be unacceptable for your real commitment (runbook step 2).
set -u
PYTHONDONTWRITEBYTECODE=1; export PYTHONDONTWRITEBYTECODE     # leave no __pycache__ beside the scripts
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/sc2-selftest.XXXXXX") || { echo "cannot create a temp dir"; exit 1; }
cd "$W" || exit 1
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; }
expect() { want=$1; desc=$2; shift 2; "$@" >"$W/.out" 2>&1; got=$?
           if [ "$got" -eq "$want" ]; then ok "$desc"; else bad "$desc (exit $got, wanted $want)"; sed 's/^/        /' "$W/.out" | tail -5; fi; }
same()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1"; printf '        got  %s\n        want %s\n' "$2" "$3"; fi; }
S512() { if command -v sha512sum >/dev/null 2>&1; then sha512sum "$1" | cut -d' ' -f1; else shasum -a 512 "$1" | cut -d' ' -f1; fi; }

echo "== SC2 self-test in $W"
echo "-- 1. tools"
if openssl version | grep -qi libressl; then bad "OpenSSL, not LibreSSL ($(openssl version)) -- install OpenSSL 3"; else ok "$(openssl version | cut -d' ' -f1-2)"; fi
same "openssl SHA3-512 test vector"  "$(printf '' | openssl dgst -sha3-512 -r 2>/dev/null | cut -d' ' -f1)" \
     a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
same "openssl BLAKE2b-512 test vector" "$(printf '' | openssl dgst -blake2b512 -r 2>/dev/null | cut -d' ' -f1)" \
     786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce
same "python3 hashlib agrees" "$(python3 -c 'import hashlib;print(hashlib.sha3_512(b"").hexdigest()[:16],hashlib.blake2b(b"").hexdigest()[:16],hashlib.sha512(b"").hexdigest()[:16])')" \
     "a69f73cca23a9ac5 786a02f742015903 cf83e1357eefb8bd"
expect 0 "openssl ts available" openssl ts -help
command -v sha512sum >/dev/null 2>&1 && ok "sha512sum present" || ok "sha512sum absent; 'shasum -a 512' will be used (macOS)"

echo "-- 2. every file a script calls is present"
missing=$(grep -ohE '(\$HERE|\$here|\$\(dirname "\$0"\))/[A-Za-z0-9_.-]+' "$HERE"/*.sh | sed 's|.*/||' | sort -u |
          while read -r f; do [ -e "$HERE/$f" ] || echo "$f"; done)
[ -z "$missing" ] && ok "release check: nothing missing" || bad "missing beside the scripts: $missing"

echo "-- 3. entropy assessor"
python3 - <<'PY'
import random
r = random.Random(20261002)
deck = [a + b for a in "A23456789TJQK" for b in "SHDC"]
open("cards14.txt", "w").write("\n".join(" ".join(r.sample(deck, 52)) for _ in range(14)) + "\n")
one = r.sample(deck, 52)
open("cards-copied.txt", "w").write("\n".join(" ".join(one) for _ in range(14)) + "\n")
fac = [a + b for b in "SHDC" for a in "A23456789TJQK"]
open("cards-factory.txt", "w").write("\n".join(" ".join(fac) for _ in range(14)) + "\n")
open("cards-reversed.txt", "w").write("\n".join(" ".join(one if i % 2 else one[::-1]) for i in range(14)) + "\n")
open("dice1500.txt", "w").write("".join(r.choice("123456") for _ in range(1500)))
open("dice1200.txt", "w").write("".join(r.choice("123456") for _ in range(1200)))
open("dice350.txt", "w").write("".join(r.choice("123456") for _ in range(350)))
open("dice100.txt", "w").write("".join(r.choice("123456") for _ in range(100)))
PY
expect 0 "14 independent decks accepted"          python3 "$HERE/sc2-nonce.py" cards14.txt
expect 4 "14 copies of one deck rejected"          python3 "$HERE/sc2-nonce.py" cards-copied.txt
expect 4 "14 unshuffled decks rejected"            python3 "$HERE/sc2-nonce.py" cards-factory.txt
expect 4 "deck alternating with its reverse rejected" python3 "$HERE/sc2-nonce.py" cards-reversed.txt
expect 0 "1500 dice accepted"                      python3 "$HERE/sc2-nonce.py" dice1500.txt
expect 4 "1200 dice rejected (too few)"            python3 "$HERE/sc2-nonce.py" dice1200.txt
expect 3 "no entropy file -> refused"              python3 "$HERE/sc2-nonce.py"

echo "-- 4. build"
printf 'TEST: which colour is the test sky, as declared by the test authority?' > q.txt
printf 'BLUE' > a.txt
printf 'TEST anchor only' > t.txt
printf 'TEST public note: this is a self-test record' > note.txt
expect 0 "build succeeds"                          sh "$HERE/sc2-make.sh" q.txt a.txt t.txt commitment.txt cards14.txt note.txt
for f in commitment.txt commitment-reference.txt commitment-title.txt commitment-imprint.txt; do
  [ -s "$f" ] && ok "wrote $f" || bad "did not write $f"; done
case "$(ls -l commitment.txt | cut -c1-10)" in -r--------) ok "secret is read-only, owner only";; *) bad "secret permissions $(ls -l commitment.txt | cut -c1-10)";; esac
[ "$(wc -l < commitment-reference.txt | tr -d ' ')" = 2 ] && ok "reference is exactly two lines" || bad "reference is not two lines"
expect 1 "refuses to overwrite"                    sh "$HERE/sc2-make.sh" q.txt a.txt t.txt commitment.txt cards14.txt
printf 'two\nlines' > qlf.txt;           expect 1 "refuses an LF inside a field"         sh "$HERE/sc2-make.sh" qlf.txt a.txt t.txt x1.txt cards14.txt
printf 'BL\342\200\213UE' > azw.txt;      expect 1 "refuses an invisible character"       sh "$HERE/sc2-make.sh" q.txt azw.txt t.txt x2.txt cards14.txt
printf 'the answer is blue' > nleak.txt; expect 1 "refuses a public note that leaks the answer" sh "$HERE/sc2-make.sh" q.txt a.txt t.txt x3.txt cards14.txt nleak.txt
printf 'TEST: is the test sky BLUE or GREY today?' > qopt.txt; printf 'Q: is the test sky BLUE or GREY today?' > nq.txt
expect 0 "accepts publishing a question that itself lists the answer" sh "$HERE/sc2-make.sh" qopt.txt a.txt t.txt x5.txt cards14.txt nq.txt
printf 'NO' > ano.txt; printf 'noted: only record' > nno.txt
expect 0 "a short answer inside another word is not a leak" sh "$HERE/sc2-make.sh" q.txt ano.txt t.txt x6.txt cards14.txt nno.txt
printf 'S5=%0128d' 0 > nlab.txt
expect 1 "refuses a note containing a digest label" sh "$HERE/sc2-make.sh" q.txt a.txt t.txt x7.txt cards14.txt nlab.txt
expect 1 "refuses degenerate entropy"              sh "$HERE/sc2-make.sh" q.txt a.txt t.txt x4.txt cards-copied.txt
printf 'BLUE\302\240SKY' > anb.txt;     expect 1 "refuses a no-break space (U+00A0) in the answer" sh "$HERE/sc2-make.sh" q.txt anb.txt t.txt x8.txt cards14.txt
printf 'TEST note\342\200\257?' > nnb.txt; expect 1 "refuses a narrow no-break space (U+202F) in the note" sh "$HERE/sc2-make.sh" q.txt a.txt t.txt x9.txt cards14.txt nnb.txt

echo "-- 5. verifier"
REF=$(cat commitment-reference.txt); L2=$(tail -1 commitment-reference.txt)
expect 0 "honest reference: MATCH"                 python3 "$HERE/sc2-verify.py" commitment.txt "$REF"
sed 's/^A=BLUE$/A=GREEN/' commitment.txt > tampered.txt
expect 1 "changed answer: NO MATCH"                python3 "$HERE/sc2-verify.py" tampered.txt "$REF"
python3 -c "d=bytearray(open('commitment.txt','rb').read()); d[-40]^=1; open('bitflip.txt','wb').write(d)"
expect 1 "one flipped bit: NO MATCH"               python3 "$HERE/sc2-verify.py" bitflip.txt "$REF"
expect 2 "digest removed: REJECTED"                python3 "$HERE/sc2-verify.py" commitment.txt "$(printf '%s' "$L2" | sed 's/ S5=[0-9a-f]*//')"
expect 2 "digest one char too long: REJECTED"      python3 "$HERE/sc2-verify.py" commitment.txt "${L2}0"
expect 0 "line-wrapped reference: MATCH"           python3 "$HERE/sc2-verify.py" commitment.txt "$(printf '%s' "$REF" | fold -w 37)"

echo "-- 6. the four hand commands equal line 2"
same "S3A by hand" "$( { printf 'SC2-A\n'; cat commitment.txt; } | openssl dgst -sha3-512 -r | cut -d' ' -f1)" "$(printf '%s' "$L2" | sed 's/.*S3A=\([0-9a-f]*\).*/\1/')"
same "S3B by hand" "$( { printf 'SC2-B\n'; cat commitment.txt; } | openssl dgst -sha3-512 -r | cut -d' ' -f1)" "$(printf '%s' "$L2" | sed 's/.*S3B=\([0-9a-f]*\).*/\1/')"
same "B2 by hand"  "$(openssl dgst -blake2b512 -r commitment.txt | cut -d' ' -f1)" "$(printf '%s' "$L2" | sed 's/.*B2=\([0-9a-f]*\).*/\1/')"
same "S5 by hand"  "$(S512 commitment.txt)" "$(printf '%s' "$L2" | sed 's/.*S5=\([0-9a-f]*\).*/\1/')"

echo "-- 7. short form survives every way a website renders the two lines"
want=$(sed 's/^SC2 REF-SHA3-512=//' commitment-title.txt)
L1=$(head -1 commitment-reference.txt)
i=0
for body in "$L1
$L2
" "$L1
$L2" "$L1
$L2
" "$L1

$L2
" "$L1 $L2"; do
  i=$((i + 1)); printf '%s' "$body" > body$i.txt
  same "rendering $i -> short form" "$(tr -s '[:space:]' ' ' < body$i.txt | sed 's/^ *//; s/ *$//' | tr -d '\n' | openssl dgst -sha3-512 -r | cut -d' ' -f1)" "$want"
done

echo "-- 8. paper"
python3 "$HERE/paperkit.py" commitment.txt master.txt > .pk 2>&1
grep -q 'bytes identical: True' .pk && ok "hex master round-trips byte for byte" || bad "hex master round-trip"
sh "$HERE/sc2-paperpack.sh" commitment.txt commitment-reference.txt > /dev/null 2>&1
[ -s VERIFY-PUBLIC.txt ] && [ -s MASTER-SECRET.txt ] && ok "public and secret sheets written separately" || bad "paper pack"
NONCE=$(sed -n 's/^N=//p' commitment.txt)
if grep -q 'BLUE' VERIFY-PUBLIC.txt || grep -q "$(printf '%s' "$NONCE" | cut -c1-24)" VERIFY-PUBLIC.txt; then bad "public sheet leaks the secret"; else ok "public sheet contains neither answer nor nonce"; fi

python3 - <<'PY'
# What a hand-typist and an OCR program really produce from the printed master sheet.
import random, re
rnd = random.Random(5)
lines = open("master.txt").read().splitlines()
head = [l for l in lines if not re.match(r"^\d{3} ", l)]
rows = [l.split() for l in lines if re.match(r"^\d{3} ", l)]
def grp(s): return " ".join(s[i:i + 8] for i in range(0, len(s), 8))
def sub(s, rules):
    return "".join(next((b for a, b, pr in rules if c == a and rnd.random() < pr), c) for c in s)
typed = ["%s  %s  %s" % (n, grp(sub(b, [("0", "o", .05), ("1", "l", .05), ("5", "s", .03)]).lower()), c.lower())
         for n, b, c in rows]
ocr = [[n, sub(b, [("0", "O", .08), ("1", "I", .05), ("1", "l", .05), ("5", "S", .05), ("2", "Z", .03)]), c]
       for n, b, c in rows]
pick = lambda ch, avoid: next(i for i, r in enumerate(rows) if ch in r[1] and i not in avoid)
i = pick("6", ()); ocr[i][1] = ocr[i][1].replace("6", "G", 1)      # 6 or C? the checksum decides
j = pick("9", (i,)); ocr[j][1] = ocr[j][1].replace("9", "g", 1)    # a 9 read as g
k = pick("8", (i, j)); ocr[k][1] = ocr[k][1].replace("8", "B", 1)  # B/8: repaired by the checksum
ocr[16][0] = "011"                                                  # line 017 numbered 011
ocr[20][1] = ocr[20][1][:30] + " " + ocr[20][1][30:]                # a stray space
bad = [list(r) for r in rows]
bad[16][1] = bad[16][1].replace("A", "B", 1).replace("3", "8", 1)   # two errors: not repairable
bad[22][1] = bad[22][1][:10] + "#" + bad[22][1][11:]                # unreadable
del bad[39]                                                         # line 040 missing
bad = bad[:-1]                                                      # the last line missing
open("typed.txt", "w").write("\n".join(head + typed) + "\n")
open("ocr.txt", "w").write("\n".join(head + [" ".join(r) for r in ocr]) + "\n")
open("bad.txt", "w").write("\n".join(head + [" ".join(r) for r in bad]) + "\n")
PY
expect 0 "master typed back (lowercase, spaces, o/l/s for 0/1/5) is rebuilt" python3 "$HERE/paperkit.py" --decode typed.txt typed.bin
cmp -s typed.bin commitment.txt && ok "  ... byte for byte" || bad "typed master did not rebuild the file"
expect 0 "master read by OCR (O/I/l/S/Z, G, g, B for 8, a misread line number) is rebuilt" python3 "$HERE/paperkit.py" --decode ocr.txt ocr.bin
cmp -s ocr.bin commitment.txt && ok "  ... byte for byte" || bad "OCR master did not rebuild the file"
grep -q 'repaired' "$W/.out" && grep -q 'its number was misread' "$W/.out" && ok "  ... and every repair is reported" || bad "repairs not reported"
expect 1 "damaged master is refused, nothing written" python3 "$HERE/paperkit.py" --decode bad.txt bad.bin
[ ! -e bad.bin ] && grep -q 'line 017 fails its checksum' "$W/.out" && grep -q "line 023: cannot read '#'" "$W/.out" \
  && grep -q 'line 040 is missing' "$W/.out" && grep -q "line $(printf '%03d' "$(grep -c '^[0-9][0-9][0-9] ' master.txt)") is missing" "$W/.out" \
  && ok "  ... naming each bad line, including a missing last line" || bad "damaged master report incomplete"

echo "-- 9. timestamp token verification (local test authority, offline)"
mkdir -p pki/newcerts pki/tsadb ts roots
( cd pki
  printf '[ca]\ndefault_ca=C\n[C]\ndir=.\ndatabase=./index.txt\nserial=./serial\ncrlnumber=./crlnumber\nnew_certs_dir=./newcerts\ndefault_md=sha256\npolicy=p\nunique_subject=no\ndefault_crl_days=30\n[p]\ncommonName=supplied\n[r]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n[i]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n[u]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n' > ca.cnf
  : > index.txt; echo 1000 > serial; echo 1000 > crlnumber; echo 01 > tsadb/serial
  q() { "$@" >/dev/null 2>&1; }
  q openssl req -newkey rsa:2048 -nodes -keyout r.key -out r.csr -subj "/CN=SC2 selftest root"
  q openssl ca -batch -config ca.cnf -selfsign -keyfile r.key -in r.csr -out r.pem -extensions r -startdate 20200101000000Z -enddate 20450101000000Z -notext
  q openssl req -newkey rsa:2048 -nodes -keyout i.key -out i.csr -subj "/CN=SC2 selftest TSA CA"
  q openssl ca -batch -config ca.cnf -cert r.pem -keyfile r.key -in i.csr -out i.pem -extensions i -startdate 20200101000000Z -enddate 20400101000000Z -notext
  q openssl req -newkey rsa:2048 -nodes -keyout u.key -out u.csr -subj "/CN=SC2 selftest TSU"
  q openssl ca -batch -config ca.cnf -cert i.pem -keyfile i.key -in u.csr -out u.pem -extensions u -startdate 20200101000000Z -enddate 20350101000000Z -notext
  cat u.pem i.pem > chain.pem
  printf '[tsa]\ndefault_tsa=t\n[t]\nserial=%s/tsadb/serial\ncrypto_device=builtin\nsigner_cert=%s/u.pem\ncerts=%s/chain.pem\nsigner_key=%s/u.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\ndigests=sha256,sha512\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\n' "$PWD" "$PWD" "$PWD" "$PWD" > tsa.cnf )
cp pki/i.pem roots/trusted-list-entry.pem
openssl ts -query -data commitment-reference.txt -sha512 -cert -out ts/test.tsq 2>/dev/null
openssl ts -reply -config pki/tsa.cnf -queryfile ts/test.tsq -out ts/test.tsr >/dev/null 2>&1
expect 0 "token verifies at its stamping time, anchor = a CA certificate (not a root)" sh "$HERE/sc2-tsverify.sh" ts roots
openssl ts -query -data commitment-title.txt -sha512 -cert -out ts/wrongfile.tsq 2>/dev/null
cp ts/test.tsr ts/wrongfile.tsr
mkdir -p tsw; cp ts/wrongfile.tsq ts/wrongfile.tsr tsw/
expect 1 "token over a different file does not verify" sh "$HERE/sc2-tsverify.sh" tsw roots
mkdir -p rootsw; openssl req -x509 -newkey rsa:2048 -nodes -keyout rootsw/k -out rootsw/other.pem -days 30 -subj "/CN=unrelated" >/dev/null 2>&1
expect 1 "token does not verify against an unrelated anchor" sh "$HERE/sc2-tsverify.sh" ts rootsw
sleep 2   # one-second timestamps cannot order same-second events; such a tie is treated as "before"
( cd pki && openssl ca -config ca.cnf -cert i.pem -keyfile i.key -revoke u.pem >/dev/null 2>&1 && openssl ca -config ca.cnf -cert i.pem -keyfile i.key -gencrl -out crl.pem >/dev/null 2>&1 )
mkdir -p tsr/crl/test; cp ts/test.tsq ts/test.tsr tsr/; cp pki/crl.pem tsr/crl/test/1.crl
expect 0 "key revoked AFTER the token was signed: token still valid, flagged" sh "$HERE/sc2-tsverify.sh" tsr roots
grep -q 'revoked LATER' "$W/.out" && ok "  ... and the late revocation is reported" || bad "late revocation not reported"
sleep 1
mkdir -p tsb/crl/late; openssl ts -query -data commitment-reference.txt -sha512 -cert -out tsb/late.tsq 2>/dev/null
openssl ts -reply -config pki/tsa.cnf -queryfile tsb/late.tsq -out tsb/late.tsr >/dev/null 2>&1
cp pki/crl.pem tsb/crl/late/1.crl
expect 1 "token signed by a key ALREADY revoked is rejected" sh "$HERE/sc2-tsverify.sh" tsb roots
printf 'not a crl' > tsb/crl/late/1.crl
grep -q . tsb/crl/late/1.crl && expect 0 "an unreadable CRL is ignored, not trusted" sh "$HERE/sc2-tsverify.sh" tsb roots

echo "-- 10. Bitcoin anchor (real proof, anchored in block 358391 in 2015)"
H=02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a1e376755f58616186272def6
same "header decodes to the block hash explorers report" "$(python3 "$HERE/sc2-btc.py" --decode "$H" | sed -n 's/^block hash  : //p')" \
     000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319
if python3 -c 'import opentimestamps' 2>/dev/null; then
  printf 'Hello World!\n' > hello-world.txt
  python3 -c "import sys;open('hello-world.txt.ots','wb').write(bytes.fromhex(sys.argv[1]))" 004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010803ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab34003f1c8010100000001e482f9d32ecc3ba657b69d898010857b54457a90497982ff56f97c4ec58e6f98010000006b483045022100b253add1d1cf90844338a475a04ff13fc9e7bd242b07762dea07f5608b2de367022000b268ca9c3342b3769cdd062891317cdcef87aac310b6855e9d93898ebbe8ec0121020d8e4d107d2b339b0050efdd4b4a09245aa056048f125396374ea6a2ab0709c6ffffffff026533e605000000001976a9140bf057d40fbba6744862515f5b55a2310de5772f88aca0860100000000001976a914f00688ac000000000808f120a987f716c533913c314c78e35d35884cac943fa42cac49d2b2c69f4003f85f880808f120dec55b3487e1e3f722a49b55a7783215862785f4a3acb392846019f71dc64a9d0808f120b2ca18f485e080478e025dab3d464b416c0e1ecb6629c9aefce8c8214d0424320808f02011b0e90661196ff4b0813c3eda141bab5e91604837bdf7a0c9df37db0e3a11980808f020c34bc1a4a1093ffd148c016b1e664742914e939efabe4d3d356515914b26d9e20808f020c3e6e7c38c69f6af24c2be34ebac48257ede61ec0a21b9535e4443277be306460808f1200798bf8606e00024e5d5d54bf0c960f629dfb9dad69157455b6f2652c0e8de810808f0203f9ada6d60baa244006bb0aad51448ad2fafb9d4b6487a0999cff26b91f0f5360808f120c703019e959a8dd3faef7489bb328ba485574758e7091f01464eb65872c975c80808f020cbfefff513ff84b915e3fed6f9d799676630f8364ea2a6c7557fad94a5b5d7880808f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b7050808000588960d73d7190103f7ef15
  printf '358391 %s\n' "$H" > hdr.txt
  expect 0 "the real proof matches the archived header, offline" python3 "$HERE/sc2-btc.py" hello-world.txt hello-world.txt.ots hdr.txt
  printf 'Hello World?\n' > other.txt
  expect 1 "the same proof does not fit a different file" python3 "$HERE/sc2-btc.py" other.txt hello-world.txt.ots hdr.txt
  python3 - <<'PY'
# A forger's header: the right merkle root, "valid" work for a difficulty it chose itself.
import hashlib, os
from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.op import OpSHA256, OpAppend
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.serialize import StreamSerializationContext
with open("other.txt", "rb") as f:
    dtf = DetachedTimestampFile.from_fd(OpSHA256(), f)
t = dtf.timestamp.ops.add(OpAppend(os.urandom(16))).ops.add(OpSHA256())
t.attestations.add(BitcoinBlockHeaderAttestation(969600))
with open("forged.ots", "wb") as f:
    dtf.serialize(StreamSerializationContext(f))
bits = 0x207fffff
target = (bits & 0xffffff) << (8 * ((bits >> 24) - 3))
for nonce in range(1 << 20):
    h = (2).to_bytes(4, "little") + bytes(32) + t.msg + (1790900000).to_bytes(4, "little") + bits.to_bytes(4, "little") + nonce.to_bytes(4, "little")
    if int.from_bytes(hashlib.sha256(hashlib.sha256(h).digest()).digest(), "little") <= target:
        break
open("forged-hdr.txt", "w").write("969600 %s\n" % h.hex())
PY
  expect 1 "a forged header at a 2026 height, with a difficulty of its own choosing, is rejected" python3 "$HERE/sc2-btc.py" other.txt forged.ots forged-hdr.txt
else
  ok "opentimestamps library not installed: skipped (pip install opentimestamps-client)"
fi

echo "-- 11. automatic release held by a custodian"
RL="--release 2032-03-01 --published 2026-10-05 --today 2026-10-08 --contact test@example.org --entropy dice350.txt"
expect 0 "custodian kit built" python3 "$HERE/sc2-release.py" make $RL --link https://example.org/sc2-test
for f in CUSTODIAN-LETTER-EN.txt CUSTODIAN-LETTER-FR.txt RELEASE-NOTE.txt INNER-ENVELOPE-LABEL.txt CANCEL-CODES-SECRET.txt; do
  [ -s "release-kit/$f" ] || bad "kit lacks $f"; done
case "$(ls -l release-kit/CANCEL-CODES-SECRET.txt | cut -c1-10)" in -r--------) ok "codes file is read-only, owner only";; *) bad "codes file permissions";; esac
expect 1 "refuses to overwrite a kit"           python3 "$HERE/sc2-release.py" make $RL --link https://example.org/x
expect 1 "refuses a release date under 93 days" python3 "$HERE/sc2-release.py" make --release 2026-12-01 --today 2026-10-08 --contact t@example.org --entropy dice350.txt --link https://example.org/x --out k2
expect 1 "refuses codes made from too few dice (100 rolls)" python3 "$HERE/sc2-release.py" make $RL --entropy dice100.txt --link https://example.org/x --out k5
expect 1 "refuses a kit with no published link" python3 "$HERE/sc2-release.py" make $RL --out k3
python3 -c "import re;t=open('commitment-reference.txt').read();open('ref-wrong.txt','w').write(re.sub(r'S5=(.)',lambda m:'S5='+('1' if m.group(1)=='0' else '0'),t))"
expect 1 "refuses a kit for a reference that is not this file's" python3 "$HERE/sc2-release.py" make $RL --link https://example.org/x --out k4 --reference ref-wrong.txt
python3 - <<'PY' > rel.out 2>&1 && ok "codes: one unbroken chain of 24 ending at the starting value, and the release-certain code, as both letters print them" || { bad "code chain"; cat rel.out; }
import hashlib, re
H = lambda s: hashlib.sha512(s.encode()).hexdigest()
t = open("release-kit/CANCEL-CODES-SECRET.txt").read()
two = r"((?:  [0-9a-f]{64}\n){2})"
codes = [x + y for x, y in re.findall(r"CODE \d\d  ([0-9a-f]{64})\n {9}([0-9a-f]{64})\n", t)]
certain = "".join(re.search(r"RELEASE-CERTAIN CODE\n" + two, t).group(1).split())
assert len(codes) == 24, len(codes)
assert all(H(codes[k + 1]) == codes[k] for k in range(23))
assert "".join(re.search(r"STARTING VALUE \(.*\)\n" + two, t).group(1).split()) == H(codes[0])
assert "".join(re.search(r"RELEASE-CERTAIN VALUE \(.*\)\n" + two, t).group(1).split()) == H(certain)
for f, a, b in (("CUSTODIAN-LETTER-EN.txt", "STARTING VALUE", "RELEASE-CERTAIN VALUE"),
                ("CUSTODIAN-LETTER-FR.txt", "VALEUR DE DÉPART", "VALEUR DE PUBLICATION CERTAINE")):
    s = open("release-kit/" + f, encoding="utf-8").read()
    assert "".join(re.search(a + r" \(.*\)\n" + two, s).group(1).split()) == H(codes[0]), f
    assert "".join(re.search(b + r" \(.*\)\n" + two, s).group(1).split()) == H(certain), f
open("codes.list", "w").write("\n".join(codes) + "\n")
open("certain.code", "w").write(certain + "\n")
PY
NONCE=$(sed -n 's/^N=//p' commitment.txt)
leak=""
for f in CUSTODIAN-LETTER-EN.txt CUSTODIAN-LETTER-FR.txt RELEASE-NOTE.txt INNER-ENVELOPE-LABEL.txt; do
  grep -q 'BLUE' "release-kit/$f" && leak="$leak $f:answer"
  grep -qw "$(wc -c < commitment.txt | tr -d ' ')" "release-kit/$f" && leak="$leak $f:size"
  i=1; while [ $i -le 740 ]; do grep -q "$(printf '%s' "$NONCE" | cut -c$i-$((i + 27)))" "release-kit/$f" && leak="$leak $f:nonce"; i=$((i + 28)); done
  while read -r c; do grep -q "$(printf '%s' "$c" | cut -c1-32)" "release-kit/$f" && leak="$leak $f:code"; done < codes.list
  grep -q "$(cut -c1-32 certain.code)" "release-kit/$f" && leak="$leak $f:certain"
done
[ -z "$leak" ] && ok "letters, note and label hold no answer, file size, nonce fragment or code" || bad "kit leaks:$leak"
L=release-kit/CUSTODIAN-LETTER-EN.txt; F=release-kit/CUSTODIAN-LETTER-FR.txt
P=$(sed -n '/check this PRACTICE code/{n;p;n;p;}' $L | tr -d ' \n'); WANT=$(sed -n '/The result must be:/{n;p;n;p;}' $L | tr -d ' \n')
PASTE=$(printf '%s\n%s' "$(printf '%s' "$P" | cut -c1-64 | tr 'a-f' 'A-F')" "$(printf '%s' "$P" | cut -c65-128)")
PY1='import hashlib,sys;print(hashlib.sha512('"''"'.join(sys.argv[1].lower().split()).encode()).hexdigest())'
if grep -qxF "  printf '%s' 'PASTE CODE' | tr 'A-F' 'a-f' | tr -d '[:space:]' | sha512sum" $L \
   && grep -qxF "  printf '%s' 'PASTE CODE' | tr 'A-F' 'a-f' | tr -d '[:space:]' | shasum -a 512" $L \
   && grep -qxF '  python3 sc2-release.py code "PASTE CODE"' $L && grep -qxF "  python3 -c \"$PY1\" \"PASTE CODE\"" $L \
   && grep -qxF "  printf '%s' 'CODE COLLE' | tr 'A-F' 'a-f' | tr -d '[:space:]' | sha512sum" $F \
   && grep -qxF "  python3 -c \"$PY1\" \"CODE COLLE\"" $F; then ok "the letters print the check commands tested below"; else bad "letter commands differ from the tested ones"; fi
[ "$(sed -n "/code d'ESSAI/{n;n;p;n;p;}" $F | tr -d ' \n')" = "$P" ] && [ "$(sed -n '/Le résultat doit être :$/{n;p;n;p;}' $F | tr -d ' \n')" = "$WANT" ] \
  && ok "both letters give the same practice code and result" || bad "practice code differs between letters"
same "check command, coreutils (practice code pasted on two lines, in capitals)" "$(printf '%s' "$PASTE" | tr 'A-F' 'a-f' | tr -d '[:space:]' | S512 /dev/stdin)" "$WANT"
same "check command, the toolkit"  "$(python3 "$HERE/sc2-release.py" code "$PASTE")" "$WANT"
same "check command, the Python one-liner" "$(python3 -c "$PY1" "$PASTE")" "$WANT"
expect 2 "the toolkit refuses a code that is not 128 characters" python3 "$HERE/sc2-release.py" code "$(printf '%s' "$P" | cut -c1-127)"
START=$(python3 -c "import hashlib;print(hashlib.sha512(open('codes.list').readline().strip().encode()).hexdigest())")
CERT=$(python3 -c "import hashlib;print(hashlib.sha512(open('certain.code').read().strip().encode()).hexdigest())")
c() { sed -n "${1}p" codes.list; }
rchk() { python3 "$HERE/sc2-release.py" check --start "$START" --certain "$CERT" --release 2032-03-01 --today "$1" log.txt; }
printf '2027-01-10 %s\n' "$(c 1)" > log.txt
expect 0 "one notice, however urgent, cancels nothing" rchk 2027-01-20
grep -q 'release on 2032-03-01' "$W/.out" && ok "  ... release still on 2032-03-01" || bad "single notice changed the date"
printf '2027-01-10 %s\n2027-01-11 %s\n2027-01-12 %s\n' "$(c 1)" "$(c 2)" "$(c 3)" > log.txt
expect 0 "three notices on three days cancel nothing" rchk 2027-02-01
printf '2027-01-10 %s\n2027-02-09 %s\n2027-03-12 %s\n' "$(c 1)" "$(c 2)" "$(c 3)" > log.txt
expect 10 "three notices 30 and 31 days apart cancel" rchk 2027-03-12
printf '2027-01-10 %s\n2027-01-15 %s\n2027-02-09 %s\n2027-02-09 %s\n2027-03-11 %s\n' "$(c 1)" "$(c 5)" "$(c 2)" "$(c 2)" "$(c 3)" > log.txt
expect 10 "a forged code is ignored and a duplicate counts once" rchk 2027-03-11
grep -q 'INVALID' "$W/.out" && grep -q 'duplicate' "$W/.out" && ok "  ... and both are reported" || bad "invalid/duplicate not reported"
printf '2027-01-10 %s\n2027-01-10 %s\n' "$(c 2)" "$(c 1)" > log.txt
expect 0 "codes arriving the same day in the wrong order are both accepted" rchk 2027-01-11
[ "$(grep -c '  valid  ' "$W/.out")" -eq 2 ] && ok "  ... as the letter's rule 1 says" || bad "same-day re-check"
: > log.txt
expect 20 "on the release date with no notice: release is due" rchk 2032-03-01
printf '2032-03-01 %s\n' "$(c 1)" > log.txt
expect 20 "a first notice ON the release date changes nothing" rchk 2032-03-01
printf '2032-02-20 %s\n' "$(c 1)" > log.txt
expect 0 "a series in progress on the release date postpones it" rchk 2032-03-05
grep -q 'release on 2032-03-23' "$W/.out" && ok "  ... to the 32nd day after the last notice (2032 is a leap year)" || bad "postponement wrong"
printf '2027-01-10 %s\n2027-02-09 %s\n2027-02-20 %s\n2027-03-11 %s\n' "$(c 1)" "$(c 2)" "$(cat certain.code)" "$(c 3)" > log.txt
expect 0 "the release-certain code stops a cancellation one notice from completing" rchk 2027-03-11
grep -q 'made certain' "$W/.out" && ok "  ... and is reported" || bad "certain not reported"
python3 - "$HERE" <<'PY' > rule.out 2>&1 && ok "the rule agrees with a day-by-day simulation written from the letter, on 20000 random cases" || { bad "rule mismatch"; tail -3 rule.out; }
import importlib.util, random, sys
spec = importlib.util.spec_from_file_location("rel", sys.argv[1] + "/sc2-release.py")
rel = importlib.util.module_from_spec(spec); spec.loader.exec_module(rel)
def custodian(events, R, lo, hi):        # the letter's rules 2-5, applied one day at a time
    last, series, certain, t = None, 0, False, min([R] + list(events))
    while True:
        if t >= R and (certain or last is None or t - last > hi):
            return ("release", t)
        for kind in events.get(t, []):
            if certain:
                continue
            if kind == "certain":
                certain = True
                if t >= R: return ("release", t)
                continue
            gap = None if last is None else t - last
            if t >= R and gap < lo: return ("release", t)
            series = series + 1 if (gap is not None and lo <= gap <= hi) else 1
            last = t
            if series == 3: return ("cancel", t)
        t += 1
rng = random.Random(3)
for _ in range(20000):
    lo, hi = rng.choice([(30, 31), (28, 35), (7, 7)]); R = 1000
    days = sorted(rng.choice(range(R - 150, R + 150)) for _ in range(rng.randint(0, 9)))
    ev, used = [], False
    for d in days:
        k = "certain" if (not used and rng.random() < 0.08) else "notice"
        used = used or k == "certain"; ev.append((d, k))
    byday = {}
    for d, k in ev: byday.setdefault(d, []).append(k)
    a = rel.evaluate(ev, R, lo, hi)[:2]; b = custodian(byday, R, lo, hi)
    assert a == b, (ev, lo, hi, a, b)
    if a[0] == "release": assert a[1] - R <= 2 * hi
PY

echo "-- 12. automatic release on GitHub (offline: a stand-in replaces drand's tle; git remotes are local)"
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  ok "Python older than 3.9: step 10A not tested here (it needs 3.9 or later)"
else
# The stand-in imitates tle's command line and its time-lock: a round opens when quicknet
# reaches it by the clock, or as STUB_TLE_ROUND_NOW says (1: everything shut; a huge number:
# everything open). It is NOT encryption: its "ciphertext" carries the plaintext. The real
# tle and drand are exercised by `sc2-autorelease.py probe` (runbook 10A), on the network.
cat > stub-tle.py <<'PY'
import base64, os, re, sys, time
a, data = sys.argv[1:], sys.stdin.buffer.read()
now = int(os.environ.get("STUB_TLE_ROUND_NOW") or (int(time.time()) - 1692803367) // 3 + 1)
if "-e" in a:
    body = b"age-encryption.org/v1\n-> tlock %s %s\nstub\n--- stub\n" % (a[a.index("-r") + 1].encode(), a[a.index("-c") + 1].encode()) + data.hex().encode()
    b = base64.b64encode(body)
    sys.stdout.buffer.write(b"-----BEGIN AGE ENCRYPTED FILE-----\n" + b"\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + b"\n-----END AGE ENCRYPTED FILE-----\n")
elif "-d" in a:
    raw = base64.b64decode(b"".join(re.search(rb"FILE-----(.*?)-----END", data, re.S).group(1).split()))
    rnd = int(raw.split(b"\n")[1].split()[2])
    if rnd > now:
        sys.stderr.write("too early to decrypt: expected round %d > %d current round\n" % (rnd, now)); sys.exit(1)
    sys.stdout.buffer.write(bytes.fromhex(raw.split(b"\n--- stub\n", 1)[1].decode()))
else:
    sys.exit(2)
PY
SC2_TLE="python3 $W/stub-tle.py"; export SC2_TLE
OPEN=999999999999
AR="$HERE/sc2-autorelease.py"
MK="--entropy dice350.txt --letter release-kit/CUSTODIAN-LETTER-EN.txt --today 2026-10-08 --canary-rounds 2"
GITC="-c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false"
mkbare() { git init -q --bare "$1" && rm -rf seed && git init -q seed && cp commitment-reference.txt commitment-title.txt seed/ \
           && (cd seed && git add -A && git $GITC commit -q -m seed && git push -q "$1" HEAD:refs/heads/main) && rm -rf seed; }
has() { git -C "$1" cat-file -e main:opening/commitment.txt 2>/dev/null; }
arun() { k=$1; d=$2; shift 2; env SC2_KEY="$k" STUB_TLE_ROUND_NOW="${ROUNDNOW:-$OPEN}" SC2_PLATFORM="${PLAT:-GitHub}" \
          GITHUB_EVENT_NAME="${MANUAL:+workflow_dispatch}" python3 "$AR" run --today "$d" --offline-test "$@"; }
for r in pubA pubB pubC pubD; do mkbare "$W/$r.git"; done
python3 - "$HERE" <<'PY' > ar.out 2>&1 && ok "the two tle builds beside the scripts are the pinned ones" || { bad "tle builds"; cat ar.out; }
import hashlib, importlib.util, sys
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
for a, want in ar.TLE_SHA256.items():
    assert hashlib.sha256(open(sys.argv[1] + "/tle-linux-" + a, "rb").read()).hexdigest() == want, a
PY
expect 1 "make refuses key material from too few dice (100 rolls)" python3 "$AR" make --opening-repo "$W/pubA.git" $MK --entropy dice100.txt --out k1 --secrets s1 --opening o1
expect 1 "make refuses a secrets folder inside the repository folder" python3 "$AR" make --opening-repo "$W/pubA.git" $MK --out k2 --secrets k2/s --opening o2
expect 1 "make refuses an https address (a deploy key needs SSH)" python3 "$AR" make --opening-repo https://github.com/x/y $MK --out k3 --secrets s3 --opening o3
sed 's#^SC2/[0-9A-F]\{10\} -- LETTER#SC2/0000000000 -- LETTER#' release-kit/CUSTODIAN-LETTER-EN.txt > letter-other.txt
expect 1 "make refuses a custodian's letter for another record" python3 "$AR" make --opening-repo "$W/pubA.git" $MK --letter letter-other.txt --out k4 --secrets s4 --opening o4
expect 1 "make refuses a tle that does not time-lock (it opens at once)" env STUB_TLE_ROUND_NOW=$OPEN python3 "$AR" make --opening-repo "$W/pubA.git" $MK --out k5 --secrets s5 --opening o5
[ ! -e k5 ] && [ ! -e s5 ] && ok "  ... and writes nothing" || bad "make wrote files for a tle that does not time-lock"
expect 0 "make builds the kit, two targets" python3 "$AR" make --opening-repo "$W/pubA.git" --opening-repo "$W/pubB.git" $MK --out kit1 --secrets sec1 --opening op1
expect 1 "make refuses to overwrite a kit" python3 "$AR" make --opening-repo "$W/pubA.git" $MK --out kit1 --secrets sec9 --opening op9
KS=$(cat sec1/SC2_KEY)
[ "$(wc -c < kit1/sc2/sealed.bin | tr -d ' ')" = 16384 ] && ok "the copy is 16384 bytes" || bad "copy size"
cmp -s op1/commitment-reference.txt commitment-reference.txt && cmp -s op1/commitment-title.txt commitment-title.txt && [ -s op1/README.md ] \
  && ok "the opening repository's first files: the reference, the short form, a README" || bad "opening folder"
python3 - "$HERE" <<'PY' > ar.out 2>&1 && ok "records of 10 and 3000 bytes give copies of the same size; each opens only with both key halves" || { bad "padding"; cat ar.out; }
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
ks, kt = os.urandom(64), os.urandom(64)
a, b = ar.seal(b"x" * 10, ks, kt), ar.seal(b"y" * 3000, ks, kt)
assert len(a) == len(b) == ar.SIZE
assert ar.unseal(a, ks, kt) == b"x" * 10 and ar.unseal(b, ks, kt) == b"y" * 3000
assert ar.unseal(a, os.urandom(64), kt) is None and ar.unseal(a, ks, os.urandom(64)) is None
PY
: > leaks.txt
find kit1 op1 -type f ! -name sealed.bin ! -name 'commitment-reference.txt' ! -name 'commitment-title.txt' ! -path '*/sc2/tools/*' ! -path '*/.git/*' > kitfiles.txt
while read -r f; do
  grep -q 'BLUE' "$f" && echo "$f:answer" >> leaks.txt
  i=1; while [ $i -le 740 ]; do grep -q "$(printf '%s' "$NONCE" | cut -c$i-$((i + 27)))" "$f" && echo "$f:nonce" >> leaks.txt; i=$((i + 28)); done
  grep -q "$(printf '%s' "$KS" | cut -c1-32)" "$f" && echo "$f:key" >> leaks.txt
  case "$f" in */config.json) ;; *) grep -qw "$(wc -c < commitment.txt | tr -d ' ')" "$f" && echo "$f:size" >> leaks.txt;; esac
done < kitfiles.txt
[ ! -s leaks.txt ] && ok "the repository folders hold no answer, nonce fragment, key or file size" || { bad "kit leaks"; cat leaks.txt; }
for t in kit1/sc2/tools/sc2-autorelease.py kit1/sc2/tools/sc2-release.py; do cmp -s "$t" "$HERE/$(basename "$t")" || bad "$t is not the toolkit's"; done
if [ ! -e kit1/SC2_KEY ] && ! grep -rqs --exclude-dir=tools 'PRIVATE KEY' kit1 op1 && [ "$(ls sec1)" = "$(printf 'SC2_KEY\nSETUP.txt')" ] \
   && grep -q '^SC2_KEY\*$' kit1/.gitignore; then
  ok "the secrets are only in the secrets folder, and .gitignore keeps them out of the clone"; else bad "secret material misplaced"; fi
python3 - <<'PY' > ar.out 2>&1 && ok "the kit carries the custodian's starting value, release-certain value, date and window; it locks to 00:00 Paris on the date" || { bad "kit vs letter"; cat ar.out; }
import datetime, hashlib, json
from zoneinfo import ZoneInfo
cfg = json.load(open("kit1/sc2/config.json"))
H = lambda s: hashlib.sha512(s.encode()).hexdigest()
assert cfg["start"] == H(open("codes.list").readline().strip()) and cfg["certain"] == H(open("certain.code").read().strip())
assert (cfg["release"], cfg["window"], cfg["timezone"], cfg["check_in"]) == ("2032-03-01", [30, 31], "Europe/Paris", True)
assert cfg["runs"] == ["2032-%02d-01" % m for m in range(2, 13)] + ["2033-01-01"], cfg["runs"]
t = int(datetime.datetime(2032, 3, 1, tzinfo=ZoneInfo("Europe/Paris")).timestamp()); r = cfg["drand"]["round"]
assert t == 1961708400 and 1692803367 + (r - 2) * 3 < t <= 1692803367 + (r - 1) * 3, r
PY
WF=kit1/.github/workflows/sc2-autorelease.yml
if ! grep -q 'uses:' $WF && grep -qx 'permissions:' $WF && grep -qx '  contents: read' $WF && [ "$(grep -c 'secrets\.' $WF)" -eq 1 ] \
   && [ "$(grep -c "^    - cron: '" $WF)" -eq 2 ] && grep -q "^    - cron: '17 16 1 1,2,3,11,12 \*'   # 1 January, 1 February, 1 March, 1 November and 1 December, 17:17 in Europe/Paris$" $WF \
   && grep -q "^    - cron: '17 15 1 4,5,6,7,8,9,10 \*'" $WF && grep -q 'timeout-minutes: 45' $WF; then
  ok "workflow: no third-party action, read-only token, one secret, a run on the 1st of every month at 17:17 Paris time (two UTC lines: winter, summer), 45-minute limit"; else bad "workflow shape"; fi
mkdir -p srv runner && git init -q --bare srv/kit1.git && (cd kit1 && git init -q && git add -A && git $GITC commit -q -m kit && git push -q ../srv/kit1.git HEAD:refs/heads/main)
python3 - "$WF" > step1.sh <<'PY'
import re, sys
m = re.search(r"- name: Get this repository\n.*?run: \|\n((?: {10}[^\n]*\n)+)", open(sys.argv[1]).read(), re.S)
print("".join(l[10:] + "\n" for l in m.group(1).splitlines()))
PY
expect 0 "the workflow's fetch step, run verbatim against a local server, gets the kit" env TOKEN=dummy RUNNER_TEMP="$W/runner" \
  GITHUB_SERVER_URL="file://$W/srv" GITHUB_REPOSITORY=kit1.git GITHUB_SHA="$(git -C srv/kit1.git rev-parse main)" bash step1.sh
cmp -s runner/kit/sc2/sealed.bin kit1/sc2/sealed.bin && [ -x runner/kit/sc2/tools/tle-linux-amd64 ] && [ -x runner/kit/sc2/tools/tle-linux-arm64 ] \
  && ok "  ... byte for byte, with tle executable" || bad "fetched kit differs"
MANUAL=1; expect 0 "and the fetched kit runs by hand, as in setup: green, with a real push to each target" arun "$KS" 2026-10-08 --kit runner/kit; MANUAL=
[ "$(grep -c 'a real push went through (an empty commit, by hand)' "$W/.out")" -eq 2 ] && git -C pubA.git log -1 --format=%s main | grep -Eq 'job A of kit [0-9a-f]{8} \(by hand\), 2026-10-08$' \
  && ok "  ... marked as by hand: no heartbeat" || bad "manual run push"
expect 1 "the first scheduled run: a heartbeat, and the yearly check-in (red on purpose)" arun "$KS" 2026-10-08 --kit kit1
grep -q "the heartbeat of job A" "$W/.out" && grep -q 'YEARLY CHECK-IN, not a fault' "$W/.out" && grep -q 'It runs on the 1st of every month, and on no other day' "$W/.out" \
  && ok "  ... both, with the dates it runs on" || bad "first scheduled run"
expect 0 "before the date: waiting, healthy (green)" arun "$KS" 2026-10-09 --kit kit1
grep -q 'release on 2032-03-01' "$W/.out" && [ "$(grep -c 'ok   write access to' "$W/.out")" -eq 2 ] \
  && [ "$(grep -c "branch main is there, with this record's reference, nothing in the way" "$W/.out")" -eq 2 ] \
  && ok "  ... release on 2032-03-01; both targets writable (dry run), with this record's reference" || bad "status lines"
n0=$(git -C pubA.git rev-list --count main)
expect 1 "the next year's first run date (2027-02-01, a month before the date's day): its heartbeat, and that year's check-in" arun "$KS" 2027-02-01 --kit kit1
[ "$(git -C pubA.git rev-list --count main)" = $((n0 + 1)) ] && grep -q 'YEARLY CHECK-IN, not a fault' "$W/.out" && ok "  ... both" || bad "check-in at the cycle's first run"
expect 0 "the next run date (2027-03-01): a real push to each target (its heartbeat), no check-in" arun "$KS" 2027-03-01 --kit kit1
[ "$(git -C pubA.git rev-list --count main)" = $((n0 + 2)) ] && git -C pubA.git log -1 --format=%s main | grep -Eq 'write test by automatic-opening job A of kit [0-9a-f]{8}, 2027-03-01$' \
  && ! grep -q 'CHECK-IN' "$W/.out" && ok "  ... an empty commit went through" || bad "heartbeat write test"
expect 0 "a run the next day (one delayed past midnight, or an extra one): green, and no second heartbeat" arun "$KS" 2027-03-02 --kit kit1
[ "$(git -C pubA.git rev-list --count main)" = $((n0 + 2)) ] && ok "  ... none" || bad "a second heartbeat for one run date"
expect 1 "a year on, after runs that never came, the cycle's first run (2028-02-01): the yearly check-in (red on purpose)" arun "$KS" 2028-02-01 --kit kit1
grep -q 'YEARLY CHECK-IN, not a fault' "$W/.out" && ok "  ... it says it is not a fault" || bad "yearly check-in"
expect 1 "a wrong SC2_KEY turns the run red" arun "$(printf '%0128d' 0)" 2026-10-08 --kit kit1
expect 1 "a missing SC2_KEY turns the run red" arun "" 2026-10-08 --kit kit1
expect 1 "63 days before the date: no reminder yet, only the yearly check-in" arun "$KS" 2031-12-29 --kit kit1
grep -q 'YEARLY CHECK-IN, not a fault' "$W/.out" && ! grep -q 'REMINDER' "$W/.out" && ok "  ... as it says" || bad "63 days before"
MANUAL=1; expect 1 "62 days before, a run by hand: the reminder, red on purpose" arun "$KS" 2031-12-30 --kit kit1; MANUAL=
grep -q 'REMINDER, not a fault: your record is due to be released on 2032-03-01, in 62 day(s)' "$W/.out" && ok "  ... and it says so" || bad "reminder text"
expect 0 "  ... but a scheduled run for a run date already covered (as GitHub's extra 29 February run, in the far west) repeats nothing" arun "$KS" 2031-12-30 --kit kit1
! grep -q 'REMINDER' "$W/.out" && ok "  ... no second reminder" || bad "a second reminder"
ROUNDNOW=1; expect 1 "on the date, time-lock still closed: red" arun "$KS" 2032-03-01 --kit kit1; ROUNDNOW=
has pubA.git && bad "published while the time-lock was closed" || ok "  ... and nothing published"
printf 'test\nre\303\247u par e-mail\n' >> kit1/sc2/log.txt
expect 1 "on the date, time-lock open, a 'test' line and an accented note left in the log: red for them, yet published" arun "$KS" 2032-03-01 --kit kit1
grep -q 'no digit in it' "$W/.out" && ! grep -q 'NOT PUBLISHED' "$W/.out" && ok "  ... a plain line with no digit is no notice: it blocks nothing" || bad "test line"
grep -v '^test$' kit1/sc2/log.txt | grep -v '^re.*u par e-mail$' > log.tmp && cat log.tmp > kit1/sc2/log.txt
for r in pubA pubB; do git -C $r.git show main:opening/commitment.txt > got-$r.txt 2>/dev/null
  cmp -s got-$r.txt commitment.txt && ok "  ... $r holds the record byte for byte" || bad "$r content"; done
expect 0 "the published record verifies with sc2-verify.py" python3 "$HERE/sc2-verify.py" got-pubA.txt "$REF"
rm -rf pubclone && git clone -q --branch main pubA.git pubclone
python3 - "$W/pubclone" <<'PY' > ar.out 2>&1 && ok "the release note's five commands, run verbatim, give the reference's digests and short form" || { bad "release note commands"; cat ar.out; }
import re, shutil, subprocess, sys
d = sys.argv[1]
note = open(d + "/opening/RELEASE-NOTE-AUTOMATIC.txt", encoding="utf-8").read()
assert "BLUE" not in note
cmds = [l[2:] for l in note.splitlines() if l.startswith("  ") and ("openssl dgst" in l or l.startswith("  sha512sum"))]
assert len(cmds) == 5, cmds
cmds[3] = cmds[3].split("(macOS")[0].strip()
if not shutil.which("sha512sum"):
    cmds[3] = cmds[3].replace("sha512sum", "shasum -a 512")
outs = [re.search(r"([0-9a-f]{128})", subprocess.run(["sh", "-c", c], cwd=d, capture_output=True, text=True).stdout).group(1) for c in cmds]
l2 = dict(re.findall(r"(S3A|S3B|B2|S5)=([0-9a-f]{128})", open(d + "/commitment-reference.txt").read()))
assert outs[:4] == [l2["S3A"], l2["S3B"], l2["B2"], l2["S5"]], outs
assert open(d + "/commitment-title.txt").read().strip() == "SC2 REF-SHA3-512=" + outs[4]
PY
n1=$(git -C pubA.git rev-list --count main)
expect 0 "run again: already published, nothing pushed" arun "$KS" 2032-03-02 --kit kit1
[ "$(git -C pubA.git rev-list --count main)" = "$n1" ] && grep -q 'already holds the record' "$W/.out" && ok "  ... no second commit" || bad "second run pushed again"
expect 0 "a run before the date once the record is public everywhere (as after your own release): green, no reminder" arun "$KS" 2032-02-01 --kit kit1
grep -q 'already public in every opening repository' "$W/.out" && ! grep -q 'REMINDER' "$W/.out" && ok "  ... it says there is nothing left to remind you of" || bad "reminder after the release"
expect 0 "decrypt by hand, time-lock open" env STUB_TLE_ROUND_NOW=$OPEN python3 "$AR" decrypt --kit kit1 --key-file sec1/SC2_KEY -o opened.txt
cmp -s opened.txt commitment.txt && ok "  ... gives the record" || bad "decrypt output"
expect 1 "decrypt refuses while the time-lock is closed" env STUB_TLE_ROUND_NOW=1 python3 "$AR" decrypt --kit kit1 --key-file sec1/SC2_KEY -o opened2.txt
[ ! -e opened2.txt ] && ok "  ... and writes nothing" || bad "decrypt wrote a file"
STUB_TLE_ROUND_NOW=$OPEN python3 "$W/stub-tle.py" -d -n x -c y < kit1/sc2/key-timelock.age > kt.txt
BY=$(sed -n 's#^    python3 -c "\(.*\)" ~/sc2-open/SC2_KEY ~/sc2-open/kt.txt sc2/sealed.bin > ~/sc2-open/commitment.txt$#\1#p' kit1/README.md)
python3 -c "$BY" sec1/SC2_KEY kt.txt kit1/sc2/sealed.bin > byhand.txt 2>/dev/null
cmp -s byhand.txt commitment.txt && ok "the README's by-hand Python line gives the record" || bad "by-hand line"
expect 0 "a second kit, one target, no check-in" python3 "$AR" make --opening-repo "$W/pubC.git" $MK --out kit2 --secrets sec2 --opening op2 --no-check-in
KS2=$(cat sec2/SC2_KEY)
printf '2027-01-10 %s\n2027-02-09 %s\n2027-03-12 %s\n' "$(c 1)" "$(c 2)" "$(c 3)" > kit2/sc2/log.txt
expect 1 "three valid notices 30 and 31 days apart: CANCELLED (red until the repository is deleted)" arun "$KS2" 2027-03-12 --kit kit2
grep -q 'CANCELLED' "$W/.out" && ok "  ... and it says so" || bad "cancel text"
expect 1 "on the release date it is still cancelled" arun "$KS2" 2032-03-01 --kit kit2
has pubC.git && bad "a cancelled release was published" || ok "  ... and nothing is published"
python3 -c "t=open('kit2/sc2/log.txt').read();open('kit2/sc2/log.txt','wb').write(t.replace(chr(10), chr(13)+chr(10)).encode('utf-16'))"
expect 1 "the same log saved as UTF-16 (Windows PowerShell's >>) still reads as a cancellation" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'CANCELLED' "$W/.out" && ! has pubC.git && ok "  ... nothing published" || bad "UTF-16 log"
same "  ... and the custodian's check agrees, from the same file" "$(python3 "$HERE/sc2-release.py" check --start "$START" --certain "$CERT" --release 2032-03-01 --today 2032-03-01 kit2/sc2/log.txt >/dev/null 2>&1; echo $?)" 10
printf '2027-01-10 %s\n2027-02-30 %s\n2027-03-12 %s\n' "$(c 1)" "$(c 2)" "$(c 3)" > kit2/sc2/log.txt
expect 1 "a notice with a date that does not exist blocks the publication on the date" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && grep -q '2027-02-30 is not a date' "$W/.out" && ! has pubC.git && ok "  ... nothing published, the line named" || bad "invalid date"
mv kit2/sc2/log.txt kit2/sc2/Log.txt
expect 1 "a missing log blocks the publication too" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && ! has pubC.git && ok "  ... nothing published" || bad "missing log"
mv kit2/sc2/Log.txt kit2/sc2/log.txt
python3 -c "import sys;c=open('codes.list').read().split();open('kit2/sc2/log.txt','w',encoding='utf-8').write('2027-01-10 %s 2027-02-09 %s\n2027-03-12 %s\n' % (c[0], c[1], c[2]))"
expect 1 "a line separator U+2028 inside a line: the job does not cancel or publish on a guess" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && ! has pubC.git && ok "  ... it blocks, as unreadable notices must" || bad "U+2028"
same "  ... reading the file as the custodian's check does (not as a cancellation)" "$(python3 "$HERE/sc2-release.py" check --start "$START" --certain "$CERT" --release 2032-03-01 --today 2032-03-01 kit2/sc2/log.txt >/dev/null 2>&1; echo $?)" 20
printf '2032-02-20 %s\n' "$(c 1)" > kit2/sc2/log.txt
MANUAL=1; expect 1 "a series in progress on the date postpones the release (a run by hand: red, a reminder of the new day)" arun "$KS2" 2032-03-05 --kit kit2; MANUAL=
grep -q 'release on 2032-03-23' "$W/.out" && ! has pubC.git && ok "  ... to 2032-03-23, as the custodian's rule says; nothing published yet" || bad "postponement"
expect 1 "  ... and the reminders follow the new day (1 day before it)" arun "$KS2" 2032-03-22 --kit kit2
grep -q 'due to be released on 2032-03-23, in 1 day(s)' "$W/.out" && grep -q 'the job publishes it at its first run from that day, on 2032-04-01' "$W/.out" \
  && ok "  ... as they should, with the run that will publish it" || bad "reminder during postponement"
expect 0 "  ... once per run date: a second scheduled run that day repeats no reminder" arun "$KS2" 2032-03-22 --kit kit2
! grep -q 'REMINDER' "$W/.out" && ok "  ... none" || bad "a second reminder during the postponement"
cp -R kit2 kit2t && python3 -c "p='kit2t/sc2/sealed.bin';d=bytearray(open(p,'rb').read());d[100]^=1;open(p,'wb').write(d)" && : > kit2t/sc2/log.txt
expect 1 "a damaged copy is reported before the date" arun "$KS2" 2027-01-02 --kit kit2t
grep -q 'sealed.bin is missing or has changed' "$W/.out" && ok "  ... by name" || bad "damage not named"
expect 1 "on the date, a damaged copy is never published" arun "$KS2" 2032-03-01 --kit kit2t
grep -q 'REFUSING' "$W/.out" && ! has pubC.git && ok "  ... REFUSING, nothing published" || bad "damaged copy"
expect 0 "the postponed release happens on its day" arun "$KS2" 2032-03-23 --kit kit2
git -C pubC.git show main:opening/commitment.txt 2>/dev/null | cmp -s - commitment.txt && ok "  ... with the record" || bad "postponed release"
printf '2027-01-10 %s\n2033-01-01 %s\nnot a line\n2027-01-11 %s\n' "$(c 1)" "$(c 2)" "$(c 5)" > kit2/sc2/log.txt
expect 1 "log lines it cannot use are reported (a future date, a line without digits, a forged code)" arun "$KS2" 2027-01-20 --kit kit2
grep -q 'after today' "$W/.out" && grep -q "no digit in it" "$W/.out" && grep -q 'is not a valid notice' "$W/.out" && grep -q 'release on 2032-03-01' "$W/.out" \
  && ok "  ... each named; the decision stands" || bad "log problems"
printf '\357\273\2772027-01-10 %s\r\n2027-02-09 %s\r\n' "$(c 1)" "$(c 2)" > kit2/sc2/log.txt
expect 0 "a log saved with a byte-order mark and Windows line ends reads the same" arun "$KS2" 2027-02-10 --kit kit2
grep -q 'A series is in progress (2 of 3)' "$W/.out" && ok "  ... both notices count (series 2 of 3)" || bad "BOM/CRLF log"
expect 0 "a secret given as a GitLab 'File' variable (a path) works" arun "$W/sec2/SC2_KEY" 2027-02-11 --kit kit2
printf '2027-01-10 %s\n2027-02-09 %s\n' "$(c 1)" "$(c 2)" > kit2/sc2/log.txt
python3 -c "import sys;open('kit2/sc2/log.txt','ab').write(('2027-03-11 '+sys.argv[1]+chr(13)+chr(10)).encode('utf-16-le'))" "$(c 3)"
expect 1 "a third notice appended as UTF-16 to the UTF-8 log (PowerShell's >>): the job blocks rather than guess" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'mixes text encodings' "$W/.out" && grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && ok "  ... it names the cause" || bad "mixed encodings"
printf '2017-01-10 %s\n' "$(c 1)" > kit2/sc2/log.txt
expect 1 "a notice dated before the record was sealed (a mistyped year) blocks too" arun "$KS2" 2032-03-01 --kit kit2
grep -q "before the record was even sealed" "$W/.out" && grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && ok "  ... named" || bad "date before the record"
printf '2027-01-10 %s\n2027-02-09 %s\n# my notes' "$(c 1)" "$(c 2)" > kit2/sc2/log.txt && printf '2027-03-11 %s\n' "$(c 3)" >> kit2/sc2/log.txt
expect 1 "the third notice added after a comment with no line end (so inside it): the job blocks, never publishes" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'a comment holds what looks like a code' "$W/.out" && grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && ok "  ... it says why" || bad "notice inside a comment"
python3 -c "import sys;open('kit2/sc2/log.txt','wb').write(('2027-01-10 %s\r\n2027-02-09 %s\r\n# notes\r\n' % (sys.argv[1], sys.argv[2])).encode('utf-16'))" "$(c 1)" "$(c 2)"
printf '\n2027-03-11 %s\n' "$(c 3)" >> kit2/sc2/log.txt
expect 1 "the third notice appended as UTF-8 to a UTF-16 log: the job blocks, never publishes" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'not plain text (in a UTF-16 file)' "$W/.out" && grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && ok "  ... it says why" || bad "UTF-8 inside UTF-16"
printf '2027-01-10 %s\n2027-02-08 %s\n2027-02-09 %s\n2027-03-11 %s\n' "$(c 1)" "$(c 2)" "$(c 2)" "$(c 3)" > kit2/sc2/log.txt
expect 1 "one code logged under two dates (a typo, then the right one): the job does not pick one" arun "$KS2" 2032-03-01 --kit kit2
grep -q 'is logged under more than one date' "$W/.out" && grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" && ok "  ... blocked, both dates named" || bad "two dates, one copy"
mkbare "$W/pubN.git" && cp -R kit2 kit2w && : > kit2w/sc2/log.txt \
  && python3 -c "import json,sys;p='kit2w/sc2/config.json';c=json.load(open(p));c['window']=[7,8];c['targets'][0]['repo']=sys.argv[1];open(p,'w').write(json.dumps(c))" "$W/pubN.git"
expect 1 "a narrow window (7 to 8 days), no check-in: the run a month before the date still sends the reminder" arun "$KS2" 2032-02-01 --kit kit2w
grep -q 'REMINDER, not a fault: your record is due to be released on 2032-03-01, in 29 day(s)' "$W/.out" && ok "  ... 29 days ahead" || bad "reminder, narrow window"
python3 - "$HERE" <<'PY' > ar.out 2>&1 && ok "addresses written differently are recognised as the same repository" || { bad "repo_key"; cat ar.out; }
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
k = ar.repo_key
same = ["git@github.com:Me/Repo.git", "ssh://git@ssh.github.com:443/me/repo", "github-sc2:me/repo.git", "HTTPS://github.com/me/repo/",
        "github.com:me/repo", "git@github.com:/me/repo.git", "https://user:tok@github.com/me/repo.git"]
assert len({k(x) for x in same}) == 1, [k(x) for x in same]
assert k("git@gitlab.com:me/repo.git") == k("ssh://git@altssh.gitlab.com:443/me/repo.git") != k(same[0])
assert k("/tmp/sc2x/repo.git") == k("file:///tmp/sc2x/repo.git") != k("/tmp/sc2x/other.git")
PY
git init -q --bare "$W/pubEmpty.git"
git init -q --bare "$W/pubOther.git" && mkdir -p seedX && (cd seedX && git init -q && printf 'other\n' > commitment-reference.txt && git add -A && git $GITC commit -q -m x && git push -q "$W/pubOther.git" HEAD:refs/heads/main)
mkdir -p seedP && (cd seedP && git init -q && cp ../commitment-reference.txt ../commitment-title.txt . && mkdir opening && printf 'placeholder\n' > opening/commitment.txt && git add -A && git $GITC commit -q -m p && git push -q "$W/pubD.git" HEAD:refs/heads/main -f)
expect 0 "a kit whose mirrors are empty, another record's, and holding a placeholder" python3 "$AR" make --opening-repo "$W/pubEmpty.git" \
  --opening-repo "$W/pubOther.git" --opening-repo "$W/pubD.git" $MK --out kit4 --secrets sec4 --opening op4
expect 1 "  ... is red every day before the date, not just on it" arun "$(cat sec4/SC2_KEY)" 2026-10-08 --kit kit4
grep -q "pubEmpty.git: its branch main cannot be fetched" "$W/.out" && grep -q "pubOther.git: its branch main does not hold this record's" "$W/.out" \
  && grep -q "pubD.git: it holds an opening/commitment.txt that is not this record" "$W/.out" && ok "  ... naming each one" || bad "mirror checks"
git init -q --bare "$W/pubR.git" && mkdir -p seedR && (cd seedR && git init -q && printf 'readme\n' > README && git add -A && git $GITC commit -q -m readme && git push -q "$W/pubR.git" HEAD:refs/heads/main)
expect 0 "rehearse: a synthetic kit, due tomorrow, publishing to a private stand-in" python3 "$AR" rehearse --opening-repo "$W/pubR.git" --canary-rounds 2
RD=$(python3 -c "import json;print(json.load(open('rehearsal-repo/sc2/config.json'))['release'])")
expect 0 "  ... green the day before, the stand-in holding no reference" arun "$(cat rehearsal-secrets/SC2_KEY)" "$(python3 -c "import datetime;print(datetime.date.fromisoformat('$RD')-datetime.timedelta(days=1))")" --kit rehearsal-repo
expect 0 "  ... and on its date it publishes the synthetic record" arun "$(cat rehearsal-secrets/SC2_KEY)" "$RD" --kit rehearsal-repo
git -C pubR.git show main:opening/RELEASE-NOTE-AUTOMATIC.txt 2>/dev/null | grep -q 'REHEARSAL, SYNTHETIC DATA' && ! git -C pubR.git show main:opening/commitment.txt | grep -q 'BLUE' \
  && grep -q 'the SCHEDULED run must publish' rehearsal-secrets/SETUP.txt && ! grep -q '{{' rehearsal-secrets/SETUP.txt \
  && ok "  ... marked REHEARSAL; its SETUP.txt asks for the scheduled run" || bad "rehearsal output"
git init -q --bare "$W/ghR.git" && git init -q --bare "$W/glR.git"
expect 0 "rehearse with GitLab and --no-peer-key: a second synthetic kit" python3 "$AR" rehearse --opening-repo "$W/pubR.git" --canary-rounds 2 \
  --gitlab --no-peer-key --private-repo "$W/ghR.git" --gitlab-repo "$W/glR.git" --out rehearsal2-repo --secrets rehearsal2-secrets
grep -q "GitLab's at 17:17 (Europe/Paris), which publishes it,$" rehearsal2-secrets/SETUP.txt && ! grep -q 'key half' rehearsal2-secrets/SETUP.txt \
  && ok "  ... its SETUP.txt promises no key half: GitLab's run publishes, GitHub's finds it done" || bad "rehearsal text without the shared half"
mkdir -p paris && (cd paris && printf 'TEST: which city hosts the test, Paris or Lyon?' > q.txt && printf 'Paris' > a.txt && printf 'TEST anchor' > t.txt \
  && printf 'Q: which city hosts the test, Paris or Lyon?' > n.txt && sh "$HERE/sc2-make.sh" q.txt a.txt t.txt commitment.txt ../cards14.txt n.txt >/dev/null 2>&1 \
  && python3 "$HERE/sc2-release.py" make --release 2032-03-01 --published 2026-10-05 --today 2026-10-08 --contact t@example.org --entropy ../dice350.txt --link https://example.org/x >/dev/null 2>&1)
expect 0 "an answer that is an ordinary word (Paris), in a public question, in the time zone's name: the kit is made" \
  sh -c "cd paris && python3 '$AR' make --opening-repo '$W/pubA.git' --entropy ../dice350.txt --today 2026-10-08 --canary-rounds 2 --out k --secrets s --opening o"
mkdir -p ny && (cd ny && printf 'TEST: which city hosts the test, Paris or Lyon?' > q.txt && printf 'Lyon' > a.txt && printf 'TEST anchor' > t.txt \
  && printf 'Q: which city hosts the test, Paris or Lyon?' > n.txt && sh "$HERE/sc2-make.sh" q.txt a.txt t.txt commitment.txt ../cards14.txt n.txt >/dev/null 2>&1 \
  && python3 "$HERE/sc2-release.py" make --release 2032-03-31 --published 2026-10-05 --today 2026-10-08 --contact t@example.org --entropy ../dice350.txt --link https://example.org/x >/dev/null 2>&1)
expect 0 "a kit for New York, released on 31 March, with GitLab: GitHub's 21:17 there is the next day in UTC" \
  sh -c "cd ny && python3 '$AR' make --opening-repo '$W/pubA.git' --entropy ../dice350.txt --today 2026-10-08 --canary-rounds 2 --timezone America/New_York --gitlab --private-repo '$W/ghN.git' --gitlab-repo '$W/glN.git' --out k --secrets s --opening o"
NYW=ny/k/.github/workflows/sc2-autorelease.yml
grep -q "^    - cron: '17 2 29 2 \*'   # 28 February, 21:17 in America/New_York (in leap years)$" $NYW \
  && grep -q "^    - cron: '17 2 1 3 \*'   # 28 February, 21:17 in America/New_York (in other years; also on 29 February in leap years)$" $NYW \
  && [ "$(grep -c "^    - cron: '" $NYW)" -eq 4 ] && grep -q "^    - cron: '17 2 1 1,2,12 \*'   # 31 January, 30 November and 31 December, 21:17 in America/New_York$" $NYW \
  && grep -q "GitHub's job also runs on 29 February in leap years, because its schedule is in UTC" ny/k/README.md && grep -qF "'17 17 28 2 *'" ny/k/.gitlab-ci.yml \
  && ok "  ... its 28 February run gets a UTC line for leap years and one for the others; README.md names the extra run" || bad "leap-year lines"
mkdir -p feb29 && (cd feb29 && printf 'TEST: which day is it, the 28th or the 29th?' > q.txt && printf 'the 29th' > a.txt && printf 'TEST anchor' > t.txt \
  && printf 'Q: which day is it?' > n.txt && sh "$HERE/sc2-make.sh" q.txt a.txt t.txt commitment.txt ../cards14.txt n.txt >/dev/null 2>&1 \
  && python3 "$HERE/sc2-release.py" make --release 2032-02-29 --published 2026-10-05 --today 2026-10-08 --contact t@example.org --entropy ../dice350.txt --link https://example.org/x >/dev/null 2>&1)
expect 1 "make refuses a release date of 29 February: February's two runs in leap years would show it" \
  sh -c "cd feb29 && python3 '$AR' make --opening-repo '$W/pubA.git' --entropy ../dice350.txt --today 2026-10-08 --canary-rounds 2 --out k --secrets s --opening o"
grep -q 'a release date of 29 February would show itself' "$W/.out" && [ ! -e feb29/k ] && [ ! -e feb29/s ] && ok "  ... before writing anything" || bad "29 February"
python3 - "$HERE" <<'PY' > ar.out 2>&1 && ok "a kit that would leak is refused, and all three folders, the secrets included, are removed" || { bad "leak refusal"; cat ar.out; }
import importlib.util, os, sys, tempfile
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
d = tempfile.mkdtemp(); out, sec, op = (os.path.join(d, x) for x in ("o", "s", "p"))
for x in (out, sec, op): os.makedirs(x)
open(os.path.join(out, "README.md"), "w").write("A=BLUE\n"); open(os.path.join(sec, "SC2_KEY"), "w").write("k")
try:
    ar.finish_make(out, sec, op, b"SC2\nA=BLUE\nEND", [os.urandom(64), os.urandom(64)], {}, 0)
    raise AssertionError("not refused")
except SystemExit:
    pass
assert not any(os.path.exists(x) for x in (out, sec, op))
PY
python3 - "$HERE" <<'PY' > ar.out 2>&1 && ok "tle: only the pinned build runs; an altered copy is refused" || { bad "tle pinning"; cat ar.out; }
import importlib.util, os, platform, shutil, sys, tempfile
os.environ.pop("SC2_TLE", None)
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
a = ar.arch()
if platform.system() == "Linux" and a:
    d = tempfile.mkdtemp(); shutil.copy(sys.argv[1] + "/tle-linux-" + a, d)
    ways, _ = ar.tle_ways(d); assert ways and ways[0][1] == [os.path.join(d, "tle-linux-" + a)], ways
    open(os.path.join(d, "tle-linux-" + a), "ab").write(b"\0")
    ways, notes = ar.tle_ways(d)
    assert ways == [] and "not the pinned build" in " ".join(notes), (ways, notes)
    shutil.rmtree(d)
PY
if command -v ssh-keygen >/dev/null 2>&1; then
  expect 1 "make --gitlab refuses to go without the two private repositories' addresses" python3 "$AR" make \
    --opening-repo git@github.com:example/sc2-test-opening.git $MK --out kit3x --secrets sec3x --opening op3x --gitlab
  expect 1 "make refuses a private repository that is also an opening repository" python3 "$AR" make \
    --opening-repo git@github.com:example/sc2-test-opening.git $MK --out kit3y --secrets sec3y --opening op3y --gitlab \
    --private-repo git@github.com:example/sc2-test-opening.git --gitlab-repo git@gitlab.com:example/sc2-auto-test.git
  expect 0 "a kit with two SSH targets and both schedulers gets one deploy key per target and per platform" python3 "$AR" make \
    --opening-repo git@github.com:example/sc2-test-opening.git --opening-repo git@codeberg.org:example/sc2-test-opening.git $MK --out kit3 --secrets sec3 --opening op3 --gitlab \
    --private-repo git@github.com:example/sc2-auto-test.git --gitlab-repo git@gitlab.com:example/sc2-auto-test.git
  [ -s sec3/SC2_DEPLOY_KEY ] && [ -s sec3/SC2_DEPLOY_KEY.pub.txt ] && [ -s sec3/SC2_DEPLOY_KEY_2 ] && [ -s sec3/gitlab/SC2_DEPLOY_KEY ] \
    && [ -s sec3/gitlab/SC2_DEPLOY_KEY_2.pub.txt ] && ! cmp -s sec3/SC2_DEPLOY_KEY sec3/gitlab/SC2_DEPLOY_KEY \
    && [ -s sec3/SC2_READ_KEY ] && [ -s sec3/gitlab/SC2_READ_KEY.pub.txt ] && ! cmp -s sec3/SC2_READ_KEY sec3/gitlab/SC2_READ_KEY \
    && [ "$(grep -c 'secrets\.' kit3/.github/workflows/sc2-autorelease.yml)" -eq 4 ] \
    && grep -qF 'SC2_READ_KEY: ${{ secrets.SC2_READ_KEY }}' kit3/.github/workflows/sc2-autorelease.yml \
    && grep -q '"web": "https://codeberg.org/example/sc2-test-opening"' kit3/sc2/config.json \
    && ok "  ... in the secrets folder, GitLab's apart and different, with a read key each; the workflow passes all four secrets" || bad "deploy keys"
  S3="$(pwd -P)/sec3"
  grep -qF "gh secret set SC2_READ_KEY --repo example/sc2-auto-test < \"$S3/SC2_READ_KEY\"" sec3/SETUP.txt \
    && grep -qF "glab variable set SC2_KEY --masked --hidden --protected -R https://gitlab.com/example/sc2-auto-test < \"$S3/gitlab/SC2_KEY\"" sec3/SETUP.txt \
    && grep -qF "glab variable set SC2_READ_KEY --type file --protected -R https://gitlab.com/example/sc2-auto-test < \"$S3/gitlab/SC2_READ_KEY\"" sec3/SETUP.txt \
    && grep -q 'THIS FOLDER OPENS YOUR RECORD AT ONCE' sec3/SETUP.txt && ! grep -q '{{' sec3/SETUP.txt \
    && [ "$(grep -n '^G6\.' sec3/SETUP.txt | cut -d: -f1)" -lt "$(grep -n '^7\. Run both' sec3/SETUP.txt | cut -d: -f1)" ] \
    && [ "$(grep -n '^7\. Run both' sec3/SETUP.txt | cut -d: -f1)" -lt "$(grep -n '^8\. Today, as soon as step 7 is done, delete this folder' sec3/SETUP.txt | cut -d: -f1)" ] \
    && [ "$(grep -n '^8\. Today' sec3/SETUP.txt | cut -d: -f1)" -lt "$(grep -n '^9\. On 2026-11-01' sec3/SETUP.txt | cut -d: -f1)" ] \
    && ok "  ... SETUP.txt: the exact gh and glab commands, the warning, GitLab's steps before the runs, the folder deleted last" || bad "SETUP.txt for two platforms"
  grep -rqs --exclude-dir=tools 'PRIVATE KEY' kit3 op3 && bad "a private key is in a repository folder" || ok "  ... and no private key is in a repository folder"
else ok "ssh-keygen absent: deploy-key generation not tested here"; fi
mkbare "$W/pubE.git"
git init -q --bare "$W/gh5.git" && git init -q --bare "$W/gl5.git"
expect 0 "a kit for two schedulers, GitHub and GitLab, each reading the other's copy of the log" python3 "$AR" make --opening-repo "$W/pubE.git" $MK \
  --out kit5 --secrets sec5 --opening op5 --gitlab --private-repo "$W/gh5.git" --gitlab-repo "$W/gl5.git"
grep -qF 'CI_PIPELINE_SOURCE == "schedule" || $CI_PIPELINE_SOURCE == "web"' kit5/.gitlab-ci.yml && grep -q 'image: python:3$' kit5/.gitlab-ci.yml \
  && grep -qF 'python3 sc2/tools/sc2-autorelease.py run --kit "$CI_PROJECT_DIR"' kit5/.gitlab-ci.yml \
  && ! grep -qE 'SC2_|PRIVATE KEY|[0-9a-f]{64}' kit5/.gitlab-ci.yml && grep -q '^  resource_group: sc2-autorelease' kit5/.gitlab-ci.yml \
  && grep -qF "'17 17 1 * *'" kit5/.gitlab-ci.yml && grep -q 'THE SECOND SCHEDULER, ON GITLAB' sec5/SETUP.txt \
  && grep -qF 'interval pattern "17 17 1 * *"' sec5/SETUP.txt && ! grep -q '{{' sec5/SETUP.txt \
  && grep -q "^    - cron: '17 20 1 1,2,3,11,12 \*'" kit5/.github/workflows/sc2-autorelease.yml && grep -q "^    - cron: '17 19 1 4,5,6,7,8,9,10 \*'" kit5/.github/workflows/sc2-autorelease.yml \
  && python3 -c "import json,sys;c=json.load(open('kit5/sc2/config.json'));sys.exit(c['platforms']!=['GitHub','GitLab'] or c['private_repos']!={'GitHub':'$W/gh5.git','GitLab':'$W/gl5.git'})" \
  && ok "  ... .gitlab-ci.yml (no secret in it, one run at a time), GitLab at 21:17, both platforms and both private copies in config.json" || bad "GitLab kit"
(cd kit5 && git init -q && git add -A && git $GITC commit -q -m kit && git branch -M main && git remote add origin "$W/gh5.git" \
  && git remote set-url --add --push origin "$W/gh5.git" && git remote set-url --add --push origin "$W/gl5.git" && git push -q -u origin main) > /dev/null 2>&1
[ "$(git -C kit5 remote -v | grep -c '(push)')" -eq 2 ] && [ -n "$(git -C gh5.git rev-parse main 2>/dev/null)" ] \
  && [ "$(git -C gh5.git rev-parse main)" = "$(git -C gl5.git rev-parse main 2>/dev/null)" ] \
  && ok "  ... SETUP's G2: one push from the working copy updates both private repositories" || bad "double push"
K5=$(cat sec5/SC2_KEY); K5G=$(cat sec5/gitlab/SC2_KEY); P5=$(cat sec5/gitlab/SC2_PEER_KEY)
glrun() { d=$1; shift; env SC2_KEY="$K5G" SC2_PEER_KEY="${PEERKEY-$P5}" STUB_TLE_ROUND_NOW="${ROUNDNOW:-$OPEN}" GITLAB_CI=true \
          CI_PIPELINE_SOURCE="${GLSOURCE:-schedule}" python3 "$AR" run --today "$d" --offline-test --kit kit5; }
python3 - "$HERE" "$W" <<'PY2' > ar.out 2>&1 && ok "  ... two copies, two keys: neither platform's secrets open the other's copy; GitLab holds GitHub's locked half" || { bad "separate copies"; cat ar.out; }
import importlib.util, os, re, subprocess, sys
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
rd = lambda p: bytes.fromhex(open(p).read().strip())
def opened(lock):
    r = subprocess.run(["python3", sys.argv[2] + "/stub-tle.py", "-d", "-n", "x", "-c", "y"], input=open(lock, "rb").read(),
                       capture_output=True, env=dict(os.environ, STUB_TLE_ROUND_NOW="999999999999"))
    return bytes.fromhex(r.stdout.decode().strip())
ksh, ksl, peer = rd("sec5/SC2_KEY"), rd("sec5/gitlab/SC2_KEY"), rd("sec5/gitlab/SC2_PEER_KEY")
kth, ktl = opened("kit5/sc2/key-timelock.age"), opened("kit5/sc2/key-timelock-gitlab.age")
rec = open("commitment.txt", "rb").read()
gh, gl = open("kit5/sc2/sealed.bin", "rb").read(), open("kit5/sc2/sealed-gitlab.bin", "rb").read()
assert ksh != ksl and kth != ktl and peer == kth
assert ar.unseal(gh, ksh, kth) == rec and ar.unseal(gl, ksl, ktl) == rec
assert ar.unseal(gh, ksl, peer) is None and ar.unseal(gl, ksh, ktl) is None and ar.unseal(gl, ksl, kth) is None
PY2
MANUAL=1; expect 0 "  ... GitHub's first run by hand: green" arun "$K5" 2026-10-08 --kit kit5; MANUAL=
grep -q "GitLab's copy of the log is readable, and the same as this one" "$W/.out" && ok "  ... it read GitLab's copy of the log" || bad "other log, GitHub side"
expect 1 "  ... 301 days on, GitLab has never run: GitHub's job reports it" arun "$K5" 2027-08-05 --kit kit5
grep -q 'the job on GitLab left no heartbeat at its scheduled run of 2027-08-01 (its last: none since it was set up)' "$W/.out" \
  && grep -q 'red run is how GitHub e-mails you' "$W/.out" && ok "  ... by name, and GitHub takes over the check-in" || bad "watchdog: GitLab missing"
expect 0 "  ... GitLab's first scheduled run: its heartbeat, GitHub's seen, and no second check-in (GitHub, standing in, sent this year's)" glrun 2027-08-05
grep -q "the heartbeat of job B" "$W/.out" && grep -q 'the job on GitHub is alive' "$W/.out" && grep -q 'SC2_PEER_KEY present' "$W/.out" \
  && ! grep -q 'CHECK-IN' "$W/.out" \
  && grep -q "GitHub's copy of the log is readable, and the same as this one" "$W/.out" \
  && ok "  ... both, it holds GitHub's half, and it read GitHub's copy of the log" || bad "watchdog: GitLab side"
git -C pubE.git log --format=%s main | grep -qi 'github\|gitlab' && bad "a public commit names a platform before the date" || ok "  ... the public heartbeats name no platform (job A, job B)"
GLSOURCE=web; expect 0 "  ... a GitLab run by hand the next day: green, and its push is no heartbeat" glrun 2027-08-06; GLSOURCE=
expect 0 "  ... GitHub's job, that day, still dates GitLab's heartbeat from the scheduled run" arun "$K5" 2027-08-06 --kit kit5
grep -q 'the job on GitLab is alive: its last heartbeat is from 2027-08-05' "$W/.out" && ok "  ... 2027-08-05" || bad "watchdog: a run by hand counted"
PEERKEY=""; expect 1 "  ... GitLab without its SC2_PEER_KEY: red" glrun 2027-08-07; unset PEERKEY
PEERKEY=""; expect 1 "  ... and at the next run date (2028-02-01), a run with a health problem leaves no heartbeat" glrun 2028-02-01; unset PEERKEY
git -C pubE.git log --format=%s main | grep -Eq 'job B of kit [0-9a-f]{8}, 2028-02-01$' && bad "an unhealthy run left a heartbeat" || ok "  ... none"
expect 1 "  ... the next run with no health problem of its own leaves it, with this year's check-in (GitLab runs first: it sends it)" glrun 2028-02-02
git -C pubE.git log --format=%s main | grep -Eq 'job B of kit [0-9a-f]{8}, 2028-02-02$' && grep -q 'red run is how GitLab e-mails you' "$W/.out" \
  && ok "  ... dated 2028-02-02" || bad "heartbeat after recovery"
CASE5=$(python3 -c "import json;print(json.load(open('kit5/sc2/config.json'))['case'])")
rm -rf fake5 && git clone -q -b main "$W/pubE.git" fake5 \
  && git -C fake5 $GITC commit -q --allow-empty -m "SC2/$CASE5: write test by automatic-opening job A of kit 00000000, 2028-05-01" && git -C fake5 push -q origin HEAD:main
expect 1 "  ... GitHub's job missed its scheduled runs (a heartbeat from another kit of the same record does not count): GitLab's job names the last one" glrun 2028-06-01
grep -q 'the job on GitHub left no heartbeat at its scheduled run of 2028-05-01 (its last: 2027-08-05)' "$W/.out" && ! grep -q 'CHECK-IN' "$W/.out" \
  && ok "  ... 2028-05-01: GitHub runs after GitLab, so not yet today's; no second check-in this year" || bad "watchdog by the schedule"
MANUAL=1; expect 0 "a GitHub run by hand on a run date, before GitLab's 17:17 run: no false alarm about GitLab" arun "$K5" 2028-07-01 --kit kit5; MANUAL=
grep -q 'the job on GitLab is alive: its last heartbeat is from 2028-06-01' "$W/.out" && ok "  ... it looks at GitLab's run before today's" || bad "watch on a run by hand"
hasfile() { git -C "$1" cat-file -e "main:$2" 2>/dev/null; }
printf '2027-01-10 %s\n2027-02-09 %s\n2027-03-12 %s\n' "$(c 1)" "$(c 2)" "$(c 3)" > kit5/sc2/log.txt
git -C kit5 $GITC commit -qam three && git -C kit5 push -q origin HEAD:main
ROUNDNOW=1; expect 1 "  ... after a completed cancellation, GitLab never releases GitHub's half, even on the date" glrun 2032-03-01; ROUNDNOW=
hasfile pubE.git opening/key-for-GitHub.txt && bad "the half was released after a cancellation" || ok "  ... nothing released"
grep -q "CANCELLED: this job (on GitLab) will never open its copy. First make sure that both copies" "$W/.out" && grep -q "delete BOTH private repositories" "$W/.out" \
  && ok "  ... and it asks for both private repositories to be deleted" || bad "cancel text, two platforms"
printf '2027-01-10 %s\n2027-02-09 %s\n' "$(c 1)" "$(c 2)" > kit5/sc2/log.txt
git -C kit5 $GITC commit -qam two && git -C kit5 push -q origin HEAD:main
printf '2027-03-12 %s\n' "$(c 3)" >> kit5/sc2/log.txt && git -C kit5 $GITC commit -qam three-github-only && git -C kit5 push -q "$W/gh5.git" HEAD:main
git -C kit5 checkout -q HEAD~1 -- sc2/log.txt
ROUNDNOW=1; expect 1 "the third notice reached GitHub's copy only: GitLab's job counts it too, and stays cancelled" glrun 2032-03-01; ROUNDNOW=
grep -q '0 notice line(s) only here, 1 only on GitHub' "$W/.out" && grep -q 'CANCELLED' "$W/.out" && ! hasfile pubE.git opening/key-for-GitHub.txt \
  && ok "  ... the difference named, nothing released" || bad "logs differ"
: > kit5/sc2/log.txt && git -C kit5 $GITC commit -qam empty && git -C kit5 push -q origin HEAD:main
printf '2027-01-10 %s\n' "$(c 1)" > kit5/sc2/log.txt && git -C kit5 $GITC commit -qam one && git -C kit5 push -q "$W/gh5.git" HEAD:main
printf '2027-01-11 %s\n' "$(c 1)" > kit5/sc2/log.txt
ROUNDNOW=1; expect 1 "one code dated differently in the two copies: GitLab's job does not publish on a guess" glrun 2032-03-01; ROUNDNOW=
grep -q "is logged under more than one date (GitHub's copy: 2027-01-10; this copy: 2027-01-11)" "$W/.out" && grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" \
  && ! hasfile pubE.git opening/key-for-GitHub.txt && ok "  ... blocked, both dates named, nothing released" || bad "dates differ"
: > kit5/sc2/log.txt && git -C kit5 $GITC commit -qam empty-again && git -C kit5 push -q origin HEAD:main
printf '2027-01-10 %s\n2027-02-09 %s\n2027-02-20 %s\n' "$(c 1)" "$(c 2)" "$(cat certain.code)" > kit5/sc2/log.txt
git -C kit5 $GITC commit -qam certain && git -C kit5 push -q "$W/gh5.git" HEAD:main
printf '2027-01-10 %s\n2027-02-09 %s\n2027-03-11 %s\n' "$(c 1)" "$(c 2)" "$(c 3)" > kit5/sc2/log.txt
ROUNDNOW=1; expect 1 "this copy alone shows a cancellation, the two together do not (a release-certain code in the other): no publication" glrun 2032-03-01; ROUNDNOW=
grep -q 'this copy alone shows a completed cancellation' "$W/.out" && grep -q 'RELEASE DUE, NOT PUBLISHED' "$W/.out" \
  && ! hasfile pubE.git opening/key-for-GitHub.txt && ok "  ... blocked, nothing released" || bad "one copy alone cancels"
printf '2027-01-10 %s\n' "$(c 5)" > kit5/sc2/log.txt && git -C kit5 $GITC commit -qam forged && git -C kit5 push -q "$W/gh5.git" HEAD:main
: > kit5/sc2/log.txt
ROUNDNOW=1; expect 1 "a forged line in GitHub's copy only: GitLab's job blocks, and says which copy holds it" glrun 2032-03-01; ROUNDNOW=
grep -q "did not accept) -- it is only in GitHub's copy" "$W/.out" && ok "  ... GitHub's" || bad "line only in the other copy"
git -C kit5 $GITC commit -qam empty-3 && git -C kit5 push -q origin HEAD:main
ROUNDNOW=1; expect 1 "  ... before the date, GitLab does not release it either" glrun 2032-02-28; ROUNDNOW=
hasfile pubE.git opening/key-for-GitHub.txt && bad "the half was released early" || ok "  ... nothing released"
mv gh5.git gh5.off
ROUNDNOW=1; expect 1 "GitHub's copy of the log unreadable on the date: GitLab's job waits, and releases nothing" glrun 2032-03-01; ROUNDNOW=
grep -q 'RELEASE DUE, WAITING' "$W/.out" && grep -q 'waits until its scheduled run of 2032-04-01' "$W/.out" && ! hasfile pubE.git opening/key-for-GitHub.txt \
  && ok "  ... until its next run, 2032-04-01" || bad "wait for the other copy of the log"
GLSOURCE=web; ROUNDNOW=1; expect 1 "  ... a run by hand the next day waits too: the wait is counted in runs, not days" glrun 2032-03-02; ROUNDNOW=; GLSOURCE=
grep -q 'waits until its scheduled run of 2032-04-01' "$W/.out" && ! hasfile pubE.git opening/key-for-GitHub.txt && ok "  ... nothing released" || bad "wait, run by hand"
ROUNDNOW=1; expect 1 "  ... and so does a scheduled run that started after midnight (2032-03-02)" glrun 2032-03-02; ROUNDNOW=
grep -q 'RELEASE DUE, WAITING' "$W/.out" && ! hasfile pubE.git opening/key-for-GitHub.txt && ok "  ... nothing released" || bad "wait, delayed run"
cp -R pubE.git pubE.save
ROUNDNOW=1; expect 1 "  ... at that run it goes ahead on its own log: it releases GitHub's half (its own lock still shut)" glrun 2032-04-01; ROUNDNOW=
hasfile pubE.git opening/key-for-GitHub.txt && ok "  ... released: one run of waiting, never more" || bad "next run"
rm -rf pubE.git && cp -R pubE.save pubE.git
printf '2032-02-29 %s\n2032-03-31 %s\n' "$(c 1)" "$(c 2)" > kit5/sc2/log.txt
ROUNDNOW=1; expect 1 "a postponed release, due on 2032-05-02, with GitHub's copy unreadable: GitLab's job waits at its first run from that day" glrun 2032-06-01; ROUNDNOW=
grep -q 'waits until its scheduled run of 2032-07-01' "$W/.out" && ! hasfile pubE.git opening/key-for-GitHub.txt && ok "  ... until 2032-07-01, a month later" || bad "wait after a postponement"
ROUNDNOW=1; expect 1 "  ... and goes ahead at that run: it releases GitHub's half (its own lock still shut)" glrun 2032-07-01; ROUNDNOW=
hasfile pubE.git opening/key-for-GitHub.txt && ok "  ... released" || bad "going ahead after the wait"
git -C kit5 checkout -q -- sc2/log.txt
rm -rf pubE.git && mv pubE.save pubE.git && mv gh5.off gh5.git
ROUNDNOW=1; expect 1 "drand gone, on the date: GitHub's job cannot open its lock, and GitLab has not released its half yet" arun "$K5" 2032-03-01 --kit kit5; ROUNDNOW=
grep -q 'has not released its half yet' "$W/.out" && ! has pubE.git && ok "  ... red, nothing published" || bad "drand gone, before the half"
ROUNDNOW=1; expect 1 "  ... GitLab's job, which runs first on the date (17:17), releases the half (its own lock does not open either)" glrun 2032-03-01; ROUNDNOW=
hasfile pubE.git opening/key-for-GitHub.txt && ! has pubE.git && ok "  ... the half is in opening/, the record not yet" || bad "half not released"
ROUNDNOW=1; expect 0 "  ... and GitHub's job, at 21:17 the same day, drand still gone, opens its copy with that half and publishes" arun "$K5" 2032-03-01 --kit kit5; ROUNDNOW=
git -C pubE.git show main:opening/commitment.txt 2>/dev/null | cmp -s - commitment.txt && grep -q "drand did not open the lock; GitLab's released half did" "$W/.out" \
  && ok "  ... the record, byte for byte" || bad "publication with the released half"
git -C pubE.git show main:opening/RELEASE-NOTE-AUTOMATIC.txt > note5.txt 2>/dev/null
mv gh5.git gh5.off
expect 1 "  ... then GitLab's job, unable to read GitHub's copy of the log, sees the record published and does not wait" glrun 2032-03-01
grep -q 'Released already: every target holds the record' "$W/.out" && ! grep -q 'RELEASE DUE, WAITING' "$W/.out" && ok "  ... it says so" || bad "waiting after publication"
mv gh5.off gh5.git
grep -q '^GitHub\. Its public reference' note5.txt && grep -q "^author's other job, on GitLab, held and released once the release was due\.$" note5.txt \
  && grep -q '^moitié de clé que détenait l.autre tâche de l.auteur, sur GitLab, et qu.elle a$' note5.txt \
  && git -C pubE.git log --format=%s main | grep -q 'automatic opening, 2032-03-01, by the job on GitHub$' \
  && ok "  ... the note and the commit name the job that opened it, and say how" || bad "release note, platform"
git -C pubE.git show main:opening/key-for-GitHub.txt > half.txt 2>/dev/null
expect 0 "decrypt by hand with a released half, drand gone" env STUB_TLE_ROUND_NOW=1 python3 "$AR" decrypt --kit kit5 --key-file sec5/SC2_KEY --half-file half.txt -o opened5.txt
expect 0 "decrypt GitLab's copy with GitLab's key" env STUB_TLE_ROUND_NOW=$OPEN python3 "$AR" decrypt --kit kit5 --platform GitLab --key-file sec5/gitlab/SC2_KEY -o opened5g.txt
cmp -s opened5.txt commitment.txt && cmp -s opened5g.txt commitment.txt && ok "  ... both give the record" || bad "decrypt per platform"
expect 1 "GitHub's key does not open GitLab's copy" env STUB_TLE_ROUND_NOW=$OPEN python3 "$AR" decrypt --kit kit5 --platform GitLab --key-file sec5/SC2_KEY -o opened5x.txt
nrun() { env GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid \
         GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false python3 "$AR" notice --kit kit5 --today "${NTODAY:-2027-03-01}" "$@"; }
expect 0 "notice: logs a valid notice and pushes it to both private repositories" nrun 2027-01-10 "$(c 1)"
[ "$(git -C gh5.git show main:sc2/log.txt)" = "2027-01-10 $(c 1)" ] && [ "$(git -C gl5.git show main:sc2/log.txt)" = "2027-01-10 $(c 1)" ] \
  && grep -q 'every copy has it (2)' "$W/.out" && ok "  ... both copies hold the line, read back" || bad "notice push"
cp kit5/sc2/log.txt log5.before
expect 1 "notice refuses a code that is not the next valid one, and changes nothing" nrun 2027-02-09 "$(c 3)"
cmp -s kit5/sc2/log.txt log5.before && grep -q 'not the next valid one' "$W/.out" && ok "  ... the log is unchanged" || bad "notice, wrong code"
expect 1 "notice refuses a date after today" nrun 2027-03-02 "$(c 2)"
mv gl5.git gl5.off
expect 1 "notice with GitLab's copy out of reach: it names the copy that lacks the line" nrun 2027-02-09 "$(c 2)"
grep -qF "ok      $W/gh5.git has it" "$W/.out" && grep -qF "FAILED  $W/gl5.git does not have it" "$W/.out" && ok "  ... GitHub's has it, GitLab's FAILED" || bad "notice, one copy out of reach"
mv gl5.off gl5.git
expect 0 "  ... run again once it is back: the line is not added twice, and both copies have it" nrun 2027-02-09 "$(c 2)"
[ "$(grep -c "$(c 2)" kit5/sc2/log.txt)" -eq 1 ] && [ "$(git -C gl5.git show main:sc2/log.txt | wc -l | tr -d ' ')" -eq 2 ] && ok "  ... once, everywhere" || bad "notice retry"
expect 1 "notice refuses a date before the record was sealed (a mistyped year)" nrun 2017-02-09 "$(c 2)"
git -C kit5 switch -q -c other
expect 1 "notice refuses to run from a branch other than main" nrun 2027-02-09 "$(c 2)"
git -C kit5 switch -q main && git -C kit5 branch -q -D other
rm -rf elsewhere && git clone -q -b main "$W/gh5.git" elsewhere && git -C elsewhere $GITC commit -q --allow-empty -m "made elsewhere" && git -C elsewhere push -q origin HEAD:main
cp kit5/sc2/log.txt log5.before
NTODAY=2027-04-30; expect 1 "notice refuses while a copy has changes this working copy lacks (git pull first)" nrun 2027-04-30 "$(c 3)"; NTODAY=
cmp -s kit5/sc2/log.txt log5.before && grep -q 'git pull' "$W/.out" && ok "  ... and changes nothing" || bad "notice when behind"
git -C kit5 pull -q --ff-only origin main
git -C kit5 push -q "$W/gl5.git" HEAD:main
rm -rf elsewhere2 && git clone -q -b main "$W/gl5.git" elsewhere2 && git -C elsewhere2 $GITC commit -q --allow-empty -m "made on GitLab" && git -C elsewhere2 push -q origin HEAD:main
NTODAY=2027-04-30; expect 1 "notice refuses while GitLab's copy has changes the working copy lacks, giving the pull command for that copy" nrun 2027-04-30 "$(c 3)"; NTODAY=
grep -qF "git pull --ff-only $W/gl5.git main" "$W/.out" && ok "  ... the exact command" || bad "notice, GitLab ahead"
git -C kit5 pull -q --ff-only "$W/gl5.git" main
printf '2017-01-10 %s\n' "$(c 1)" >> kit5/sc2/log.txt && git -C kit5 $GITC commit -qam typo
NTODAY=2027-04-30; expect 1 "notice refuses to log onto a log the jobs would not act on (a mistyped year above)" nrun 2027-04-30 "$(c 3)"; NTODAY=
grep -q 'the jobs would not act on the log' "$W/.out" && grep -q 'before the record was even sealed' "$W/.out" && ok "  ... and says what to fix" || bad "notice on a blocked log"
grep -v '^2017-' kit5/sc2/log.txt > log.tmp && cat log.tmp > kit5/sc2/log.txt && git -C kit5 $GITC commit -qam "typo removed"
git -C kit5 remote set-url --delete --push origin "$W/gl5.git"
expect 1 "notice when GitLab's copy is missing from the push addresses: it says so" nrun 2027-02-09 "$(c 2)"
grep -q "MISSING GitLab's" "$W/.out" && ok "  ... MISSING, by name" || bad "notice, a missing push address"
git -C kit5 remote set-url --add --push origin "$W/gl5.git"
git init -q --bare "$W/extra5.git" && git -C kit5 remote set-url --add --push origin "$W/extra5.git"
mv gh5.git gh5.off; mv gl5.git gl5.off
expect 1 "notice when neither private copy can be reached (an extra address can): it says that no copy has it" nrun 2027-02-09 "$(c 2)"
grep -q 'NO copy has this notice yet' "$W/.out" && ok "  ... plainly" || bad "notice, nothing reachable"
mv gh5.off gh5.git; mv gl5.off gl5.git; git -C kit5 remote set-url --delete --push origin "$W/extra5.git"
NTODAY=2027-04-30; expect 0 "notice of a code 80 days after the previous one: logged, with a warning that it starts a new series" nrun 2027-04-30 "$(c 3)"; NTODAY=
grep -q 'STARTS A NEW SERIES: it came 80 days after' "$W/.out" && grep -q 'every copy has it (2)' "$W/.out" && ok "  ... warned, and both copies have it" || bad "new series warning"
python3 -c "t=open('kit5/sc2/log.txt').read();open('kit5/sc2/log.txt','wb').write(t.replace(chr(10), chr(13)+chr(10)).encode('utf-16'))"
git -C kit5 $GITC commit -qam utf16 && git -C kit5 push -q origin HEAD:main
NTODAY=2027-05-30; expect 0 "notice on a log saved as UTF-16 (PowerShell): it logs the next notice" nrun 2027-05-30 "$(c 4)"; NTODAY=
NTODAY=2027-06-30; expect 0 "  ... and the third of the new series: CANCELLED, with what to delete" nrun 2027-06-30 "$(c 5)"; NTODAY=
grep -q 'CANCELLED: the jobs will never open their copies' "$W/.out" && grep -q 'BOTH private repositories' "$W/.out" && ok "  ... said to the author" || bad "notice, cancelled"
same "  ... and the custodian's check reads the same file as a cancellation" "$(python3 "$HERE/sc2-release.py" check --start "$START" --certain "$CERT" --release 2032-03-01 --today 2032-03-01 kit5/sc2/log.txt >/dev/null 2>&1; echo $?)" 10
expect 1 "notice run outside the working copy says where to run it" python3 "$AR" notice --kit "$W/op5" 2027-01-10 "$(c 1)"
expect 0 "--no-peer-key: two schedulers, no shared half" python3 "$AR" make --opening-repo "$W/pubA.git" $MK --out kit7 --secrets sec7 --opening op7 --gitlab --no-peer-key \
  --private-repo "$W/gh7.git" --gitlab-repo "$W/gl7.git"
[ ! -e sec7/gitlab/SC2_PEER_KEY ] && python3 -c "import json,sys;c=json.load(open('kit7/sc2/config.json'));sys.exit(c['peer'] is not None)" \
  && ! grep -q SC2_PEER_KEY sec7/SETUP.txt && ok "  ... nothing in the secrets, config.json or SETUP.txt" || bad "--no-peer-key"
python3 - "$HERE" <<'PY2' > ar.out 2>&1 && ok "the custodian's local date without the runner's time zone data: from the table in config.json" || { bad "time zone table"; cat ar.out; }
import datetime, importlib.util, json, sys
from zoneinfo import ZoneInfo
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
table = json.load(open("kit1/sc2/config.json"))["tz_offsets"]
assert {60, 120} <= {m for _, m in table}, table[:4]
assert ar.local_today("No/Such_Zone", table) == datetime.datetime.now(ZoneInfo("Europe/Paris")).date()
t2 = ar.tz_table("Europe/Paris", datetime.date(2032, 2, 20), datetime.date(2032, 4, 10))
assert t2 == [["2032-02-20", 60], ["2032-03-28", 120]], t2
PY2
python3 - "$HERE" <<'PY2' > ar.out 2>&1 && ok "the schedule: for every release date of a year, the release date's day of every month (the last day of shorter months), and a run within 32 days of every day a postponed release can fall on, for any window" || { bad "run dates"; cat ar.out; }
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
for i in range(366):
    R = dt.date(2032, 1, 1) + dt.timedelta(days=i)
    ds = ar.run_dates(R)
    assert ds[1] == R and all(a < b for a, b in zip(ds[:12], ds[1:12])) and len({(d.month, d.day) for d in ds}) == len(ds), (R, ds)
    assert sorted({d.month for d in ds}) == list(range(1, 13)) and len(ds) == (13 if (R.month, R.day) == (2, 29) else 12), (R, ds)
    for d in ds:
        last = 28 if d.month == 2 else (dt.date(2001 + d.month // 12, d.month % 12 + 1, 1) - dt.timedelta(days=1)).day
        assert d.day == min(R.day, last) or d == R, (R, d)
    cfg = {"runs": [d.isoformat() for d in ds], "made": "2026-10-08", "release": R.isoformat()}
    for hi in (1, 8, 31, 100, 365):
        last = R + dt.timedelta(days=2 * hi)                 # the latest day a series running on R can move it to
        s = ar.scheduled(cfg, R, last + dt.timedelta(days=35))
        assert s[0] == R and s[-1] >= last and all((b - a).days <= 32 for a, b in zip(s, s[1:])), (R, hi, s)   # 28 Feb to 31 Mar
PY2
python3 - "$HERE" <<'PY2' > ar.out 2>&1 && ok "GitHub's UTC lines, in every year of a kit's life and any time zone: one run on each run date, at its local time give or take summer time; the only other day is 29 (or 28) February in the far west, and the kit names it" || { bad "UTC lines"; cat ar.out; }
import datetime as dt, importlib.util, sys
from zoneinfo import ZoneInfo
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
leap = lambda y: ar.on_day(y, dt.date(2000, 2, 29)) is not None
for i in range(366):
    R = dt.date(2032, 1, 1) + dt.timedelta(days=i)
    ds, yrs = ar.run_dates(R), ar.kit_years(dt.date(2026, 10, 8), R)
    want = {(d.month, d.day) for d in ds}
    for tz in ("Europe/Paris", "America/New_York", "America/Los_Angeles", "America/St_Johns", "Pacific/Kiritimati",
               "Pacific/Pago_Pago", "Asia/Kolkata", "Australia/Lord_Howe"):
        z = ZoneInfo(tz)
        for hm in ((17, 17), (21, 17)):
            cr = ar.github_crons(ds, tz, hm, yrs)
            fired = {}
            for y in range(yrs[0] - 1, yrs[-1] + 2):
                for c, _, _ in cr:
                    f = c.split()
                    for mo in (int(x) for x in f[3].split(",")):
                        try:
                            t = dt.datetime(y, mo, int(f[2]), int(f[1]), int(f[0]), tzinfo=dt.timezone.utc).astimezone(z)
                        except ValueError:                  # 29 February outside a leap year
                            continue
                        fired.setdefault(t.date(), []).append(t)
            for y in yrs:
                for d in ds:
                    day = ar.on_day(y, d)
                    if day:
                        ts = fired.get(day, [])
                        assert len(ts) == 1 and abs(ts[0].hour * 60 + ts[0].minute - hm[0] * 60 - hm[1]) <= 60, (tz, hm, R, day, ts)
            extra = {(t.month, t.day, leap(t.year)) for t in fired if yrs[0] <= t.year <= yrs[-1] and (t.month, t.day) not in want}
            assert extra <= {(2, 29, True), (2, 28, False)}, (tz, hm, R, extra)
            assert bool(ar.github_also(cr, ds, tz, yrs)) == bool(extra), (tz, hm, R, extra)
PY2
python3 - "$HERE" <<'PY2' > ar.out 2>&1 && ok "the watch, the wait, the heartbeats and the check-in follow the schedule: a run by hand, a delayed run, a dropped run, any window" || { bad "schedule rules"; cat ar.out; }
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
D = dt.date
assert ar.run_times(["GitHub", "GitLab"]) == {"GitLab": (17, 17), "GitHub": (21, 17)} and ar.run_times(["GitHub"]) == {"GitHub": (17, 17)}
assert ar.gitlab_crons(ar.run_dates(D(2032, 3, 1)), (17, 17)) == ["17 17 1 * *"]
assert ar.gitlab_crons(ar.run_dates(D(2032, 3, 31)), (17, 17)) == ["17 17 31 1,3,5,7,8,10,12 *", "17 17 30 4,6,9,11 *", "17 17 28 2 *"]
assert ar.gitlab_crons(ar.run_dates(D(2032, 2, 29)), (17, 17)) == ["17 17 29 * *", "17 17 28 2 *"]
assert ar.run_words(ar.run_dates(D(2032, 3, 1))) == "the 1st of every month"
assert ar.run_words(ar.run_dates(D(2032, 3, 31))) == "the 31st of every month (the 30th in April, June, September and November; the 28th in February)"
assert ar.run_words(ar.run_dates(D(2032, 2, 29))) == "the 29th of every month, and the 28th of February"
cfg = {"runs": [d.isoformat() for d in ar.run_dates(D(2032, 3, 1))], "made": "2026-10-08", "release": "2032-03-01",
       "run_at": {"GitLab": "17:17", "GitHub": "21:17"}}
assert ar.last_expected(cfg, "GitHub", "GitLab", D(2032, 3, 1)) == D(2032, 2, 1)
assert ar.last_expected(cfg, "GitLab", "GitHub", D(2032, 3, 1)) == D(2032, 3, 1)
assert ar.last_expected(cfg, "GitLab", "GitHub", D(2032, 3, 1), manual=True) == D(2032, 2, 1)   # by hand, maybe before GitLab's run
assert ar.last_expected(cfg, "GitHub", "GitLab", D(2027, 1, 15)) == D(2027, 1, 1)
assert ar.last_expected(cfg, "GitHub", "GitLab", D(2026, 10, 20)) is None            # no run yet since the kit was made
import os; os.environ["SC2_PLATFORM"] = "GitHub"
cfg2 = dict(cfg, platforms=["GitHub", "GitLab"])
assert not ar.speaks(cfg2, {}, set()) and ar.speaks(cfg2, {}, {"GitLab"}) and ar.speaks(cfg2, None, set())   # GitLab runs first
os.environ["SC2_PLATFORM"] = "GitLab"; assert ar.speaks(cfg2, {}, set())
cr = ar.github_crons(ar.run_dates(D(2032, 2, 29)), "America/New_York", (21, 17), ar.kit_years(D(2026, 10, 8), D(2032, 2, 29)))
notes = {c: n for c, _, n in cr}
assert notes["17 2 1 3 *"] == " (also the run of 28 February in other years)" and notes["17 2 29 2 *"] == " (in leap years)", notes
assert ar.wait_until(cfg, D(2032, 3, 1)) == D(2032, 4, 1) and ar.wait_until(cfg, D(2032, 3, 2)) == D(2032, 5, 1)
assert ar.wait_until(cfg, D(2032, 5, 2)) == D(2032, 7, 1) and ar.wait_until(cfg, D(2032, 6, 1)) == D(2032, 7, 1)
for R in (D(2032, 3, 31), D(2032, 1, 29), D(2032, 3, 1), D(2032, 12, 31), D(2032, 2, 29), D(2032, 8, 30)):
    cw = {"runs": [d.isoformat() for d in ar.run_dates(R)], "made": "2026-10-08", "release": R.isoformat()}
    for k in range(0, 731):                            # a due day anywhere in the next two years
        E = R + dt.timedelta(days=k)
        w, s0 = ar.wait_until(cw, E), ar.scheduled(cw, E, E + dt.timedelta(days=400))[0]
        assert w is not None and 25 <= (w - s0).days <= ar.WAIT_NEXT, (R, E, s0, w)
c31 = {"runs": [d.isoformat() for d in ar.run_dates(D(2032, 3, 31))], "made": "2026-10-08", "release": "2032-03-31"}
assert ar.beat_due(c31, {"GitHub": D(2027, 4, 1)}, "GitHub", D(2027, 4, 30))      # 31 March's run, delayed to 1 April
assert not ar.beat_due(c31, {"GitHub": D(2027, 4, 1)}, "GitHub", D(2027, 4, 2))
assert not ar.beat_due(c31, {"GitHub": D(2027, 4, 30)}, "GitHub", D(2027, 4, 30))
assert ar.beat_due(c31, {}, "GitHub", D(2027, 1, 5)) and ar.beat_due(c31, None, "GitHub", D(2027, 1, 5))
assert ar.next_run(ar.run_dates(D(2032, 3, 1)), D(2026, 10, 8)) == D(2026, 11, 1)
assert ar.next_run(ar.run_dates(D(2032, 3, 1)), D(2027, 3, 15)) == D(2027, 4, 1)
for R in (D(2032, 3, 1), D(2032, 3, 31), D(2031, 12, 15)):   # GitLab runs first, GitHub stands in when GitLab missed
    cw = {"runs": [d.isoformat() for d in ar.run_dates(R)], "made": "2026-10-08", "release": R.isoformat()}
    c0 = ar.run_dates(R)[0]                                     # the check-in's day: a month before the release date's
    for drop in (None, D(2028, c0.month, c0.day)):
        hb, sent = {}, []
        for day in ar.scheduled(cw, D(2026, 10, 9), D(2030, 12, 31)):
            for plat in ("GitLab", "GitHub"):
                if plat == "GitLab" and day == drop:
                    continue
                speaker = plat == "GitLab" or hb.get("GitLab", D.min) < day
                if ar.beat_due(cw, hb, plat, day):
                    if speaker and ar.checkin_due(cw, hb, day):
                        sent.append((day, plat))
                    hb[plat] = day
        first = ar.scheduled(cw, D(2026, 10, 9), D(2027, 12, 31))[0]      # the first run after setup: a check-in too
        want = sorted({first} | {d for d in (D(y, c0.month, c0.day) for y in range(2026, 2031)) if d > D(2026, 10, 8)})
        assert [d for d, _ in sent] == want, (R, drop, sent)
        assert [p for _, p in sent] == ["GitHub" if d == drop else "GitLab" for d in want], (R, drop, sent)
PY2
python3 - "$HERE" "$W" <<'PY2' > ar.out 2>&1 && ok "heartbeats that cannot be read turn the run red: it leaves none and sends no check-in" || { bad "unreadable heartbeats"; cat ar.out; }
import datetime as dt, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
rel = ar.sibling("sc2_release", "sc2-release.py")
os.chdir(sys.argv[2])
base = "kit1/sc2"; cfg = json.load(open(base + "/config.json")); cfg["_title"] = base + "/commitment-title.txt"
os.environ.update(SC2_KEY=open("sec1/SC2_KEY").read().strip(), STUB_TLE_ROUND_NOW="999999999999", SC2_PLATFORM="GitHub")
os.environ.pop("GITHUB_EVENT_NAME", None)
n0 = os.popen("git -C pubA.git rev-list --count main").read()
ar.heartbeats = lambda *a: None
problems = []
beat, hb, missed = ar.health(cfg, base, problems, True, rel, dt.date(2033, 2, 1), True)
assert not beat and hb is None and any("could not be read" in p for p in problems), (beat, hb, problems)
assert os.popen("git -C pubA.git rev-list --count main").read() == n0
PY2
python3 - "$HERE" "$W" <<'PY2' > ar.out 2>&1 && ok "a read of a repository that fails is tried again 20 seconds later, and succeeds" || { bad "fetch retry"; cat ar.out; }
import importlib.util, subprocess, sys, tempfile, threading, time
spec = importlib.util.spec_from_file_location("ar", sys.argv[1] + "/sc2-autorelease.py"); ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
src, late = sys.argv[2] + "/pubA.git", sys.argv[2] + "/late.git"
threading.Timer(3, lambda: subprocess.run(["git", "clone", "-q", "--bare", src, late], check=True)).start()
d = tempfile.mkdtemp(); ar.git_init(d)
t0 = time.time(); rc, err = ar.fetch(late, "refs/heads/main", d, depth=1)
assert rc == 0 and 15 < time.time() - t0 < 90, (rc, err, time.time() - t0)
PY2
unset SC2_TLE
rm -rf srv runner kit*/sc2/tools/tle-linux-* kit*/.git gh5.git gl5.git rehearsal*-repo/sc2/tools/tle-linux-* paris/k/sc2/tools/tle-linux-* ny/k/sc2/tools/tle-linux-* late.git   # 27 MB per kit copy
fi

echo "-- 13. your own release, at any time, with a cooling-off delay (sc2-disclose.py)"
DS="$HERE/sc2-disclose.py"
ZG="-c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false"
CASE=$(sed -n '1s#^SC2/\([0-9A-F]\{10\}\).*#\1#p' commitment-reference.txt)
dsrun() { env GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid \
          GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false python3 "$DS" "$@"; }
# The clock cannot be moved here; the request's times are, as if this many minutes had passed since the wait ended
# (or, with a second argument, as if the day to confirm ended that many seconds from now).
waited() { python3 - "$1" "${2:-}" <<'PY'
import datetime as dt, json, sys
r = json.load(open("sc2-release-request.json"))
t = dt.datetime.now(dt.timezone.utc)
nb = t - dt.timedelta(minutes=int(sys.argv[1]))
r["not_before"] = nb.isoformat()
r["not_after"] = (t + dt.timedelta(seconds=int(sys.argv[2])) if sys.argv[2] else nb + dt.timedelta(hours=24)).isoformat()
json.dump(r, open("sc2-release-request.json", "w"))
PY
}
zrepo() { git init -q --bare "$W/$1.git" && rm -rf zseed && git init -q zseed && cp commitment-reference.txt commitment-title.txt zseed/ \
          && (cd zseed && git add -A && git $ZG commit -q -m seed && git push -q "$W/$1.git" HEAD:refs/heads/main) && rm -rf zseed \
          && rm -rf "$1" && git clone -q -b main "$W/$1.git" "$1"; }
zhas() { git -C "$W/$1.git" cat-file -e main:opening/commitment.txt 2>/dev/null; }
zclosed() { python3 -c "import json,sys; sys.exit(0 if json.load(open('sc2-release-request.json')).get('closed') else 1)" 2>/dev/null; }
zrepo pubZ
printf 'release SC2/%s now\n' "$CASE" > ds-yes.txt && printf 'release it\n' > ds-no.txt && rm -f sc2-release-request.json
expect 1 "release: start refuses a file that is not the record" dsrun start --file commitment-title.txt
[ ! -e sc2-release-request.json ] && ok "  ... and records nothing" || bad "start recorded a request for the wrong file"
expect 1 "  ... and a wait of less than an hour" dsrun start --hours 0
expect 0 "start checks the record and records the time; nothing is published" dsrun start
grep -q 'Nothing was published' "$W/.out" && [ -s sc2-release-request.json ] && ! zhas pubZ && ok "  ... nothing" || bad "start"
expect 1 "  ... a second start while the first is open is refused" dsrun start
expect 1 "confirm at once: too early, nothing published" dsrun confirm --repo pubZ < ds-yes.txt
grep -q 'Too early: the wait ends at' "$W/.out" && ! zhas pubZ && ok "  ... it says when the wait ends" || bad "confirm too early"
waited 1
expect 1 "after the wait, the wrong sentence publishes nothing, and the request stays open" dsrun confirm --repo pubZ < ds-no.txt
grep -q 'Not published' "$W/.out" && ! zhas pubZ && [ -s sc2-release-request.json ] && ok "  ... nothing published" || bad "wrong sentence"
expect 1 "  ... and so does no input at all (closed)" dsrun confirm --repo pubZ <&-
grep -q 'Not published by this command' "$W/.out" && ! grep -q Traceback "$W/.out" && ! zhas pubZ && ok "  ... no error dump" || bad "closed input"
expect 0 "the right sentence publishes the record and a note, reads the record back, and closes the request, kept as the list of pushes" dsrun confirm --repo pubZ --no-archive < ds-yes.txt
git -C pubZ.git show main:opening/commitment.txt 2>/dev/null | cmp -s - commitment.txt \
  && git -C pubZ.git show main:opening/RELEASE-NOTE-AUTHOR.txt 2>/dev/null | grep -q "^RELEASE OF SEALED RECORD SC2/$CASE BY ITS AUTHOR$" \
  && zclosed && git -C pubZ.git log -1 --format='%an %ad %s' --date=format:%z main | grep -q "^t +0000 SC2/$CASE: released by its author, " \
  && [ "$(git -C pubZ log -1 --format=%H)" = "$(git -C pubZ.git rev-parse main)" ] \
  && ok "  ... byte for byte, with the note, in your own name, dated in UTC; your clone brought up to date after" || bad "release"
git -C pubZ.git show main:opening/commitment.txt > zgot.txt 2>/dev/null
expect 0 "  ... and it verifies with sc2-verify.py" python3 "$HERE/sc2-verify.py" zgot.txt "$(cat commitment-reference.txt)"
git -C pubZ.git show main:opening/RELEASE-NOTE-AUTHOR.txt 2>/dev/null > znote.txt
mkdir -p znote/opening && cp commitment-reference.txt znote/ && cp zgot.txt znote/opening/commitment.txt
sed -n 's/^  \(.*openssl dgst.*\)$/\1/p; s/^  \(sha512sum [^ ]*\) .*$/\1/p' znote.txt > znote.sh
command -v sha512sum >/dev/null 2>&1 || sed -i.bak 's/^sha512sum /shasum -a 512 /' znote.sh
[ "$(wc -l < znote.sh)" -eq 5 ] && (cd znote && sh ../znote.sh) | grep -o '[0-9a-f]\{128\}' > znote.out \
  && [ "$(sed -n 4p znote.out)" = "$(S512 commitment.txt)" ] && grep -q "$(sed -n 5p znote.out)" commitment-title.txt \
  && ok "  ... the note's own five commands, run as printed, give the record's digests and the short form" || bad "the note's commands"
expect 0 "  ... afterwards, no request is open; cancel and status say where the record went" dsrun cancel
grep -q 'No release request is open here: the last one, made at .*, was released at .*ALREADY PUSHED to: .*pubZ.git' "$W/.out"; z1=$?
dsrun confirm --repo pubZ < ds-yes.txt > "$W/.out" 2>&1; z2=$?
[ "$z1" = 0 ] && [ "$z2" = 1 ] && grep -q 'No release request is open here.*ALREADY PUSHED to: .*pubZ.git' "$W/.out" && zclosed \
  && ok "  ... and confirm refuses, saying the same, not that nothing was published" || bad "after a release"
dsrun start > "$W/.out" 2>&1; waited 1
grep -q 'Nothing more was published. The record was ALREADY PUSHED to: .*pubZ.git' "$W/.out" && ok "  ... and so does a new start" || bad "start after a release"
n0=$(git -C pubZ.git rev-list --count main)
expect 0 "confirm on a repository that already holds the record adds nothing" dsrun confirm --repo pubZ --no-archive < ds-yes.txt
[ "$(git -C pubZ.git rev-list --count main)" = "$n0" ] && grep -q 'already holds the record' "$W/.out" && ok "  ... no second commit" || bad "release twice"
printf '{"format": "SC2-RELEASE-REQUEST-1", "case": "0123456789", "sha512": "00", "requested": "2026-01-01T00:00:00+00:00", "not_before": "2026-01-01T01:00:00+00:00", "not_after": "2026-01-02T01:00:00+00:00", "published": ["https://github.com/me/old-public.git"], "unsure": [], "closed": "2026-01-01T02:00:00+00:00", "how": "released"}\n' > sc2-release-request.json
expect 1 "start beside another record's closed request refuses, instead of claiming that record's pushes as this one's" dsrun start
grep -q 'is the request of another record, SC2/0123456789. Move it elsewhere' "$W/.out" && ! grep -q 'ALREADY PUSHED' "$W/.out" && ok "  ... said" || bad "another record's request"
rm -f sc2-release-request.json                          # what follows starts with nothing published
expect 1 "with no request file at all, confirm says that this command published nothing, not that nothing was" dsrun confirm --repo pubZ < ds-yes.txt
grep -q 'This command published nothing' "$W/.out" && (cd pubZ && dsrun status > /dev/null 2>&1) && [ -z "$(git -C pubZ status --porcelain)" ] \
  && [ ! -e sc2-disclose.lock ] && [ ! -e pubZ/sc2-disclose.lock ] && ok "  ... and no command leaves a file for its lock, here or in a clone where it was run by mistake" || bad "no request file, or a lock file left"
dsrun start > /dev/null 2>&1; waited 1500
expect 1 "a request not confirmed within the day after the wait lapses" dsrun confirm --repo pubZ < ds-yes.txt
grep -q 'lapsed' "$W/.out" && ok "  ... it says so" || bad "lapsed request"
expect 0 "  ... and cancel drops it" dsrun cancel
[ ! -e sc2-release-request.json ] && grep -q 'Nothing was published' "$W/.out" && ok "  ... gone" || bad "cancel"
zrepo pubY && mkdir -p pubY/opening && printf 'something else\n' > pubY/opening/commitment.txt && git -C pubY add -A && git -C pubY $ZG commit -q -m other && git -C pubY push -q
zrepo pubK && mkdir -p pubK/sc2 && printf '{}\n' > pubK/sc2/config.json && git -C pubK add -A && git -C pubK $ZG commit -q -m kit && git -C pubK push -q
zrepo pubP && git init -q --bare "$W/elsewhere.git" && git -C pubP remote set-url --add --push origin "$W/pubP.git" && git -C pubP remote set-url --add --push origin "$W/elsewhere.git"
zrepo pubT && mkdir -p nohome
zrepo pubV
dsrun start > /dev/null 2>&1; waited 1
expect 1 "refused, nothing published anywhere: a repository holding another opening/commitment.txt" dsrun confirm --repo pubV --repo pubY < ds-yes.txt
grep -q 'not this record' "$W/.out" && ! zhas pubV && ok "  ... named; the other repository untouched too" || bad "another record"
expect 1 "  ... the working copy of your private automated-release repository" dsrun confirm --repo pubK < ds-yes.txt
grep -q 'PRIVATE' "$W/.out" && ! zhas pubK && ok "  ... nothing published" || bad "private kit refused"
expect 1 "  ... a clone that pushes somewhere besides where it reads, which you might not see" dsrun confirm --repo pubP < ds-yes.txt
grep -q 'not only to' "$W/.out" && ! zhas pubP && ! git -C elsewhere.git cat-file -e main:opening/commitment.txt 2>/dev/null && ok "  ... nothing published" || bad "push address"
expect 1 "  ... git not knowing your name and e-mail, so that it could not commit" \
  env HOME="$W/nohome" XDG_CONFIG_HOME="$W/nohome" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.useConfigOnly \
  GIT_CONFIG_VALUE_0=true python3 "$DS" confirm --repo pubT < ds-yes.txt
grep -q 'does not know your name and e-mail' "$W/.out" && ! zhas pubT && [ -z "$(git -C pubT status --porcelain)" ] \
  && ok "  ... with the commands to set them; the clone untouched" || bad "no git identity"
expect 1 "  ... a folder that is not a git working copy" dsrun confirm --repo "$W/nowhere" < ds-yes.txt
dsrun cancel > /dev/null 2>&1
zrepo pubX && rm -rf zelse && git clone -q -b main "$W/pubX.git" zelse && git -C zelse $ZG commit -q --allow-empty -m "made elsewhere" && git -C zelse push -q
git -C pubX $ZG commit -q --allow-empty -m "a draft of yours, not pushed"
git -C pubX config push.followTags true && git -C pubX $ZG tag -a private-draft -m "my private notes"
mkdir -p pubX/.git/info && printf '*.txt filter=demo\n' > pubX/.git/info/attributes && git -C pubX config filter.demo.clean 'head -c 100'
dsrun start > /dev/null 2>&1; waited 1
expect 0 "a clone behind its repository, with a commit and a tag of yours not pushed, and a filter that would alter the file: released" \
  dsrun confirm --repo pubX --repo pubX/ --no-archive < ds-yes.txt
git -C pubX.git show main:opening/commitment.txt | cmp -s - commitment.txt && [ "$(git -C pubX.git log -2 --format=%s main | tail -1)" = "made elsewhere" ] \
  && ! git -C pubX.git log --format=%s main | grep -q 'a draft of yours' && [ -z "$(git -C pubX.git tag)" ] && [ "$(grep -o 'published and read back' "$W/.out" | wc -l)" -eq 1 ] \
  && grep -q 'git -C .*pull' "$W/.out" && ok "  ... on top of the change made elsewhere; your draft, your tag and the filter left out; once for one repository named twice" || bad "the release commit alone"
zrepo dsD && rm -rf dsD2 && git clone -q -b main "$W/dsD.git" dsD2 && dsrun start > /dev/null 2>&1; waited 1
expect 0 "two clones of one repository: the first publishes, the second finds the record there and adds nothing" dsrun confirm --repo dsD --repo dsD2 --no-archive < ds-yes.txt
[ "$(git -C dsD.git rev-list --count main)" = 2 ] && [ "$(grep -c 'published and read back' "$W/.out")" = 1 ] && [ "$(grep -c 'already holds the record' "$W/.out")" = 1 ] \
  && ok "  ... one release commit" || bad "two clones of one repository"
if [ "$(id -u)" != 0 ]; then
  zrepo pubU && zrepo pubS && dsrun start > /dev/null 2>&1; waited 1
  chmod -R a-w "$W/pubU.git"
  expect 1 "a push refused (a repository read-only for a while): the others still published, that one named" dsrun confirm --repo pubS --repo pubU --no-archive < ds-yes.txt
  chmod -R u+w "$W/pubU.git"
  grep -q 'your clone is as it was' "$W/.out" && zhas pubS && ! zhas pubU && [ -z "$(git -C pubU log --format=%s origin/main..HEAD)" ] \
    && ! git -C pubU cat-file -e "$(git hash-object commitment.txt)" 2>/dev/null && [ -s sc2-release-request.json ] \
    && ok "  ... nothing left behind in its clone, not even in .git; the request still open" || bad "push refused"
  expect 0 "  ... status says where it is already public" dsrun status
  grep -q 'ALREADY PUSHED to: .*pubS.git' "$W/.out" && ok "  ... named" || bad "status after a partial release"
  waited -5
  expect 1 "  ... and so does a confirm made too early, refused, or given the wrong sentence, instead of saying nothing was published" dsrun confirm --repo pubS --repo pubU < ds-yes.txt
  grep -q 'ALREADY PUSHED to: .*pubS.git' "$W/.out" && ! grep -q 'Nothing was published' "$W/.out"; z1=$?
  waited 1
  dsrun confirm --repo pubS --repo "$W/nowhere" < ds-yes.txt > "$W/.out" 2>&1
  grep -q 'Nothing more was published. The record was ALREADY PUSHED to: .*pubS.git' "$W/.out"; z2=$?
  dsrun confirm --repo pubS --repo pubU < ds-no.txt > "$W/.out" 2>&1
  [ "$z1" = 0 ] && [ "$z2" = 0 ] && grep -q 'Not published by this command: that is not the sentence. The record was ALREADY PUSHED to: .*pubS.git.*The request stays open until' "$W/.out" \
    && ok "  ... named each time" || bad "a refusal after a partial release"
  rm -rf zelse2 && git clone -q -b main "$W/pubU.git" zelse2 && git -C zelse2 $ZG commit -q --allow-empty -m "a heartbeat meanwhile" && git -C zelse2 push -q
  expect 0 "  ... run again after a heartbeat came meanwhile: the release goes on top of it" dsrun confirm --repo pubS --repo pubU --no-archive < ds-yes.txt
  zhas pubU && [ "$(git -C pubU.git rev-list --count main)" = 3 ] && ok "  ... published, one release commit" || bad "release after a refused push"
else ok "run as root: a read-only repository cannot be simulated"; fi
zrepo pubL && dsrun start > /dev/null 2>&1; waited 1 2
dslate() { (sleep 4; cat ds-yes.txt) | dsrun confirm "$@"; }
expect 1 "the sentence typed after the day to confirm ended: refused, nothing published" dslate --repo pubL --no-archive
grep -q 'while the sentence was being typed' "$W/.out" && ! zhas pubL && ok "  ... the window is checked again after the sentence" || bad "window after the sentence"
dsrun cancel > /dev/null 2>&1
printf '[1, 2]\n' > sc2-release-request.json
expect 1 "a request file that is not one: a plain message, no crash" dsrun status
grep -q 'cannot be read' "$W/.out" && ! grep -q Traceback "$W/.out" && ok "  ... delete it, then start again" || bad "bad request file"
rm -f sc2-release-request.json
expect 1 "  ... and a wait of more than a year is refused plainly" dsrun start --hours 100000000
! grep -q Traceback "$W/.out" && ok "  ... no crash" || bad "huge wait"
zrepo pubM && printf 'notes\n' > pubM/notes.txt && git -C pubM add notes.txt && git -C pubM $ZG commit -q -m notes && git -C pubM push -q
rm -rf zelse3 && git clone -q -b main "$W/pubM.git" zelse3 && printf 'notes, edited elsewhere\n' > zelse3/notes.txt && git -C zelse3 $ZG commit -qam edited && git -C zelse3 push -q
printf 'my own unfinished edit\n' > pubM/notes.txt && git -C pubM config merge.autoStash true
dsrun start > /dev/null 2>&1; waited 1
python3 -c "import json;p='sc2-release-request.json';r=json.load(open(p));del r['published'];json.dump(r,open(p,'w'))"
expect 0 "your uncommitted work in the clone (and git's auto-stash on), and a request file without its list of repositories: released" dsrun confirm --repo pubM --no-archive < ds-yes.txt
zhas pubM && [ "$(cat pubM/notes.txt)" = "my own unfinished edit" ] && [ -z "$(git -C pubM stash list)" ] && grep -q 'git -C .*pull' "$W/.out" \
  && ok "  ... your edit untouched, no stash made; it tells you to pull" || bad "uncommitted work"
git init -q --bare "$W/zz/real.git" 2>/dev/null || { mkdir -p "$W/zz" && git init -q --bare "$W/zz/real.git"; }
mkdir -p "$W/other" && git init -q --bare "$W/other/real.git"
rm -rf zseed && git init -q zseed && cp commitment-reference.txt zseed/ && git -C zseed add -A && git -C zseed $ZG commit -q -m seed && git -C zseed push -q "$W/zz/real.git" HEAD:refs/heads/main && git -C zseed push -q "$W/other/real.git" HEAD:refs/heads/main && rm -rf zseed
rm -rf zr && git -c "url.$W/zz/.insteadOf=alias:" clone -q -b main alias:real.git zr && git -C zr config "url.$W/zz/.insteadOf" alias: && git -C zr config "url.$W/other/.pushInsteadOf" "$W/zz/"
dsrun start > /dev/null 2>&1; waited 1
expect 0 "a clone whose address goes through rewrite rules: the record goes where its ordinary push would go" dsrun confirm --repo zr --no-archive < ds-yes.txt
git -C "$W/zz/real.git" cat-file -e main:opening/commitment.txt 2>/dev/null && ! git -C "$W/other/real.git" cat-file -e main:opening/commitment.txt 2>/dev/null \
  && ok "  ... into the repository shown, not into another" || bad "rewrite rules"
python3 - "$DS" "$W" <<'PY' > ar.out 2>&1 && ok "public only when checked: a check that fails keeps the request open, names the repository, and is done again on the next run; nothing checked is not called public" || { bad "the anonymous check"; cat ar.out; }
import builtins, datetime as dt, importlib.util, io, json, os, subprocess, sys, contextlib
spec = importlib.util.spec_from_file_location("d", sys.argv[1]); d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
os.chdir(sys.argv[2])
case = open("commitment-reference.txt").read()[4:14]
for k, v in dict(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x").items():
    os.environ[k] = v
subprocess.run("git init -q --bare pubH.git && rm -rf zh && git init -q zh && cp commitment-reference.txt zh/ && git -C zh add -A "
               "&& git -C zh -c commit.gpgsign=false commit -q -m s && git -C zh push -q ../pubH.git HEAD:refs/heads/main && rm -rf pubH "
               "&& git clone -q -b main pubH.git pubH", shell=True, check=True)
def run(public, *repos):
    d.anonymous = lambda p, data, work: public(p) if callable(public) else public
    builtins.input = lambda prompt="": "release SC2/%s now" % case
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            rc = d.main(["confirm", "--no-archive"] + [x for r in (repos or ("pubH",)) for x in ("--repo", r)])
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue()
def started():
    d.main(["start"])
    r = json.load(open("sc2-release-request.json")); nb = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    r["not_before"], r["not_after"] = nb.isoformat(), (nb + dt.timedelta(hours=24)).isoformat(); json.dump(r, open("sc2-release-request.json", "w"))
started()
rc, out = run(False)
assert rc == 1 and "could not be confirmed that an anonymous reader" in out and "Released:" not in out, out
assert os.path.exists("sc2-release-request.json") and json.load(open("sc2-release-request.json"))["published"], out
rc, out = run(False)                                    # the next run checks again, though the record is there
assert rc == 1 and "already holds the record, but it could not be confirmed" in out and "Released:" not in out, out
rc, out = run(None)                                     # no address to check: pushed, and said to be NOT checked
assert rc == 0 and "NOT checked as public" in out and "Released:" not in out and "you may delete" not in out and "Next:" not in out, out
assert json.load(open("sc2-release-request.json")).get("closed"), out
plan, publish = d.plan, d.publish                       # of two repositories, one checked: public, and the other named
def fake_plan(f, data, case, tail):
    return dict(dir=f, up="origin/main", remote="origin", branch="main", who="t <t@x>", done=False, track="", objects="",
                url={"B": "https://github.com/me/r.git", "C": "/srv/r.git"}[f], web={"B": "https://github.com/me/r", "C": None}[f])
def fake_publish(p, data, note, case, day, tmp, mark, fds=()):
    mark("record")
    return True, True if p["web"] else None, "published and read back"
d.plan, d.publish = fake_plan, fake_publish
started()
rc, out = run(None, "B", "C")
assert rc == 0 and "Released: SC2/%s is public: an anonymous reader gets it from https://github.com/me/r" % case in out, out
assert "Not checked for /srv/r.git" in out and "Next:" in out, out
d.plan, d.publish = plan, publish
env = d.anon_env("/nowhere")
os.environ.update(GIT_ASKPASS="/bin/echo", SSH_ASKPASS="/bin/echo", GIT_CONFIG_COUNT="1", GIT_CONFIG_PARAMETERS="'x.y=z'", ALL_PROXY="socks5h://127.0.0.1:1")
env = d.anon_env("/nowhere")
assert env["HOME"] == "/nowhere" and env["GIT_ASKPASS"] == "" and "SSH_ASKPASS" not in env and env["GIT_CONFIG_GLOBAL"] == os.devnull
assert not any(k.startswith("GIT_CONFIG_COUNT") or k == "GIT_CONFIG_PARAMETERS" for k in env) and env["ALL_PROXY"] == "socks5h://127.0.0.1:1", env
PY
python3 - "$DS" "$W" <<'PY' > ar.out 2>&1 && ok "web addresses: HTTPS (a token in it dropped, in git's messages too), SSH as ssh resolves it (a host alias, GitHub's and GitLab's port 443) unless git uses its own ssh command; none for a local path or an unknown host" || { bad "web_url"; cat ar.out; }
import importlib.util, os, subprocess, sys
spec = importlib.util.spec_from_file_location("d", sys.argv[1]); d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
fake = os.path.join(sys.argv[2], "zfakessh"); os.makedirs(fake, exist_ok=True)
with open(os.path.join(fake, "ssh"), "w") as f:            # ssh -G as it answers with such a configuration
    f.write('#!/bin/sh\n[ "$1" = -G ] && [ "$2" = -- ] || exit 2\ncase "$3" in\n  github-sc2|github.com-work) echo "user git"; '
            'echo "hostname github.com";;\n  github.com) echo "hostname ssh.github.com"; echo "port 443";;\n  gl443) echo "hostname '
            'altssh.gitlab.com";;\n  *) echo "hostname $3";;\nesac\n')
os.chmod(os.path.join(fake, "ssh"), 0o755)
path = os.environ["PATH"]
os.environ["PATH"] = fake + os.pathsep + path
for k in ("GIT_SSH_COMMAND", "GIT_SSH"):
    os.environ.pop(k, None)
assert d.web_url("github-sc2:me/r.git") == "https://github.com/me/r" and d.web_url("git@github.com-work:me/r.git") == "https://github.com/me/r"
assert d.web_url("git@github.com:me/sc2-public.git") == "https://github.com/me/sc2-public"
assert d.web_url("ssh://git@ssh.github.com:443/me/r.git") == "https://github.com/me/r"
assert d.web_url("ssh://git@gl443/g/sub/r.git") == "https://gitlab.com/g/sub/r" and d.web_url("ssh://git@altssh.gitlab.com:443/g/r") == "https://gitlab.com/g/r"
assert d.web_url("nodot:me/r.git") is None and d.web_url("/tmp/x.git") is None and d.web_url("C:/x/r.git") is None
assert d.web_url("-oProxyCommand=x:me/r") is None and d.web_url("ssh://-oProxyCommand=x/me/r") is None
assert d.web_url("https://me:tok@gitlab.com/me/o.git") == "https://gitlab.com/me/o" and d.shown("https://me:tok@gitlab.com/me/o.git") == "https://gitlab.com/me/o.git"
os.environ["GIT_SSH_COMMAND"] = "ssh -F /dev/null"          # git's own ssh command: the host as written
assert d.web_url("github-sc2:me/r.git") is None and d.web_url("git@github.com:me/r.git") == "https://github.com/me/r"
del os.environ["GIT_SSH_COMMAND"]
subprocess.run(["git", "init", "-q", sys.argv[2] + "/zsshc"], check=True)
subprocess.run(["git", "-C", sys.argv[2] + "/zsshc", "config", "core.sshCommand", "ssh -F /dev/null"], check=True)
assert d.web_url("github-sc2:me/r.git", sys.argv[2] + "/zsshc") is None and d.web_url("github-sc2:me/r.git") == "https://github.com/me/r"
os.environ["PATH"] = os.path.join(sys.argv[2], "nohome")   # no ssh at all: the host as written
assert d.web_url("git@github.com:me/r.git") == "https://github.com/me/r" and d.web_url("github-sc2:me/r.git") is None
os.environ["PATH"] = path
msg = d.gerr(subprocess.CompletedProcess([], 128, "", "fatal: could not read Password for 'https://SECRETTOKEN@127.0.0.1:18444': terminal prompts disabled"))
assert "SECRETTOKEN" not in msg and "https://127.0.0.1:18444" in msg, msg
PY
zrepo dsF && cat > zfail.sh <<'SH'
#!/bin/sh
# the repository unreachable once it holds the record: the read-back after the push fails
if git -C "$1" cat-file -e main:opening/commitment.txt 2>/dev/null; then echo "simulated outage" >&2; exit 1; fi
exec git upload-pack "$1"
SH
chmod +x zfail.sh && git -C dsF config remote.origin.uploadpack "$W/zfail.sh" && dsrun start > /dev/null 2>&1; waited 1
expect 1 "the record pushed, then the repository unreachable: said so, and recorded" dsrun confirm --repo dsF --no-archive < ds-yes.txt
grep -q 'published, but it could not be read back' "$W/.out" && zhas dsF && grep -q 'dsF.git' sc2-release-request.json \
  && [ "$(git -C dsF rev-parse origin/main)" = "$(git -C dsF.git rev-parse main)" ] && git -C dsF cat-file -e origin/main:opening/commitment.txt \
  && git -C dsF log --all --oneline > /dev/null 2>&1 && git -C dsF fsck --no-progress > /dev/null 2>&1 \
  && ok "  ... your clone whole: what it knows of the repository names nothing missing" || bad "read-back failure"
git -C dsF config --unset remote.origin.uploadpack
expect 0 "  ... run again once it is reachable: it adds nothing, and closes the request" dsrun confirm --repo dsF --no-archive < ds-yes.txt
[ "$(git -C dsF.git rev-list --count main)" = 2 ] && zclosed && grep -q 'NOT checked as public' "$W/.out" && ok "  ... one release commit" || bad "after a read-back failure"
nl="$W/new
line"
zrepo dsC && mkdir -p "$W/a:b" && mv dsC "$W/a:b/dsC" && zrepo dsN && mkdir -p "$nl" && mv dsN "$nl/dsN" && zrepo dsS && mv dsS "dsS "
dsrun start > /dev/null 2>&1; waited 1
expect 0 "clones in folders whose names hold a colon (a slash in a Finder name, on macOS) or a line break, or end in a space: released" \
  dsrun confirm --repo "$W/a:b/dsC" --repo "$nl/dsN" --repo "$W/dsS " --no-archive < ds-yes.txt
zhas dsC && zhas dsN && zhas dsS && ok "  ... all three" || bad "colon, line break or space in a clone's path"
zrepo dsR
python3 - "$W" > zsrv.log 2>&1 <<'PY' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="x"'); self.send_header("Content-Length", "0"); self.end_headers()
    do_POST = do_GET
    def log_message(self, *a):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1] + "/zport.part", "w").write(str(s.server_address[1])); __import__("os").replace(sys.argv[1] + "/zport.part", sys.argv[1] + "/zport")
s.serve_forever()
PY
zsrv=$!; i=0; while [ ! -s zport ] && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
git -C dsR remote set-url origin "http://SECRETTOKEN@127.0.0.1:$(cat zport 2>/dev/null)/r.git" && dsrun start > /dev/null 2>&1; waited 1
expect 1 "a repository that asks for a password: refused, and a token written into its address is not printed, even in git's own message" \
  env -u http_proxy -u HTTP_PROXY -u all_proxy -u ALL_PROXY GIT_TERMINAL_PROMPT=0 HOME="$W/nohome" XDG_CONFIG_HOME="$W/nohome" GIT_CONFIG_NOSYSTEM=1 \
  GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid python3 "$DS" confirm --repo dsR < ds-yes.txt
kill "$zsrv" 2>/dev/null; wait "$zsrv" 2>/dev/null
grep -q 'cannot reach http://127.0.0.1:.*could not read Password' "$W/.out" && ! grep -q SECRETTOKEN "$W/.out" && ok "  ... named without it" || { bad "token in git's message"; cat "$W/.out"; }
dsrun cancel > /dev/null 2>&1
zrepo dsI1 && zrepo dsI2 && zrepo dsI3 && zrepo dsI4 && zrepo dsJ && zrepo dsW && zrepo dsP && zrepo dsV1 && zrepo dsV2 && cat > zslow.sh <<'SH'
#!/bin/sh
# the read-back after the push held until $ZGO exists: the moment to stop confirm
if git -C "$1" cat-file -e main:opening/commitment.txt 2>/dev/null; then
  : > "$ZMARK"; i=0; while [ ! -e "$ZGO" ] && [ "$i" -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
fi
exec git upload-pack "$1"
SH
chmod +x zslow.sh && for z in dsI1 dsI2 dsI3 dsI4; do git -C $z config remote.origin.uploadpack "$W/zslow.sh"; done
for z in dsJ dsW; do printf '#!/bin/sh\n: > "$ZMARK"; i=0; while [ ! -e "$ZGO" ] && [ "$i" -lt 600 ]; do sleep 0.1; i=$((i + 1)); done\n' > $z.git/hooks/pre-receive && chmod +x $z.git/hooks/pre-receive; done
python3 - "$DS" "$W" "$CASE" > zsig.out 2>&1 <<'PY'
import datetime as dt, glob, json, os, select, signal, subprocess, sys, time
DS, W, CASE = sys.argv[1:4]
os.chdir(W)
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
           GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="commit.gpgsign", GIT_CONFIG_VALUE_0="false", ZMARK=W + "/zmark", ZGO=W + "/zgo")
REQ = "sc2-release-request.json"
def report(cond, what, detail=""):
    print(("OK " if cond else "FAIL ") + what + ("" if cond else ": " + detail.replace("\n", " | ")[-600:]), flush=True)
def ds(*args):
    return subprocess.run([sys.executable, DS] + list(args), env=ENV, capture_output=True, text=True, input="")
def started():
    assert ds("start").returncode == 0
    r = json.load(open(REQ)); nb = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    r["not_before"], r["not_after"] = nb.isoformat(), (nb + dt.timedelta(hours=24)).isoformat(); json.dump(r, open(REQ, "w"))
def has(repo):
    return subprocess.run(["git", "-C", repo + ".git", "cat-file", "-e", "main:opening/commitment.txt"], capture_output=True).returncode == 0
def whole(repo):          # the clone's own view of the repository names nothing missing
    return all(subprocess.run(["git", "-C", repo] + c, capture_output=True).returncode == 0 for c in
               (["log", "--all", "--oneline"], ["fsck", "--no-progress"], ["cat-file", "-e", "origin/main^{tree}"]))
def until(cond, limit=60):
    end = time.time() + limit
    while not cond():
        if time.time() > end:
            raise AssertionError("timed out")
        time.sleep(0.05)
def confirm(repo):
    for f in ("zmark", "zgo"):
        if os.path.exists(f):
            os.remove(f)
    return subprocess.Popen([sys.executable, DS, "confirm", "--repo", repo, "--no-archive"], env=ENV, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
def prompt(p, limit=60):
    buf, end = b"", time.time() + limit
    while b"\n> " not in buf:
        if not select.select([p.stdout], [], [], max(0, end - time.time()))[0]:
            raise AssertionError("no prompt: %r" % buf[-300:])
        c = os.read(p.stdout.fileno(), 4096)
        if not c:
            raise AssertionError("ended before the prompt: %r" % buf[-300:])
        buf += c
def finish(p):
    out = p.communicate(timeout=120)[0].decode("utf-8", "replace")
    open("zgo", "w").close()
    return out
def left():
    return glob.glob(os.path.join(glob.escape(W), "sc2-disclose-tmp-*"))

started()                                                 # Ctrl-C at the sentence
p = confirm("dsI1"); prompt(p); os.killpg(p.pid, signal.SIGINT); out = finish(p)
report(p.returncode == 1 and "Not published" in out and "Traceback" not in out and os.path.exists(REQ) and not has("dsI1") and not left(),
       "Ctrl-C at the sentence: nothing published, the request still open, no traceback", out)
for sig, repo in ((signal.SIGINT, "dsI1"), (signal.SIGTERM, "dsI2"), (signal.SIGHUP, "dsI3")):
    if sig != signal.SIGINT:
        started()
    p = confirm(repo); prompt(p); p.stdin.write(("release SC2/%s now\n" % CASE).encode()); p.stdin.flush()
    until(lambda: os.path.exists("zmark")); os.killpg(p.pid, sig); out = finish(p)
    r = json.load(open(REQ))
    st, ca = ds("status").stdout, ds("cancel").stdout
    report(p.returncode == 130 and "INTERRUPTED. The record was ALREADY PUSHED to: " in out and repo + ".git" in out and has(repo)
           and [x for x in r["published"] if x.endswith("/" + repo + ".git")] and not r["unsure"] and not left() and whole(repo)
           and "ALREADY PUSHED to: " in st and repo + ".git" in st and "What was pushed stays" in ca and json.load(open(REQ)).get("closed"),
           "%s once the record is pushed: it is recorded, said, and said again by status and cancel; no copy left in a "
           "working folder; the clone whole" % {signal.SIGINT: "Ctrl-C", signal.SIGTERM: "A shutdown (SIGTERM)",
                                              signal.SIGHUP: "A closed terminal (SIGHUP)"}[sig], out + st + ca)
started()                                                 # kill -9 once pushed: the working folder stays, until the next run
p = confirm("dsI4"); prompt(p); p.stdin.write(("release SC2/%s now\n" % CASE).encode()); p.stdin.flush()
until(lambda: os.path.exists("zmark")); os.killpg(p.pid, signal.SIGKILL); out = finish(p)
before = left()
blobs = [f for d in before for f in glob.glob(os.path.join(glob.escape(d), "*", "objects", "??", "*"))]
st = ds("status").stdout
report(len(before) == 1 and len(blobs) >= 4 and "Removed " in st and "it held a copy of the record" in st and not left()
       and "ALREADY PUSHED to: " in st and "dsI4.git" in st and whole("dsI4"),
       "kill -9 once pushed: the working folder and its copy of the record stay only until the next run, which removes them", st)
r = json.load(open(REQ)); r["not_after"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat(); json.dump(r, open(REQ, "w"))
st = ds("start").stdout
report("Nothing more was published. The record was ALREADY PUSHED to: " in st and "dsI4.git" in st,
       "a new request after a lapsed one says where the record already is, not that nothing was published", st)
r = json.load(open(REQ)); r["not_before"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat(); json.dump(r, open(REQ, "w"))
p = confirm("dsJ"); prompt(p); p.stdin.write(("release SC2/%s now\n" % CASE).encode()); p.stdin.flush()
until(lambda: os.path.exists("zmark")); os.kill(p.pid, signal.SIGKILL); p.wait()   # during the push; the push itself goes on
r = json.load(open(REQ)); st = ds("status").stdout
report([x for x in r["unsure"] if x.endswith("/dsJ.git")] and "was cut short: the record MAY be there" in st and "a push started from it still runs" in st
       and len(left()) == 1, "kill -9 during a push: saved as cut short, the record MAY be there; the working folder kept while that push runs", st)
open("zgo", "w").close()
until(lambda: has("dsJ"))                                # the push, left running, ends
until(lambda: "Removed " in ds("status").stdout)
report(not left() and whole("dsJ"), "  ... then the next run gives the clone the pushed commit and removes the folder: the clone whole, no fetch needed", "")
r = json.load(open(REQ)); r["not_before"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat(); json.dump(r, open(REQ, "w"))
p = confirm("dsJ"); prompt(p); p.stdin.write(("release SC2/%s now\n" % CASE).encode()); p.stdin.flush(); out = finish(p)
report(p.returncode == 0 and "already holds the record" in out and json.load(open(REQ)).get("closed") and not left() and whole("dsJ"),
       "  ... and confirm, run again, finds the record there, closes the request, and leaves the clone whole", out)
import importlib.util                                     # the cleanup removes only folders a confirm made
spec = importlib.util.spec_from_file_location("d", DS); d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
mine = W + "/sc2-disclose-tmp-zzzzzzzz"; os.makedirs(mine + "/0"); open(mine + "/" + d.MADE, "w").close()
empty = W + "/sc2-disclose-tmp-yyyyyyyy"; os.makedirs(empty)
for other in ("sc2-disclose-tmp-keepthis", "sc2-disclose-tmp-notmine"):
    os.makedirs(W + "/" + other, exist_ok=True)
    open(W + "/" + other + "/yours.txt", "w").close()
d.sweep(W, False); young = os.path.isdir(mine) and os.path.isdir(empty)    # without a lock: only a folder a day old
d.sweep(W, True)
report(young and not os.path.isdir(mine) and not os.path.isdir(empty) and os.path.isdir(W + "/sc2-disclose-tmp-keepthis")
       and os.path.isdir(W + "/sc2-disclose-tmp-notmine") and d.adopt({"dir": W, "track": "refs/remotes/origin/main", "objects": W}, "0" * 40, W) is False,
       "  ... and it removes only folders a confirm made (or an empty one of that name), without a lock only a day-old one; "
       "an unknown answer from git is not taken for 'the remote did not take it'", "")
started()                                                 # while a confirm publishes, the other commands keep out
p = confirm("dsW"); prompt(p); p.stdin.write(("release SC2/%s now\n" % CASE).encode()); p.stdin.flush()
until(lambda: os.path.exists("zmark"))                    # its push, held at the repository
c1, c2, st = ds("cancel"), ds("start"), ds("status")
c3 = subprocess.run([sys.executable, DS, "confirm", "--repo", "dsP", "--no-archive"], env=ENV, capture_output=True, text=True,
                    input="release SC2/%s now\n" % CASE)
open("zgo", "w").close(); out = finish(p)
report(all(c.returncode == 1 and "Another command of sc2-disclose.py is at work in this folder" in c.stderr for c in (c1, c2, c3))
       and "this one published nothing" in c3.stderr and not has("dsP") and st.returncode == 0 and "is publishing in this folder now" in st.stdout
       and "Removed" not in st.stdout and p.returncode == 0 and has("dsW") and json.load(open(REQ)).get("closed"),
       "while a confirm publishes, cancel, start and another confirm refuse (the other confirm once its sentence is typed), and status says so",
       c1.stderr + c2.stderr + c3.stderr + st.stdout + out)
started()                                                 # a confirm left at its prompt keeps no one out
p = confirm("dsP"); prompt(p)
ca = ds("cancel")
p.stdin.write(("release SC2/%s now\n" % CASE).encode()); p.stdin.flush(); out = finish(p)
report(ca.returncode == 0 and "Release request dropped" in ca.stdout and p.returncode == 1 and "The request changed while the sentence was being typed" in out
       and "this command published nothing" in out and not has("dsP"),
       "a confirm left at its prompt keeps no one out: cancel drops the request, and that confirm, once its sentence comes, publishes nothing",
       ca.stdout + ca.stderr + out)
started()                                                 # two confirms at their prompts: one releases, then the other gets a wrong line
p1, p2 = confirm("dsV1"), None
prompt(p1)
p2 = subprocess.Popen([sys.executable, DS, "confirm", "--repo", "dsV2", "--no-archive"], env=ENV, stdin=subprocess.PIPE,
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
prompt(p2)
p1.stdin.write(("release SC2/%s now\n" % CASE).encode()); p1.stdin.flush(); out1 = finish(p1)
p2.stdin.write(b"release it\n"); p2.stdin.flush(); out2 = finish(p2)
report(p1.returncode == 0 and p2.returncode == 1 and "Not published by this command" in out2 and "no longer open" in out2
       and "stays open" not in out2 and "ALREADY PUSHED to: " in out2 and "dsV1.git" in out2 and not has("dsV2"),
       "two confirms at their prompts: once one has released, the other, given a wrong line, says the request is no longer open and where the record went",
       out1 + out2)
print("DONE")
PY
while IFS= read -r line; do case "$line" in "OK "*) ok "${line#OK }";; "FAIL "*) bad "${line#FAIL }";; esac; done < zsig.out
grep -q '^DONE$' zsig.out || { bad "the interruption tests stopped"; tail -20 zsig.out; }
python3 - "$DS" "$W" <<'PY' > ar.out 2>&1 && ok "a Ctrl-C during the final cleanup of a release changes nothing; a signal while the clone gets the pushed commit still leaves it whole; a Ctrl-C at a command's start shows no error dump; nohup is respected" || { bad "signals, in-process"; cat ar.out; }
import builtins, contextlib, datetime as dt, importlib.util, io, json, os, signal, subprocess, sys
spec = importlib.util.spec_from_file_location("d", sys.argv[1]); d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
os.chdir(sys.argv[2])
case = open("commitment-reference.txt").read()[4:14]
for k, v in dict(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x").items():
    os.environ[k] = v
def fresh(name):
    subprocess.run("git init -q --bare {0}.git && rm -rf zq && git init -q zq && cp commitment-reference.txt zq/ && git -C zq add -A "
                   "&& git -C zq -c commit.gpgsign=false commit -q -m s && git -C zq push -q ../{0}.git HEAD:refs/heads/main && rm -rf zq {0} "
                   "&& git clone -q -b main {0}.git {0}".format(name), shell=True, check=True)
def run(*args):
    builtins.input = lambda prompt="": "release SC2/%s now" % case
    d.STOP["now"] = False
    d.RUN.clear()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            rc = d.main(list(args))
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue()
def started():
    run("start")
    r = json.load(open("sc2-release-request.json")); nb = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    r["not_before"], r["not_after"] = nb.isoformat(), (nb + dt.timedelta(hours=24)).isoformat(); json.dump(r, open("sc2-release-request.json", "w"))
def whole(repo):
    return all(subprocess.run(["git", "-C", repo] + c, capture_output=True).returncode == 0 for c in
               (["log", "--all", "--oneline"], ["fsck", "--no-progress"], ["cat-file", "-e", "origin/main^{tree}"]))
fresh("dsQ1"); started()                                  # a Ctrl-C as the release, done, cleans up
remove = d.remove
d.remove = lambda w: ((os.kill(os.getpid(), signal.SIGINT) if d.RUN.get("closed") else None), remove(w))[1]
rc, out = run("confirm", "--repo", "dsQ1", "--no-archive")
d.remove = remove
assert rc == 0 and "INTERRUPTED" not in out and "Interrupted" not in out and json.load(open("sc2-release-request.json")).get("closed"), out
fresh("dsQ2"); started()                                  # a signal while the clone gets the commit the remote took
adopt, calls = d.adopt, []
def cut(p, c, tmp):
    calls.append(c)
    if len(calls) == 1:
        raise KeyboardInterrupt
    return adopt(p, c, tmp)
d.adopt = cut
rc, out = run("confirm", "--repo", "dsQ2", "--no-archive")
d.adopt = adopt
r = json.load(open("sc2-release-request.json"))
assert rc == 130 and "INTERRUPTED" in out and "dsQ2.git was cut short" in out and len(calls) >= 2 and whole("dsQ2"), (out, calls)
assert [u for u in r["unsure"] if u.endswith("/dsQ2.git")] and not r.get("closed"), r
run("cancel")
sweep = d.sweep                                           # a Ctrl-C while leftovers are looked for, at the start
d.sweep = lambda folder, locked: (_ for _ in ()).throw(KeyboardInterrupt)
rc, out = run("status")
d.sweep = sweep
assert rc == 130 and "This command published nothing" in out, out
signal.signal(signal.SIGHUP, signal.SIG_IGN)              # under nohup
run("status")
assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
PY
python3 - "$DS" "$W" <<'PY' > ar.out 2>&1 && ok "a push starts only once its process number is noted: a stop before that publishes nothing; a process number given again to another program is not taken for a push; without a shell, the push goes without its gate" || { bad "the push's gate, or alive()"; cat ar.out; }
import builtins, contextlib, datetime as dt, importlib.util, io, json, os, subprocess, sys
spec = importlib.util.spec_from_file_location("d", sys.argv[1]); d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
os.chdir(sys.argv[2])
case = open("commitment-reference.txt").read()[4:14]
for k, v in dict(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x").items():
    os.environ[k] = v
subprocess.run("git init -q --bare dsG.git && rm -rf zq && git init -q zq && cp commitment-reference.txt zq/ && git -C zq add -A "
               "&& git -C zq -c commit.gpgsign=false commit -q -m s && git -C zq push -q ../dsG.git HEAD:refs/heads/main && rm -rf zq dsG "
               "&& git clone -q -b main dsG.git dsG", shell=True, check=True)
def run(*args):
    builtins.input = lambda prompt="": "release SC2/%s now" % case
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            rc = d.main(list(args))
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue()
run("start")
r = json.load(open("sc2-release-request.json")); nb = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
r["not_before"], r["not_after"] = nb.isoformat(), (nb + dt.timedelta(hours=24)).isoformat(); json.dump(r, open("sc2-release-request.json", "w"))
save = d.save
def stopped(path, r):                                     # stopped as the push's process number is about to be noted
    if "pid" in r:
        raise KeyboardInterrupt
    return save(path, r)
d.save = stopped
rc, out = run("confirm", "--repo", "dsG", "--no-archive")
d.save = save
gone = subprocess.run(["git", "-C", "dsG.git", "cat-file", "-e", "main:opening/commitment.txt"], capture_output=True).returncode != 0
assert rc == 130 and gone and not [x for x in os.listdir(".") if x.startswith(d.TMP) and os.path.isfile(os.path.join(x, d.MADE))], (rc, gone, out)
run("cancel")
now, me = dt.datetime.now(dt.timezone.utc), d.started(os.getpid())
if me:                                                    # Linux: a process is known by its start time too
    assert d.alive({"pid": os.getpid(), "started": me}) and not d.alive({"pid": os.getpid(), "started": "1"})
    assert not d.alive({"pid": 1, "at": now.isoformat(), "started": me})
assert not d.alive({"pid": os.getpid(), "at": (now - dt.timedelta(hours=7)).isoformat()}) and not d.alive({"pid": os.getpid()})
subprocess.run("git init -q --bare dsG2.git && rm -rf zq && git init -q zq && cp commitment-reference.txt zq/ && git -C zq add -A "
               "&& git -C zq -c commit.gpgsign=false commit -q -m s && git -C zq push -q ../dsG2.git HEAD:refs/heads/main && rm -rf zq dsG2 "
               "&& git clone -q -b main dsG2.git dsG2", shell=True, check=True)
run("start")
r = json.load(open("sc2-release-request.json")); nb = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
r["not_before"], r["not_after"] = nb.isoformat(), (nb + dt.timedelta(hours=24)).isoformat(); json.dump(r, open("sc2-release-request.json", "w"))
real = subprocess.Popen                                   # no shell to wait in: the push goes all the same, without its gate
def nosh(args, *a, **k):
    if args and args[0] in ("/bin/sh", "sh"):
        raise FileNotFoundError(args[0])
    return real(args, *a, **k)
subprocess.Popen = nosh
rc, out = run("confirm", "--repo", "dsG2", "--no-archive")
subprocess.Popen = real
assert rc == 0 and subprocess.run(["git", "-C", "dsG2.git", "cat-file", "-e", "main:opening/commitment.txt"]).returncode == 0, out
PY

echo
echo "== $pass passed, $fail failed.  Test files left in $W (synthetic; delete when you like)."
if [ "$fail" -eq 0 ]; then echo "ALL SELF-TESTS PASSED"; exit 0; else echo "SELF-TEST FAILED -- do not proceed until this machine passes"; exit 1; fi
