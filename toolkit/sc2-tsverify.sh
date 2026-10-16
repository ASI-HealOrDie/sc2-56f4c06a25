#!/bin/sh
# sc2-tsverify.sh <timestamps-dir> <roots-dir>
#
# Verifies every RFC 3161 token (*.tsr) in <timestamps-dir>:
#   - against its own request (*.tsq: same imprint, same nonce),
#   - with a signature chain ending at a certificate in <roots-dir> that YOU obtained
#     independently (EU Trusted List, an OS trust store, the operator's site with a
#     fingerprint check) -- never at a certificate that came inside the token,
#   - AT THE STAMPING TIME printed inside the token (-attime), which is what a historical
#     timestamp asserts; expired certificates are therefore fine,
#   - and against the CRLs archived with the token at stamping time (crl/<name>/*.crl),
#     so a key that was already revoked when it signed is caught.
#
# -partial_chain lets a NON-self-signed certificate you placed in <roots-dir> act as the
# trust anchor. That is necessary: the EU Trusted List usually publishes a qualified
# service's issuing CA or the timestamp unit's own certificate, not a self-signed root,
# and without this flag every such token fails with "unable to get issuer certificate".
# It never lets a certificate from inside the token become an anchor (tested).
#
# Exit 0 if at least one token verifies and none is revoked; 1 otherwise.
set -eu
D="${1:?usage: sc2-tsverify.sh <timestamps-dir> <roots-dir>}"; ROOTS="${2:?roots dir}"

# genTime as printed by openssl, e.g. "Oct  2 00:00:02.123 2026 GMT" -> epoch seconds.
# GNU date understands it; macOS date does not, so fall back to Python, which must drop
# the fractional seconds first or it raises an error (and every token would read
# "NOT VERIFIED" on a Mac).
epoch() {
  date -u -d "$1" +%s 2>/dev/null && return 0
  python3 -c "import sys,re,calendar,time
s=re.sub(r'(\d\d:\d\d:\d\d)\.\d+', r'\1', sys.argv[1]).replace('GMT','').strip()
print(calendar.timegm(time.strptime(' '.join(s.split()), '%b %d %H:%M:%S %Y')))" "$1" 2>/dev/null
}

TMP=$(mktemp "${TMPDIR:-/tmp}/sc2crl.XXXXXX")
trap 'rm -f "$TMP"' EXIT INT TERM

found=0; good=0; revoked=0
for tsr in "$D"/*.tsr; do
  [ -e "$tsr" ] || break
  n=$(basename "$tsr" .tsr); found=$((found + 1))
  q="$D/$n.tsq"; ch="$D/$n-untrusted-chain.pem"
  printf '  %-14s ' "$n"
  if [ ! -s "$q" ]; then echo "*** no $n.tsq: a token can only be checked against its own request"; continue; fi
  gen=$(openssl ts -reply -in "$tsr" -text 2>/dev/null | sed -n 's/^Time stamp: //p')
  alg=$(openssl ts -reply -in "$tsr" -text 2>/dev/null | sed -n 's/^Hash Algorithm: //p' | head -1)
  ep=$(epoch "$gen" || true)
  if [ -z "$ep" ]; then echo "*** cannot read the stamping time ($gen)"; continue; fi
  # The token embeds its certificates (it was requested with -cert); the extracted chain
  # file is a human-readable copy of the same certificates, used if present.
  U=""; [ -s "$ch" ] && U="-untrusted $ch"
  anchor=""
  for r in "$ROOTS"/*.pem; do
    [ -e "$r" ] || break
    # shellcheck disable=SC2086
    if openssl ts -verify -in "$tsr" -queryfile "$q" -CAfile "$r" $U \
         -partial_chain -attime "$ep" >/dev/null 2>&1; then
      anchor=$(basename "$r"); break
    fi
  done
  if [ -z "$anchor" ]; then
    echo "$gen  [$alg]  NOT VERIFIED -- no certificate in $ROOTS anchors it"
    continue
  fi
  # Revocation, judged at the stamping time, from the CRLs archived with this token:
  # find the timestamp unit's certificate, check each CRL's own signature against its
  # issuer in the chain, and compare the unit's revocation date (if listed) with genTime.
  # (openssl's -crl_check cannot do this: it calls a CRL issued after genTime "not yet
  # valid" and stops, which is precisely the case of a key revoked after signing.)
  if [ -s "$ch" ]; then cp "$ch" "$TMP"
  else openssl ts -reply -in "$tsr" -token_out 2>/dev/null | openssl pkcs7 -inform DER -print_certs -out "$TMP" 2>/dev/null || : > "$TMP"; fi
  rev=$(python3 - "$TMP" "$ep" "$D/crl/$n" <<'PY'
import calendar, glob, os, re, subprocess, sys, time
certs_pem, gen, crldir = open(sys.argv[1]).read(), int(sys.argv[2]), sys.argv[3]
run = lambda args, data=None: subprocess.run(args, input=data, capture_output=True, text=True)
def when(s):
    s = re.sub(r"(\d\d:\d\d:\d\d)\.\d+", r"\1", s).replace("GMT", "").strip()
    return calendar.timegm(time.strptime(" ".join(s.split()), "%b %d %H:%M:%S %Y"))
certs = []
for c in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", certs_pem, re.S):
    o = run(["openssl", "x509", "-noout", "-serial", "-subject", "-issuer", "-nameopt", "RFC2253",
             "-ext", "extendedKeyUsage"], c).stdout
    g = lambda k: (re.search(r"^%s=(.*)$" % k, o, re.M) or [None, ""])[1].strip()
    certs.append({"pem": c, "serial": g("serial").upper().lstrip("0"), "subject": g("subject"),
                  "issuer": g("issuer"), "tsu": "Time Stamping" in o})
tsu = next((c for c in certs if c["tsu"]), None)
files = sorted(glob.glob(os.path.join(crldir, "*.crl")))
if not files: print("no CRL archived"); sys.exit()
if tsu is None: print("CRL check impossible: no timestamping certificate found"); sys.exit()
checked = 0
for f in files:
    txt = run(["openssl", "crl", "-inform", "DER", "-in", f, "-noout", "-text", "-nameopt", "RFC2253"]).stdout
    fmt = "DER"
    if not txt:
        txt = run(["openssl", "crl", "-in", f, "-noout", "-text", "-nameopt", "RFC2253"]).stdout; fmt = "PEM"
    m = re.search(r"Issuer: ?(.*)", txt)
    if not m or m.group(1).strip() != tsu["issuer"]:
        continue                                      # a CRL for another level of the chain
    issuer = next((c for c in certs if c["subject"] == tsu["issuer"]), None)
    if issuer is None: continue
    tmp = sys.argv[1] + ".iss"; open(tmp, "w").write(issuer["pem"])
    ok = "verify OK" in (lambda r: r.stdout + r.stderr)(run(["openssl", "crl", "-inform", fmt, "-in", f, "-CAfile", tmp, "-noout"]))
    os.remove(tmp)
    if not ok: continue                               # a CRL we cannot authenticate proves nothing
    checked += 1
    for ser, rdate in re.findall(r"Serial Number: ([0-9A-Fa-f]+)\s+Revocation Date: ([^\n]+)", txt):
        if ser.upper().lstrip("0") == tsu["serial"]:
            r = when(rdate)
            if r <= gen:
                print("*** REVOKED on %s, BEFORE it signed ***" % rdate.strip()); sys.exit()
            print("key revoked LATER (%s), after this token was signed" % rdate.strip()); sys.exit()
print("not revoked (%d authenticated CRL%s)" % (checked, "" if checked == 1 else "s") if checked
      else "CRL archived but not authenticated against the chain")
PY
)
  case "$rev" in
    *BEFORE*) revoked=$((revoked + 1)); echo "$gen  [$alg]  $rev" ;;
    *)        good=$((good + 1)); echo "$gen  [$alg]  VERIFIED via $anchor; $rev" ;;
  esac
done
[ "$found" -gt 0 ] || { echo "  *** no tokens in $D"; exit 1; }
echo "  => $good of $found token(s) verify at their stamping time against roots you hold."
[ "$revoked" -eq 0 ] || echo "  => *** $revoked token(s) signed by a key already listed as REVOKED -- they prove nothing."
[ "$good" -gt 0 ] && [ "$revoked" -eq 0 ]
