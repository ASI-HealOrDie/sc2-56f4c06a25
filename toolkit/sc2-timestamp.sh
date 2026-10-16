#!/bin/sh
# sc2-timestamp.sh <file> <trusted-roots-dir> [outdir]
#
# Asks several independent RFC 3161 timestamp authorities (TSAs) to sign a hash of <file>,
# keeps each token with its own request, and archives the revocation lists (CRLs) that
# were current when it signed. Then verifies everything with sc2-tsverify.sh.
#
# Run it on the PUBLIC reference file only. Never on the secret: a TSA receives a hash of
# whatever you give it, and the secret must not leave your machine in any form.
#
# TRUST MODEL: certificates that arrive inside a response are NEVER trust anchors. Anchors
# come only from <trusted-roots-dir>, which you populate yourself (see the runbook, 5b).
#
# RE-RUN SAFE: an authority that already gave you a token is skipped. A new request is
# written to temporary files and moved into place only once it is Granted and answers
# your own nonce, so a failure can never delete or orphan a token you already hold.
# (The previous version deleted a good token when a re-run of the same authority failed.)
#
# The authority list can be replaced without editing this script: put lines in the same
# format in a file and set SC2_TSA_LIST=/path/to/that/file.
set -eu
F="${1:?usage: sc2-timestamp.sh <file> <trusted-roots-dir> [outdir]}"; ROOTS="${2:-}"; D="${3:-timestamps}"
HERE=$(dirname "$0")
[ -r "$F" ] || { echo "FATAL: cannot read $F"; exit 1; }
[ -d "$ROOTS" ] || { echo "FATAL: no trusted-roots directory. Without independently"
                     echo "obtained roots, verification is circular and proves nothing."; exit 1; }
NR=$(ls "$ROOTS"/*.pem 2>/dev/null | wc -l | tr -d ' ')
[ "$NR" -gt 0 ] || { echo "FATAL: $ROOTS contains no .pem files."; exit 1; }
case "$(basename "$F")" in
  commitment.txt|*secret*|MASTER*) echo "FATAL: $F looks like the SECRET. Timestamp only the public reference."; exit 1 ;;
esac
mkdir -p "$D/crl"
echo "file: $F   sha512: $(openssl dgst -sha512 -r "$F" | cut -c1-32)..."
echo "trust anchors: $NR certificate(s) in $ROOTS"

# name|url|seconds to wait before EACH request|digests to try, in order
# Sources checked 2026-10-02 (details in RUNBOOK.md, Sources):
#   belgium    free for non-commercial use under BOSA's conditions (terms PDF, 2019)
#   portugal   free for citizens; 20 requests / 20 min, then a 24 h block; policy POL26
#              v3.0 (Feb 2026) accepts SHA-256 only -> this leg is 2^128, flagged
#   spain-accv free for personal use only; SHA-256/384/512
#   izenpe     free below an unpublished monthly threshold; SHA-512 listed
#   lithuania  moved to tsa2.baltstamp.lt (statement V5.8, 2026-03-03); 100 requests per
#              month without registration; another key change announced for 2027-01-15
#   sectigo-q  eIDAS-qualified endpoint; "15 seconds or more between each" request
#   freetsa    not on the EU list; new P-384 certificate since 2026-03-16
#   digicert   the one non-EU operator (US); chain to DigiCert Trusted Root G4
# Removed after checking: Greece/APED (terms address subscribers, forbid letting others
# use the service) and QuoVadis EU (DigiCert Europe: subscribers only, IP registration).
TSAS_DEFAULT="belgium|http://tsa.belgium.be/connect|0|sha512 sha256
portugal|http://ts.cartaodecidadao.pt/tsa/server|0|sha256
spain-accv|http://tss.accv.es:8318/tsa|0|sha512 sha256
basque-izenpe|http://tsa.izenpe.com|0|sha512 sha256
lithuania|http://tsa2.baltstamp.lt|0|sha512 sha256
sectigo-q|http://timestamp.sectigo.com/qualified|16|sha512 sha256
freetsa|https://freetsa.org/tsr|0|sha512 sha256
digicert|http://timestamp.digicert.com|0|sha512 sha256"
if [ -n "${SC2_TSA_LIST:-}" ]; then TSAS=$(grep -v '^#' "$SC2_TSA_LIST"); else TSAS="$TSAS_DEFAULT"; fi

nonce_of() { openssl ts "$1" -in "$2" -text 2>/dev/null | sed -n 's/^Nonce: //p' | head -1; }

cdp_urls() {   # CRL distribution point URLs of every certificate in a PEM bundle
  python3 - "$1" <<'PY'
import re, subprocess, sys
pem = open(sys.argv[1]).read()
seen = []
for c in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S):
    out = subprocess.run(["openssl", "x509", "-noout", "-ext", "crlDistributionPoints"],
                         input=c, capture_output=True, text=True).stdout
    for u in re.findall(r"URI:(\S+)", out):
        if u not in seen:
            seen.append(u); print(u)
PY
}

new=0
while IFS='|' read -r n u w algs; do
  [ -n "$n" ] || continue
  printf '%-14s ' "$n"
  if [ -s "$D/$n.tsr" ] && [ -s "$D/$n.tsq" ]; then
    echo "already have a token -- skipped (move $n.tsr and $n.tsq aside to re-request)"; continue
  fi
  got=""
  for alg in $algs; do
    [ "${w:-0}" -gt 0 ] && sleep "$w"
    openssl ts -query -data "$F" -"$alg" -cert -out "$D/.$n.tsq.tmp" 2>/dev/null || continue
    curl -s -f --max-time 45 -H "Content-Type: application/timestamp-query" \
         --data-binary "@$D/.$n.tsq.tmp" "$u" -o "$D/.$n.tsr.tmp" 2>/dev/null || continue
    # A TSA that refuses a digest answers HTTP 200 with PKIStatus=rejection, so the
    # fallback is driven by the PKIStatus, not by curl's exit code.
    openssl ts -reply -in "$D/.$n.tsr.tmp" -text 2>/dev/null | grep -q "Status: Granted" || continue
    # It must answer OUR request: same nonce (stops a cached or replayed response).
    [ "$(nonce_of -query "$D/.$n.tsq.tmp")" = "$(nonce_of -reply "$D/.$n.tsr.tmp")" ] || continue
    got="$alg"; break
  done
  if [ -z "$got" ]; then
    rm -f "$D/.$n.tsq.tmp" "$D/.$n.tsr.tmp"     # temporary files only; nothing you held
    echo "no usable response (unreachable, refused, or rejected every digest)"; continue
  fi
  mv "$D/.$n.tsq.tmp" "$D/$n.tsq"; mv "$D/.$n.tsr.tmp" "$D/$n.tsr"; new=$((new + 1))
  T=$(openssl ts -reply -in "$D/$n.tsr" -text 2>/dev/null | sed -n 's/^Time stamp: //p')
  note=""; [ "$got" = sha256 ] && note=" [SHA-256 imprint: 2^128 leg]"
  # Human-readable copy of the certificates embedded in the token (untrusted, never an anchor).
  if openssl ts -reply -in "$D/$n.tsr" -token_out -out "$D/.$n.tk" 2>/dev/null \
     && openssl pkcs7 -inform DER -in "$D/.$n.tk" -print_certs -out "$D/$n-untrusted-chain.pem" 2>/dev/null; then
    # Archive the CRLs that are current NOW, while the authority still publishes them.
    # Operators are not obliged to keep revocation data for expired certificates.
    mkdir -p "$D/crl/$n"; k=0
    for cu in $(cdp_urls "$D/$n-untrusted-chain.pem" || true); do
      k=$((k + 1))
      [ -s "$D/crl/$n/$k.crl" ] && continue
      if curl -s -f --max-time 30 -o "$D/crl/$n/.$k.tmp" "$cu" 2>/dev/null; then
        mv "$D/crl/$n/.$k.tmp" "$D/crl/$n/$k.crl"; printf '%s\n' "$cu" > "$D/crl/$n/$k.url"
      else
        rm -f "$D/crl/$n/.$k.tmp"; note="$note [CRL $cu not fetched]"
      fi
    done
    [ "$k" -gt 0 ] || note="$note [no CRL distribution point]"
  else
    note="$note [certificates not extractable; token kept]"
  fi
  rm -f "$D/.$n.tk"
  echo "$T  ($got)$note"
  printf '%s|%s|%s|%s|fetched %s\n' "$n" "$u" "$got" "$T" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$D/log.txt"
done <<EOF
$TSAS
EOF

echo
echo "$new new token(s) this run. Verification of everything held in $D:"
sh "$HERE/sc2-tsverify.sh" "$D" "$ROOTS" || true
echo
echo "A token marked NOT VERIFIED is kept but proves nothing until you place its anchor"
echo "certificate in $ROOTS (runbook 5b). Re-running this script is safe."
