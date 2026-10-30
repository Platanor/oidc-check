#!/usr/bin/env bash
# Platanor GH-01…04: request GitHub Actions OIDC tokens and keep them out of the public log.
#
#   token.sh fetch <name> <audience>   request a token, print its header and claims (no signature)
#   token.sh seal <dir>                encrypt all tokens of this job to .github/recipient.pem
#
# The repository is public, so the log and the artifacts are public too. A full token is
# only stored encrypted (AES-256 with a random key, the key under RSA-OAEP-SHA256).
set -euo pipefail
store="$RUNNER_TEMP/tokens.tsv"

case "$1" in
fetch)
  name="$2"
  aud="$3"
  if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    echo "$name: NO TOKEN (ACTIONS_ID_TOKEN_REQUEST_URL is not set)"
    printf '%s\t%s\n' "$name" "NO_TOKEN" >> "$store"
    exit 0
  fi
  enc=$(jq -rn --arg a "$aud" '$a|@uri')
  resp=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
              "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$enc" || true)
  token=$(jq -r '.value // empty' <<<"$resp" 2>/dev/null || true)
  if [ -z "$token" ]; then
    echo "$name: REQUEST FAILED, audience length ${#aud}: $(head -c 300 <<<"$resp")"
    printf '%s\t%s\n' "$name" "FAILED" >> "$store"
    exit 0
  fi
  echo "::add-mask::$token"
  printf '%s\t%s\n' "$name" "$token" >> "$store"
  echo "== $name: audience length ${#aud}, token length ${#token}"
  python3 - "$token" <<'EOF'
import base64, json, sys
part = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
h, p, _ = sys.argv[1].split(".")
print("header:", json.dumps(part(h), sort_keys=True))
print("claims:", json.dumps(part(p), sort_keys=True, indent=1))
EOF
  ;;
seal)
  out="$2"
  mkdir -p "$out"
  [ -f "$store" ] || : > "$store"
  openssl rand -hex 32 > "$RUNNER_TEMP/k"
  openssl enc -aes-256-cbc -pbkdf2 -pass "file:$RUNNER_TEMP/k" -in "$store" -out "$out/tokens.enc"
  openssl pkeyutl -encrypt -pubin -inkey .github/recipient.pem -pkeyopt rsa_padding_mode:oaep \
          -pkeyopt rsa_oaep_md:sha256 -in "$RUNNER_TEMP/k" -out "$out/key.enc"
  rm -f "$RUNNER_TEMP/k" "$store"
  echo "sealed $(ls "$out")"
  ;;
esac
