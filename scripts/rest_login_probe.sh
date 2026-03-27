#!/usr/bin/env bash
set -euo pipefail

# REST login probe helper for Apex Fusion.
# - Loads workspace .env (if present)
# - Retries login a few times (controllers can be flaky)
# - Verifies /rest/status using the resulting connect.sid cookie

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_FILE="$ROOT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  # Export all variables defined in .env while sourcing.
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

: "${APEX_HOST:?Set APEX_HOST in .env (or environment)}"

# Support either naming convention:
# - Preferred: APEX_USERNAME / APEX_PASSWORD
# - Legacy:    APEX_USER / APEX_PASS
APEX_USERNAME="${APEX_USERNAME:-${APEX_USER:-}}"
APEX_PASSWORD="${APEX_PASSWORD:-${APEX_PASS:-}}"

: "${APEX_USERNAME:?Set APEX_USERNAME (or APEX_USER) in .env (or environment)}"
: "${APEX_PASSWORD:?Set APEX_PASSWORD (or APEX_PASS) in .env (or environment)}"

HOST="$APEX_HOST"
USER="$APEX_USERNAME"
PASS="$APEX_PASSWORD"
ATTEMPTS="${APEX_LOGIN_ATTEMPTS:-6}"

BASE_URL="http://$HOST"
COOKIE_JAR="$(mktemp -t apex.cookies.XXXXXX)"
HEADERS_FILE="$(mktemp -t apex.headers.XXXXXX)"
BODY_FILE="$(mktemp -t apex.body.XXXXXX)"

cleanup() {
  rm -f "$COOKIE_JAR" "$HEADERS_FILE" "$BODY_FILE"
}
trap cleanup EXIT

json_payload() {
  python3 - "$USER" "$PASS" <<'PY'
import json
import os
import sys

username = sys.argv[1]
password = sys.argv[2]
print(json.dumps({
  "login": username,
  "password": password,
  "remember_me": False,
}))
PY
}

have_cookie_sid() {
  # curl cookie jar format: 7 tab-separated columns; cookie name is col 6.
  awk -F '\t' '$6 == "connect.sid" && $7 != "" { found=1 } END { exit(found?0:1) }' "$COOKIE_JAR"
}

for ((i=1; i<=ATTEMPTS; i++)); do
  echo "login attempt $i/$ATTEMPTS"

  payload="$(json_payload)"

  http_code="$(
    curl -sS -o "$BODY_FILE" -D "$HEADERS_FILE" \
      -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
      --max-time 10 \
      -H 'Accept: */*' \
      -H 'Content-Type: application/json' \
      -H 'User-Agent: HomeAssistant-ApexFusion' \
      -X POST "$BASE_URL/rest/login" \
      --data "$payload" \
      -w '%{http_code}' \
      || true
  )"

  echo "  HTTP $http_code"

  # Some controllers return 200 but only set the cookie.
  if have_cookie_sid; then
    echo "  connect.sid acquired"
    break
  fi

  # Backoff a bit between attempts.
  sleep "0.$((i * 2))"
done

if ! have_cookie_sid; then
  echo "FAILED: no connect.sid cookie after $ATTEMPTS attempts" >&2
  echo "Last response headers (first 20 lines):" >&2
  sed -n '1,20p' "$HEADERS_FILE" >&2 || true
  exit 1
fi

echo "GET /rest/status (should be JSON)"
status_code="$(
  curl -sS -o "$BODY_FILE" -D "$HEADERS_FILE" \
    -b "$COOKIE_JAR" \
    --max-time 10 \
    -H 'Accept: */*' \
    -H 'User-Agent: HomeAssistant-ApexFusion' \
    "$BASE_URL/rest/status" \
    -w '%{http_code}' \
    || true
)"

ctype="$(grep -i '^Content-Type:' "$HEADERS_FILE" | head -n 1 | cut -d: -f2- | xargs || true)"
echo "  HTTP $status_code content-type=${ctype:-unknown}"

if [[ "$status_code" != "200" ]]; then
  echo "FAILED: /rest/status returned HTTP $status_code" >&2
  sed -n '1,20p' "$HEADERS_FILE" >&2 || true
  exit 2
fi

# Print a tiny bit of the JSON without dumping your whole controller state.
python3 - "$BODY_FILE" <<'PY'
import json
import sys
from pathlib import Path
p = Path(sys.argv[1])
try:
  obj = json.loads(p.read_text(errors='replace') or '{}')
  # Show a couple of stable-ish hints.
  if isinstance(obj, dict):
    print("  keys:", ", ".join(sorted(obj.keys())[:12]))
  else:
    print("  JSON parsed but not an object")
except Exception as e:
  print("FAILED: response was not JSON:", e)
  sys.exit(3)
PY


echo "OK"
