#!/usr/bin/env bash
# Fallback when Docker is unavailable: Alpine's /bin/sh is ash/dash; macOS dash behaves the same
# for the mapfile/process-substitution syntax error.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

SH_BIN="${SH_BIN:-}"
if [[ -z "${SH_BIN}" ]]; then
  if command -v dash >/dev/null 2>&1; then
    SH_BIN="$(command -v dash)"
  elif [[ -x /bin/dash ]]; then
    SH_BIN=/bin/dash
  else
    echo "Install dash (brew install dash) or run ./run-test.sh with Docker." >&2
    exit 1
  fi
fi

git show HEAD:buildscripts/getFrogbot.sh >"${SCRIPT_DIR}/getFrogbot.before.sh"
cp "${REPO_ROOT}/buildscripts/getFrogbot.sh" "${SCRIPT_DIR}/getFrogbot.after.sh"

MOCK_PORT=8765
export FROGBOT_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
export MOCK_PORT
if [[ "$(uname -s)" == "Darwin" ]]; then
  export OSTYPE=darwin
fi

python3 "${SCRIPT_DIR}/mock_server.py" &
MOCK_PID=$!
trap 'kill "$MOCK_PID" 2>/dev/null || true' EXIT
sleep 1

echo "Using sh: ${SH_BIN} ($("${SH_BIN}" -c 'echo ok' 2>&1 || true))"
echo ""

echo "--- BEFORE (expect syntax error) ---"
set +e
before_out=$(cat "${SCRIPT_DIR}/getFrogbot.before.sh" | "${SH_BIN}" -s 2.0.0-test 2>&1)
before_code=$?
set -e
printf '%s\n' "$before_out" | tail -5
echo "exit code: ${before_code}"
if [ "${before_code}" -eq 0 ]; then
  echo "FAIL: BEFORE should exit non-zero"
  exit 1
fi
if ! printf '%s' "$before_out" | grep -qE 'Syntax error|redirection unexpected|mapfile: not found|Checksum verification failed'; then
  echo "FAIL: expected mapfile/syntax/checksum failure"
  exit 1
fi
echo "PASS: BEFORE failed as expected"
echo ""

echo "--- AFTER (expect success) ---"
set +e
after_out=$(cat "${SCRIPT_DIR}/getFrogbot.after.sh" | "${SH_BIN}" -s 2.0.0-test 2>&1)
after_code=$?
set -e
printf '%s\n' "$after_out" | tail -8
echo "exit code: ${after_code}"
if [[ "${after_code}" -ne 0 ]]; then
  echo "FAIL: AFTER should exit 0"
  exit 1
fi
if ! printf '%s' "$after_out" | grep -q "Checksum verification passed"; then
  echo "FAIL: AFTER did not verify checksums"
  exit 1
fi
if printf '%s' "$after_out" | grep -qE 'Syntax error|redirection unexpected'; then
  echo "FAIL: AFTER still hit syntax error"
  exit 1
fi
echo "PASS: AFTER succeeded"
echo ""
echo "Local dash simulation passed (use ./run-test.sh for real Alpine)."
