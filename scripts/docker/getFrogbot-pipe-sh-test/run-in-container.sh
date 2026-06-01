#!/bin/sh
set -eu

MOCK_PORT=8765
export FROGBOT_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
export MOCK_PORT

python3 /test/mock_server.py &
MOCK_PID=$!
trap 'kill "$MOCK_PID" 2>/dev/null || true' EXIT

sleep 1

echo "Alpine: $(cat /etc/os-release 2>/dev/null | head -1 || echo unknown)"
echo "sh: $(ls -l /bin/sh)"
echo "bash: $(command -v bash || echo missing)"
echo "python3: $(command -v python3 || echo missing)"
echo ""

echo "--- Expect BEFORE to fail (mapfile / process substitution under /bin/sh) ---"
set +e
before_out=$(cat /test/getFrogbot.before.sh | sh -s 2.0.0-test 2>&1)
before_code=$?
set -e
printf '%s\n' "$before_out" | tail -8
echo "exit code: ${before_code}"
if [ "${before_code}" -eq 0 ]; then
  echo "FAIL: BEFORE should exit non-zero"
  exit 1
fi
if ! printf '%s' "$before_out" | grep -qE 'Syntax error|redirection unexpected|mapfile: not found|Checksum verification failed|Failed to fetch Artifactory'; then
  echo "FAIL: BEFORE did not fail in the expected checksum/mapfile path"
  exit 1
fi
echo "PASS: BEFORE failed as expected under Alpine /bin/sh"
echo ""

echo "--- Expect AFTER to succeed (POSIX checksum parse under /bin/sh) ---"
after_out=$(cat /test/getFrogbot.after.sh | sh -s 2.0.0-test 2>&1)
after_code=$?
printf '%s\n' "$after_out" | tail -8
echo "exit code: ${after_code}"
if [ "${after_code}" -ne 0 ]; then
  echo "FAIL: AFTER should have succeeded"
  exit 1
fi
if ! printf '%s' "$after_out" | grep -q "Checksum verification passed"; then
  echo "FAIL: AFTER did not complete checksum verification"
  exit 1
fi
if printf '%s' "$after_out" | grep -qi "syntax error\|redirection unexpected"; then
  echo "FAIL: AFTER hit a sh syntax error"
  exit 1
fi
echo "PASS: AFTER completed without sh syntax error"
echo ""
echo "All pipe-to-sh tests passed."
