#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

export PATH="${HOME}/.rd/bin:/usr/local/bin:${PATH}"

git show HEAD:buildscripts/getFrogbot.sh >"${SCRIPT_DIR}/getFrogbot.before.sh"
cp "${REPO_ROOT}/buildscripts/getFrogbot.sh" "${SCRIPT_DIR}/getFrogbot.after.sh"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. Install Docker or Rancher Desktop, then re-run." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running. Start Docker Desktop / Rancher Desktop, then re-run:" >&2
  echo "  ${SCRIPT_DIR}/run-test.sh" >&2
  exit 1
fi

IMAGE="frogbot-getfrogbot-pipe-sh-test:local"
echo "Building ${IMAGE} (bare Alpine 3.20 + curl + python3 only) ..."
docker build -t "${IMAGE}" "${SCRIPT_DIR}"

echo ""
echo "Running container (pipe getFrogbot.sh to sh, like CI) ..."
docker run --rm "${IMAGE}"
