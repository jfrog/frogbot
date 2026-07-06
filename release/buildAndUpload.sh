#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

case "$(uname -s)" in
  Darwin) HOST_GOOS=darwin ;;
  Linux) HOST_GOOS=linux ;;
  CYGWIN*|MINGW*|MSYS*) HOST_GOOS=windows ;;
  *) HOST_GOOS= ;;
esac
case "$(uname -m)" in
  x86_64|amd64) HOST_GOARCH=amd64 ;;
  arm64|aarch64) HOST_GOARCH=arm64 ;;
  i386|i686) HOST_GOARCH=386 ;;
  armv7l) HOST_GOARCH=arm ;;
  *) HOST_GOARCH= ;;
esac

VERSION_VERIFIED=0
OUTPUT_ROOT=""
LAST_OUT_PATH=""

build () {
  pkg="$1"
  export GOOS="$2"
  export GOARCH="$3"
  exeName="$4"
  local outDir="${OUTPUT_ROOT}/${pkg}"
  mkdir -p "$outDir"
  LAST_OUT_PATH="${outDir}/${exeName}"
  echo "Building ${LAST_OUT_PATH} for ${GOOS}-${GOARCH} ..."

  CGO_ENABLED=0 jf go build -trimpath -o "$LAST_OUT_PATH" -ldflags '-w -extldflags "-static" -X github.com/jfrog/frogbot/v3/utils.FrogbotVersion='"$version"
  chmod +x "$LAST_OUT_PATH"

  if [[ "$VERSION_VERIFIED" -eq 0 ]] && [[ -n "$HOST_GOOS" ]] && [[ -n "$HOST_GOARCH" ]] \
    && [[ "$2" = "$HOST_GOOS" ]] && [[ "$3" = "$HOST_GOARCH" ]]; then
    verifyVersionMatching "$LAST_OUT_PATH"
    VERSION_VERIFIED=1
  fi
}

buildAndUpload () {
  pkg="$1"
  goos="$2"
  goarch="$3"
  fileExtension="$4"
  exeName="frogbot$fileExtension"

  build "$pkg" "$goos" "$goarch" "$exeName"

  sha256sum "$LAST_OUT_PATH" >"${LAST_OUT_PATH}.sha256"
  if [[ -n "${FROGBOT_GPG_KEY_ID:-}" ]] && command -v gpg >/dev/null 2>&1; then
    gpg --batch --yes --local-user "$FROGBOT_GPG_KEY_ID" --detach-sign --armor -o "${LAST_OUT_PATH}.asc" "$LAST_OUT_PATH"
  fi

  destPath="${pkgPath}/${version}/${pkg}/${exeName}"
  jf rt u "${LAST_OUT_PATH}" "${destPath}"
}

verifyVersionMatching () {
  local exe="$1"
  echo "Verifying provided version matches built version..."
  res=$("$exe" -v)
  exitCode=$?
  if [[ $exitCode -ne 0 ]]; then
    echo "Error: Failed verifying version matches"
    exit $exitCode
  fi

  echo "Output: $res"
  builtVersion="${res##* }"
  if [[ "$builtVersion" != "$version" ]]; then
    echo "Versions dont match. Provided: $version, Actual: $builtVersion"
    exit 1
  fi
  echo "Versions match."
}

version="${1:?version argument required, e.g. 2.0.0-test}"
pkgPath="jfs-frogbot-releases-local/v3"
OUTPUT_ROOT="${REPO_ROOT}/v3/${version}"
mkdir -p "$OUTPUT_ROOT"
echo "Local artifacts: ${OUTPUT_ROOT}/"

if [[ -z "$HOST_GOOS" ]] || [[ -z "$HOST_GOARCH" ]]; then
  echo "Warning: unknown host OS/arch; skipping embedded version check (builds still run)." >&2
fi

buildAndUpload 'frogbot-linux-386' 'linux' '386' ''
buildAndUpload 'frogbot-linux-amd64' 'linux' 'amd64' ''
buildAndUpload 'frogbot-linux-s390x' 'linux' 's390x' ''
buildAndUpload 'frogbot-linux-arm64' 'linux' 'arm64' ''
buildAndUpload 'frogbot-linux-arm' 'linux' 'arm' ''
buildAndUpload 'frogbot-linux-ppc64' 'linux' 'ppc64' ''
buildAndUpload 'frogbot-linux-ppc64le' 'linux' 'ppc64le' ''
buildAndUpload 'frogbot-mac-386' 'darwin' 'amd64' ''
buildAndUpload 'frogbot-mac-arm64' 'darwin' 'arm64' ''
buildAndUpload 'frogbot-windows-amd64' 'windows' 'amd64' '.exe'

if [[ -n "${FROGBOT_GPG_PUBLIC_KEY_FILE:-}" ]] && [[ -f "${FROGBOT_GPG_PUBLIC_KEY_FILE}" ]]; then
  cp "${FROGBOT_GPG_PUBLIC_KEY_FILE}" "${OUTPUT_ROOT}/frogbot-signing-key.asc"
  jf rt u "${OUTPUT_ROOT}/frogbot-signing-key.asc" "${pkgPath}/${version}/frogbot-signing-key.asc"
fi
jf rt u "./buildscripts/getFrogbot.sh" "${pkgPath}/${version}/" --flat

echo "Done. Artifacts ready at: ${OUTPUT_ROOT}/"
