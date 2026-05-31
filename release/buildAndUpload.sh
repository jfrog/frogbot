#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../buildscripts/verifyArtifact.sh"

JF_SERVER_ID="${JF_SERVER_ID:-}"

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

build () {
  pkg="$1"
  export GOOS="$2"
  export GOARCH="$3"
  exeName="$4"
  echo "Building $exeName for $GOOS-$GOARCH ..."

  CGO_ENABLED=0 jf go build -o "$exeName" -ldflags '-w -extldflags "-static" -X github.com/jfrog/frogbot/v2/utils.FrogbotVersion='"$version"
  chmod +x "$exeName"

  if [[ "$VERSION_VERIFIED" -eq 0 ]] && [[ -n "$HOST_GOOS" ]] && [[ -n "$HOST_GOARCH" ]] \
    && [[ "$2" = "$HOST_GOOS" ]] && [[ "$3" = "$HOST_GOARCH" ]]; then
    verifyVersionMatching "$exeName"
    VERSION_VERIFIED=1
  fi
}

verify_upload() {
  local localFile="$1"
  local destPath="$2"
  echo "Verifying uploaded artifact ${localFile} using Artifactory file details ..."
  verifyArtifact_file --file "${localFile}" --repo-path "${destPath}" --jf-cli
}

buildAndUpload () {
  pkg="$1"
  goos="$2"
  goarch="$3"
  fileExtension="$4"
  exeName="frogbot$fileExtension"

  build "$pkg" "$goos" "$goarch" "$exeName"

  destPath="$pkgPath/$version/$pkg/$exeName"
  echo "Uploading $exeName to $destPath ..."
  jf rt u "./$exeName" "$destPath"
  verify_upload "./$exeName" "$destPath"
}

verifyVersionMatching () {
  local exe="$1"
  echo "Verifying provided version matches built version..."
  res=$("./${exe}" -v)
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

version="${1:?version argument required}"
pkgPath="ecosys-frogbot/v2"

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

if [[ "$VERSION_VERIFIED" -eq 0 ]] && [[ -n "$HOST_GOOS" ]] && [[ -n "$HOST_GOARCH" ]]; then
  echo "Warning: no build matched host ${HOST_GOOS}/${HOST_GOARCH}; embedded version check was skipped." >&2
fi

jf rt u "./buildscripts/getFrogbot.sh" "$pkgPath/$version/" --flat
