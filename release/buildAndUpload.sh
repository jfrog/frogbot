#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../buildscripts/verifyArtifact.sh"

JF_SERVER_ID="${JF_SERVER_ID:-}"

#function build(pkg, goos, goarch, exeName)
build () {
  pkg="$1"
  export GOOS="$2"
  export GOARCH="$3"
  exeName="$4"
  echo "Building $exeName for $GOOS-$GOARCH ..."

  CGO_ENABLED=0 jf go build -o "$exeName" -ldflags '-w -extldflags "-static" -X github.com/jfrog/frogbot/v2/utils.FrogbotVersion='"$version"
  chmod +x "$exeName"
}

verify_upload() {
  local localFile="$1"
  local destPath="$2"
  echo "Verifying uploaded artifact ${localFile} using Artifactory file details ..."
  verifyArtifact_file --file "${localFile}" --repo-path "${destPath}" --jf-cli
}

#function buildAndUpload(pkg, goos, goarch, fileExtension)
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

# Verify version provided in pipelines UI matches version in frogbot source code.
verifyVersionMatching () {
  echo "Verifying provided version matches built version..."
  res=$(eval "./frogbot -v")
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

version="$1"
pkgPath="ecosys-frogbot/v2"

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

jf rt u "./buildscripts/getFrogbot.sh" "$pkgPath/$version/" --flat
