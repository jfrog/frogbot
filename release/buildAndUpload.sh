#!/bin/bash
set -eu

JF_SERVER_ID="${JF_SERVER_ID:-internal}"

#function build(pkg, goos, goarch, exeName)
build () {
  pkg="$1"
  export GOOS="$2"
  export GOARCH="$3"
  exeName="$4"
  echo "Building $exeName for $GOOS-$GOARCH ..."

  CGO_ENABLED=0 jf go build -o "$exeName" -ldflags '-w -extldflags "-static" -X github.com/jfrog/frogbot/v2/utils.FrogbotVersion='"$version"
  chmod +x "$exeName"

  # Run verification after building plugin for the correct platform of this image.
  if [[ "$pkg" = "frogbot-linux-386" ]]; then
    verifyVersionMatching
  fi
}

get_artifactory_download_url() {
  local destPath="$1"
  local artifactoryUrl
  artifactoryUrl=$(jf c show "${JF_SERVER_ID}" --format=json | sed -n 's/.*"url":"\([^"]*\)".*/\1/p' | head -1)
  if [[ -z "${artifactoryUrl}" ]]; then
    echo "Failed to resolve Artifactory URL from JFrog CLI server '${JF_SERVER_ID}'" >&2
    exit 1
  fi
  artifactoryUrl="${artifactoryUrl%/}"
  if [[ "${artifactoryUrl}" != */artifactory ]]; then
    artifactoryUrl="${artifactoryUrl}/artifactory"
  fi
  echo "${artifactoryUrl}/${destPath}"
}

verify_upload() {
  local localFile="$1"
  local destPath="$2"
  local downloadUrl
  downloadUrl=$(get_artifactory_download_url "${destPath}")
  echo "Verifying uploaded artifact ${localFile} using Artifactory file details ..."
  jf go run ./release/verifyartifact/ --url "${downloadUrl}" --file "${localFile}" --server-id "${JF_SERVER_ID}"
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

  # Get the version which is after the last space. (expected output to -v for example: "Frogbot version version v2.0.0")
  echo "Output: $res"
  builtVersion="${res##* }"
  # Compare versions
  if [[ "$builtVersion" != "$version" ]]; then
    echo "Versions dont match. Provided: $version, Actual: $builtVersion"
    exit 1
  fi
  echo "Versions match."
}

version="$1"
pkgPath="ecosys-frogbot/v2"

# Build and upload for every architecture.
# Keep 'linux-386' first to prevent unnecessary uploads in case the built version doesn't match the provided one.
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
