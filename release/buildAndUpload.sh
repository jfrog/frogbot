#!/bin/bash
set -eu

# Optional: set JF_SERVER_ID to a specific JFrog CLI server; otherwise the default configured server is used.
JF_SERVER_ID="${JF_SERVER_ID:-}"
VERIFY_TOOL=""

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
#  if [[ "$pkg" = "frogbot-linux-386" ]]; then
#    verifyVersionMatching
#  fi
}

get_jfrog_config_json() {
  if [[ -n "${JF_SERVER_ID}" ]]; then
    jf c show "${JF_SERVER_ID}" --format=json
  else
    jf c show --format=json
  fi
}

extract_artifactory_url_from_config() {
  local configJson="$1"
  local artifactoryUrl=""

  if command -v jq >/dev/null 2>&1; then
    artifactoryUrl=$(printf '%s\n' "${configJson}" | jq -r '([.[] | select(.isDefault == true)][0] // .[0]) | .artifactoryUrl // empty' | head -1)
    if [[ -z "${artifactoryUrl}" ]]; then
      local baseUrl
      baseUrl=$(printf '%s\n' "${configJson}" | jq -r '([.[] | select(.isDefault == true)][0] // .[0]) | .url // empty' | head -1)
      if [[ -n "${baseUrl}" ]]; then
        artifactoryUrl="${baseUrl%/}/artifactory/"
      fi
    fi
  else
    artifactoryUrl=$(printf '%s\n' "${configJson}" | grep -E '"artifactoryUrl"[[:space:]]*:' | head -1 | sed -E 's/.*"artifactoryUrl"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
    if [[ -z "${artifactoryUrl}" ]]; then
      local baseUrl
      baseUrl=$(printf '%s\n' "${configJson}" | grep -E '"url"[[:space:]]*:' | head -1 | sed -E 's/.*"url"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
      if [[ -n "${baseUrl}" ]]; then
        artifactoryUrl="${baseUrl%/}/artifactory/"
      fi
    fi
  fi

  artifactoryUrl="${artifactoryUrl%/}"
  if [[ "${artifactoryUrl}" != http://* && "${artifactoryUrl}" != https://* ]]; then
    return 1
  fi
  printf '%s' "${artifactoryUrl}"
}

get_artifactory_download_url() {
  local destPath="$1"
  local configJson artifactoryUrl
  if [[ -n "${JF_ARTIFACTORY_URL:-}" ]]; then
    artifactoryUrl="${JF_ARTIFACTORY_URL%/}"
  else
    if ! configJson=$(get_jfrog_config_json 2>&1); then
      echo "Failed to read JFrog CLI configuration. Run 'jf c add' or set JF_ARTIFACTORY_URL / JF_SERVER_ID." >&2
      echo "${configJson}" >&2
      exit 1
    fi
    if ! artifactoryUrl=$(extract_artifactory_url_from_config "${configJson}"); then
      if [[ -n "${JF_SERVER_ID}" ]]; then
        echo "Failed to resolve Artifactory URL from JFrog CLI server '${JF_SERVER_ID}'." >&2
      else
        echo "Failed to resolve Artifactory URL from the default JFrog CLI server." >&2
      fi
      exit 1
    fi
  fi
  echo "${artifactoryUrl}/${destPath}"
}

build_verify_tool() {
  local hostGoos hostGoarch
  # jf go env may print info logs to stdout; use the last line which holds the actual value.
  hostGoos="$(jf go env GOHOSTOS 2>&1 | tail -1)"
  hostGoarch="$(jf go env GOHOSTARCH 2>&1 | tail -1)"
  VERIFY_TOOL="$(mktemp -t verifyartifact.XXXXXX)"
  echo "Building upload verification tool for ${hostGoos}-${hostGoarch} ..."
  GOOS="${hostGoos}" GOARCH="${hostGoarch}" CGO_ENABLED=0 jf go build -o "${VERIFY_TOOL}" ./release/verifyartifact/
}

verify_upload() {
  local localFile="$1"
  local destPath="$2"
  local downloadUrl
  if [[ -z "${VERIFY_TOOL}" || ! -x "${VERIFY_TOOL}" ]]; then
    build_verify_tool
  fi
  downloadUrl=$(get_artifactory_download_url "${destPath}")
  echo "Verifying uploaded artifact ${localFile} using Artifactory file details ..."
  if [[ -n "${JF_SERVER_ID}" ]]; then
    "${VERIFY_TOOL}" --url "${downloadUrl}" --file "${localFile}" --server-id "${JF_SERVER_ID}"
  else
    "${VERIFY_TOOL}" --url "${downloadUrl}" --file "${localFile}"
  fi
}

cleanup() {
  if [[ -n "${VERIFY_TOOL}" && -f "${VERIFY_TOOL}" ]]; then
    rm -f "${VERIFY_TOOL}"
  fi
}
trap cleanup EXIT

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

build_verify_tool

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
