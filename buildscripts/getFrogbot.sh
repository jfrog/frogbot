#!/bin/bash

FROGBOT_OS="na"
FILE_NAME="na"
VERSION="[RELEASE]"
PLATFORM_URL="https://releases.jfrog.io"
if [ -n "${FROGBOT_BASE_URL:-}" ]; then
  PLATFORM_URL="${FROGBOT_BASE_URL%%/}"
fi

setFrogbotVersion() {
  if [ $# -eq 1 ]
  then
      VERSION=$1
      echo "Downloading version $VERSION of Frogbot..."
  elif [ -n "${JF_FROGBOT_VERSION:-}" ]
  then
      VERSION="${JF_FROGBOT_VERSION}"
      echo "Downloading version $VERSION of Frogbot (JF_FROGBOT_VERSION)..."
  else
      echo "Downloading the latest version of Frogbot..."
  fi
}

setFrogbotRemoteRepositoryIfNeeded() {
  if [ -n "${JF_RELEASES_REPO}" ]
  then
    PLATFORM_URL="${JF_URL%%/}"
    REMOTE_PATH="$JF_RELEASES_REPO/artifactory/"
  fi
}

setWindowsProperties() {
  FROGBOT_OS="windows"
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v2/${VERSION}/frogbot-windows-amd64/frogbot.exe"
  FILE_NAME="frogbot.exe"
}

setMacProperties() {
  FROGBOT_OS="mac"
  MACHINE_TYPE="$(uname -m)"
  case $MACHINE_TYPE in
      arm | armv7l | arm64 | aarch64)
          ARCH="arm64"
          ;;
      *)
          ARCH="386"
          ;;
  esac
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v2/${VERSION}/frogbot-${FROGBOT_OS}-${ARCH}/frogbot"
  FILE_NAME="frogbot"
}

setLinuxProperties() {
  FROGBOT_OS="linux"
  MACHINE_TYPE="$(uname -m)"
  case $MACHINE_TYPE in
      i386 | i486 | i586 | i686 | i786 | x86)
          ARCH="386"
          ;;
      amd64 | x86_64 | x64)
          ARCH="amd64"
          ;;
      arm | armv7l)
          ARCH="arm"
          ;;
      aarch64)
          ARCH="arm64"
          ;;
      s390x)
          ARCH="s390x"
          ;;
      ppc64)
         ARCH="ppc64"
         ;;
      ppc64le)
         ARCH="ppc64le"
         ;;
      *)
          echo "Unknown machine type: $MACHINE_TYPE"
          exit 1
          ;;
  esac
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v2/${VERSION}/frogbot-${FROGBOT_OS}-${ARCH}/frogbot"
  FILE_NAME="frogbot"
}

setFrogbotDownloadProperties() {
  if echo "${OSTYPE}" | grep -q msys; then
    setWindowsProperties
  elif echo "${OSTYPE}" | grep -q darwin; then
    setMacProperties
  else
    setLinuxProperties
  fi
}

setPermissions() {
  chmod u+x "${FILE_NAME}"
}

echoGreetings() {
  echo "Frogbot downloaded successfully!"
}

download_to() {
  dl_url="$1"
  dl_out="$2"
  if [ -n "${JF_ACCESS_TOKEN:-}" ]; then
    curl -fLg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" -X GET "${dl_url}" -o "${dl_out}"
  elif [ -n "${JF_USER:-}" ]; then
    curl -fLg -u "${JF_USER}:${JF_PASSWORD:-}" -X GET "${dl_url}" -o "${dl_out}"
  else
    curl -fLg -X GET "${dl_url}" -o "${dl_out}"
  fi
}

head_request() {
  dl_url="$1"
  if [ -n "${JF_ACCESS_TOKEN:-}" ]; then
    curl -sfILg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" "${dl_url}"
  elif [ -n "${JF_USER:-}" ]; then
    curl -sfILg -u "${JF_USER}:${JF_PASSWORD:-}" "${dl_url}"
  else
    curl -sfILg "${dl_url}"
  fi
}

artifact_url_to_storage_url() {
  local prefix suffix
  case "${1}" in
    */artifactory/*)
      prefix="${1%%/artifactory/*}"
      suffix="${1#*/artifactory/}"
      suffix="${suffix%%\?*}"
      echo "${prefix}/artifactory/api/storage/${suffix}"
      return 0
      ;;
  esac
  return 1
}

storage_request() {
  local storage_url="$1"
  if [ -n "${JF_ACCESS_TOKEN:-}" ]; then
    curl -sfLg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" "${storage_url}"
  elif [ -n "${JF_USER:-}" ]; then
    curl -sfLg -u "${JF_USER}:${JF_PASSWORD:-}" "${storage_url}"
  else
    curl -sfLg "${storage_url}"
  fi
}

get_header_value() {
  header_name="$1"
  echo "$2" | awk -v header="$header_name" '
    BEGIN { IGNORECASE=1; value="" }
    $1 ~ header":" { sub(/^[^:]+:[[:space:]]*/, ""); value=$0 }
    END { gsub(/\r/, "", value); print value }
  '
}

parse_storage_checksums() {
  json="$1"
  local _cs
  if command -v jq >/dev/null 2>&1; then
    remote_md5=$(echo "${json}" | jq -r '.checksums.md5 // empty')
    remote_sha1=$(echo "${json}" | jq -r '.checksums.sha1 // empty')
    remote_sha256=$(echo "${json}" | jq -r '.checksums.sha256 // empty')
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    _cs=$(echo "${json}" | python3 -c 'import json,sys; c=json.load(sys.stdin).get("checksums",{}); print(c.get("md5") or ""); print(c.get("sha1") or ""); print(c.get("sha256") or "")')
    remote_md5=$(printf '%s\n' "${_cs}" | sed -n '1p')
    remote_sha1=$(printf '%s\n' "${_cs}" | sed -n '2p')
    remote_sha256=$(printf '%s\n' "${_cs}" | sed -n '3p')
    return 0
  fi
  return 1
}

stderr_indicates_auth_failure() {
  [ -f "$1" ] && grep -qiE '401|403|Unauthorized|Forbidden' "$1"
}

load_remote_checksums_from_headers() {
  headers="$1"
  remote_md5=$(get_header_value "X-Checksum-Md5" "${headers}")
  remote_sha1=$(get_header_value "X-Checksum-Sha1" "${headers}")
  remote_sha256=$(get_header_value "X-Checksum-Sha256" "${headers}")
  [ -n "${remote_md5}" ] && [ -n "${remote_sha1}" ]
}

load_remote_checksums() {
  local headers json storage_url head_err

  remote_md5=""
  remote_sha1=""
  remote_sha256=""

  head_err=$(mktemp "${TMPDIR:-/tmp}/frogbot-head.XXXXXX")
  if headers=$(head_request "${URL}" 2>"${head_err}") && load_remote_checksums_from_headers "${headers}"; then
    rm -f "${head_err}"
    return 0
  fi
  if stderr_indicates_auth_failure "${head_err}"; then
    echo "Artifactory HEAD request was rejected (401/403). Check JF_ACCESS_TOKEN or JF_USER/JF_PASSWORD." >&2
    rm -f "${head_err}"
    return 1
  fi
  rm -f "${head_err}"

  if ! storage_url=$(artifact_url_to_storage_url "${URL}"); then
    echo "Cannot derive Artifactory Storage API URL from ${URL}." >&2
    return 1
  fi

  echo "Checksum headers not returned by HEAD; using Artifactory Storage API ..." >&2
  if ! json=$(storage_request "${storage_url}"); then
    echo "Failed to fetch Artifactory storage metadata from ${storage_url}." >&2
    return 1
  fi
  if ! parse_storage_checksums "${json}"; then
    echo "jq or python3 is required to parse Artifactory storage metadata." >&2
    return 1
  fi
  if [ -z "${remote_md5}" ] || [ -z "${remote_sha1}" ]; then
    echo "Artifactory storage metadata did not include md5/sha1 checksums." >&2
    return 1
  fi
  return 0
}

local_md5() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" | awk '{print $1}'
  else
    md5 -q "$1"
  fi
}

local_sha1() {
  if command -v sha1sum >/dev/null 2>&1; then
    sha1sum "$1" | awk '{print $1}'
  else
    shasum -a 1 "$1" | awk '{print $1}'
  fi
}

local_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify_download_or_exit() {
  if [ "${FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION:-}" = "1" ]; then
    echo "WARNING: skipping checksum verification (FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION=1)." >&2
    echo "Downloaded ${FILE_NAME} (checksum verification skipped)."
    return 0
  fi

  if ! load_remote_checksums; then
    echo "Failed to fetch Artifactory file details for this Frogbot build." >&2
    rm -f "${FILE_NAME}"
    exit 1
  fi

  file_md5=$(local_md5 "${FILE_NAME}")
  file_sha1=$(local_sha1 "${FILE_NAME}")
  file_sha256=$(local_sha256 "${FILE_NAME}")
  if [ "${file_md5}" != "${remote_md5}" ] || [ "${file_sha1}" != "${remote_sha1}" ] \
    || { [ -n "${remote_sha256}" ] && [ "${file_sha256}" != "${remote_sha256}" ]; }; then
    echo "Checksum verification failed." >&2
    echo "Remote md5=${remote_md5} sha1=${remote_sha1} sha256=${remote_sha256}" >&2
    echo "Local  md5=${file_md5} sha1=${file_sha1} sha256=${file_sha256}" >&2
    rm -f "${FILE_NAME}"
    exit 1
  fi

  echo "Checksum verification passed for ${FILE_NAME}."
}

download() {
  echo "Downloading from ${URL} ..."
  download_to "${URL}" "${FILE_NAME}" || { rm -f "${FILE_NAME}"; exit 1; }
  verify_download_or_exit
  setPermissions && echoGreetings
}

setFrogbotVersion "$@"
setFrogbotRemoteRepositoryIfNeeded
setFrogbotDownloadProperties
download
