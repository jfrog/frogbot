#!/bin/bash

FROGBOT_OS="na"
FILE_NAME="na"
VERSION="[RELEASE]"
PLATFORM_URL="https://releases.jfrog.io"

setFrogbotVersion() {
  if [ $# -eq 1 ]
  then
      VERSION=$1
      echo "Downloading version $VERSION of Frogbot..."
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
  if [ -n "${REMOTE_PATH}" ]; then
      if [ -n "${JF_ACCESS_TOKEN}" ]; then
        curl -fLg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" -X GET "${dl_url}" -o "${dl_out}"
      else
        curl -fLg -u "${JF_USER}:${JF_PASSWORD}" -X GET "${dl_url}" -o "${dl_out}"
      fi
    else
      curl -fLg -X GET "${dl_url}" -o "${dl_out}"
    fi
}

head_request() {
  dl_url="$1"
  if [ -n "${REMOTE_PATH}" ]; then
      if [ -n "${JF_ACCESS_TOKEN}" ]; then
        curl -sfILg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" "${dl_url}"
      else
        curl -sfILg -u "${JF_USER}:${JF_PASSWORD}" "${dl_url}"
      fi
    else
      curl -sfILg "${dl_url}"
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

  headers=$(head_request "${URL}") || {
    echo "Failed to fetch Artifactory file details for this Frogbot build." >&2
    rm -f "${FILE_NAME}"
    exit 1
  }

  remote_md5=$(get_header_value "X-Checksum-Md5" "${headers}")
  remote_sha1=$(get_header_value "X-Checksum-Sha1" "${headers}")
  remote_sha256=$(get_header_value "X-Checksum-Sha256" "${headers}")

  if [ -z "${remote_md5}" ] || [ -z "${remote_sha1}" ]; then
    echo "Artifactory did not return checksum headers; cannot verify the downloaded binary." >&2
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
