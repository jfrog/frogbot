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
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v3/${VERSION}/frogbot-windows-amd64/frogbot.exe"
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
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v3/${VERSION}/frogbot-${FROGBOT_OS}-${ARCH}/frogbot"
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
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v3/${VERSION}/frogbot-${FROGBOT_OS}-${ARCH}/frogbot"
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

download_optional() {
  dl_url="$1"
  dl_out="$2"
  if [ -n "${REMOTE_PATH}" ]; then
      if [ -n "${JF_ACCESS_TOKEN}" ]; then
        curl -sfLg -H "Authorization:Bearer ${JF_ACCESS_TOKEN}" -X GET "${dl_url}" -o "${dl_out}" && return 0
      else
        curl -sfLg -u "${JF_USER}:${JF_PASSWORD}" -X GET "${dl_url}" -o "${dl_out}" && return 0
      fi
    else
      curl -sfLg -X GET "${dl_url}" -o "${dl_out}" && return 0
    fi
  return 1
}

verify_checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "${FILE_NAME}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "${FILE_NAME}.sha256"
  else
    echo "Neither sha256sum nor shasum was found; cannot verify the binary checksum." >&2
    return 1
  fi
}

verify_checksum_or_exit() {
  if [ "${FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION:-}" = "1" ]; then
    echo "WARNING: skipping checksum verification (FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION=1)." >&2
    return 0
  fi
  checksum_url="${URL}.sha256"
  if ! download_to "${checksum_url}" "${FILE_NAME}.sha256"; then
    echo "Failed to download the checksum file for this Frogbot build." >&2
    echo "Releases that predate checksum publishing require FROGBOT_INSECURE_SKIP_CHECKSUM_VERIFICATION=1 (not recommended)." >&2
    rm -f "${FILE_NAME}"
    exit 1
  fi
  if ! verify_checksum; then
    echo "Checksum verification failed." >&2
    rm -f "${FILE_NAME}" "${FILE_NAME}.sha256"
    exit 1
  fi
  rm -f "${FILE_NAME}.sha256"
}

verify_gpg_if_signature_present() {
  sig_url="${URL}.asc"
  if ! download_optional "${sig_url}" "${FILE_NAME}.asc"; then
    rm -f "${FILE_NAME}.asc"
    return 0
  fi
  key_url="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v3/${VERSION}/frogbot-signing-key.asc"
  if ! download_optional "${key_url}" "frogbot-signing-key.asc"; then
    echo "A detached signature was published but frogbot-signing-key.asc could not be downloaded for this release." >&2
    rm -f "${FILE_NAME}" "${FILE_NAME}.asc"
    exit 1
  fi
  if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required to verify the Frogbot release signature." >&2
    rm -f "${FILE_NAME}" "${FILE_NAME}.asc" "frogbot-signing-key.asc"
    exit 1
  fi
  GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/frogbot-gpg.XXXXXX")
  export GNUPGHOME
  gpg --batch --import "frogbot-signing-key.asc" >/dev/null 2>&1
  if ! gpg --batch --verify "${FILE_NAME}.asc" "${FILE_NAME}"; then
    echo "GPG signature verification failed." >&2
    rm -rf "${GNUPGHOME}"
    rm -f "${FILE_NAME}" "${FILE_NAME}.asc" "frogbot-signing-key.asc"
    exit 1
  fi
  rm -rf "${GNUPGHOME}"
  rm -f "${FILE_NAME}.asc" "frogbot-signing-key.asc"
}

download() {
  download_to "${URL}" "${FILE_NAME}" || { rm -f "${FILE_NAME}"; exit 1; }
  verify_checksum_or_exit
  verify_gpg_if_signature_present
  setPermissions && echoGreetings
}

setFrogbotVersion "$@"
setFrogbotRemoteRepositoryIfNeeded
setFrogbotDownloadProperties
download
