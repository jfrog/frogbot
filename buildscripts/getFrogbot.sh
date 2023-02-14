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
  if [[ -n "${JF_REMOTE_REPO}" ]]
  then
    PLATFORM_URL="${JF_URL%/}"
    REMOTE_PATH="$JF_REMOTE_REPO/artifactory/"
  fi
}

setWindowsProperties() {
  FROGBOT_OS="windows"
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v2/${VERSION}/frogbot-windows-amd64/frogbot.exe"
  FILE_NAME="frogbot.exe"
}

setMacProperties() {
  FROGBOT_OS="mac"
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v2/${VERSION}/frogbot-mac-386/frogbot"
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
          exit -1
          ;;
  esac
  URL="${PLATFORM_URL}/artifactory/${REMOTE_PATH}frogbot/v2/${VERSION}/frogbot-${FROGBOT_OS}-${ARCH}/frogbot"
  FILE_NAME="frogbot"
}

setFrogbotDownloadProperties() {
  if $(echo "${OSTYPE}" | grep -q msys); then
    setWindowsProperties
  elif $(echo "${OSTYPE}" | grep -q darwin); then
    setMacProperties
  else
    setLinuxProperties
  fi
}

setCurlArgs() {
  if [[ -n ${REMOTE_PATH} ]]; then
    if [[ -n ${JF_ACCESS_TOKEN} ]]; then
      CURL_ARGS=(-XGET "$URL" -L -k -g -H "Authorization: Bearer ${JF_ACCESS_TOKEN}")
    else
      CURL_ARGS=(-XGET -u "${JF_USER}":"${JF_PASSWORD}" "$URL" -L -k -g)
    fi
  else
    CURL_ARGS=(-XGET "$URL" -L -k -g)
  fi
}

downloadFrogbot() {
  curl "${CURL_ARGS[@]}" > $FILE_NAME
  chmod u+x $FILE_NAME
}

setFrogbotVersion "$@"
setFrogbotRemoteRepositoryIfNeeded
setFrogbotDownloadProperties
setCurlArgs
downloadFrogbot
