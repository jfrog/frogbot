#!/bin/bash

FROGBOT_OS="na"
FILE_NAME="na"
VERSION="[RELEASE]"

if [ $# -eq 1 ]
then
    VERSION=$1
    echo "Downloading version $VERSION of Frogbot..."
else
    echo "Downloading the latest version of Frogbot..."
fi

if $(echo "${OSTYPE}" | grep -q msys); then
    FROGBOT_OS="windows"
    URL="https://releases.jfrog.io/artifactory/frogbot/v2/${VERSION}/frogbot-windows-amd64/frogbot.exe"
    FILE_NAME="frogbot.exe"
elif $(echo "${OSTYPE}" | grep -q darwin); then
    FROGBOT_OS="mac"
    URL="https://releases.jfrog.io/artifactory/frogbot/v2/${VERSION}/frogbot-mac-386/frogbot"
    FILE_NAME="frogbot"
else
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
    URL="https://releases.jfrog.io/artifactory/frogbot/v2/${VERSION}/frogbot-${FROGBOT_OS}-${ARCH}/frogbot"
    FILE_NAME="frogbot"
fi

curl -XGET "$URL" -L -k -g > $FILE_NAME
chmod u+x $FILE_NAME
