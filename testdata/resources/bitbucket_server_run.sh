#!/bin/bash

export BITBUCKET_VERSION=8.16.1
export BITBUCKET_HOME=${PWD}/bitbucketHome

# Download Bitbucket Server
curl -fLg https://www.atlassian.com/software/stash/downloads/binary/atlassian-bitbucket-$BITBUCKET_VERSION.tar.gz -O

# Extract Bitbucket Server
tar -xvzf atlassian-bitbucket-$BITBUCKET_VERSION.tar.gz

# Change directory to Bitbucket Server installation
cd atlassian-bitbucket-$BITBUCKET_VERSION

# Set Bitbucket home directory
./bin/set-bitbucket-home.sh

# Disable Mesh to avoid sidecar startup issues in containerized environments
export JVM_SUPPORT_RECOMMENDED_ARGS="-Dmesh.enabled=false ${JVM_SUPPORT_RECOMMENDED_ARGS}"

# Start Bitbucket Server
./bin/start-bitbucket.sh --no-search