#!/bin/bash
set -eu

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
    verifyVersionMatching "$exeName"
  fi
}

#function buildAndUpload(pkg, goos, goarch, fileExtension)
buildAndUpload () {
  pkg="$1"
  goos="$2"
  goarch="$3"
  fileExtension="$4"
  # Use unique filename during build to avoid parallel conflicts
  uniqueExeName="${pkg}${fileExtension}"
  finalExeName="frogbot$fileExtension"

  build "$pkg" "$goos" "$goarch" "$uniqueExeName"

  destPath="$pkgPath/$version/$pkg/$finalExeName"
  echo "Uploading $uniqueExeName to $destPath ..."
  jf rt u "./$uniqueExeName" "$destPath"
  
  # Clean up the unique build file after upload
  rm -f "./$uniqueExeName"
}

# Verify version provided in pipelines UI matches version in frogbot source code.
# Takes the executable name as parameter
verifyVersionMatching () {
  local exePath="$1"
  echo "Verifying provided version matches built version..."
  res=$(eval "./$exePath -v")
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
# Extract major version (e.g., "3.1.1" -> "3")
majorVersion="${version%%.*}"
# Allow overriding repository name via environment variable
repoName="${FROGBOT_REPO_NAME:-ecosys-frogbot}"
pkgPath="${repoName}/v${majorVersion}"

# Build and upload for every architecture.
# Keep 'linux-386' first to prevent unnecessary uploads in case the built version doesn't match the provided one.
echo "Building linux-386 first for version verification..."
buildAndUpload 'frogbot-linux-386' 'linux' '386' ''

# Build the rest in parallel for speed
echo ""
echo "Building remaining 9 platforms in parallel..."
pids=()

buildAndUpload 'frogbot-linux-amd64' 'linux' 'amd64' '' & pids+=($!)
buildAndUpload 'frogbot-linux-s390x' 'linux' 's390x' '' & pids+=($!)
buildAndUpload 'frogbot-linux-arm64' 'linux' 'arm64' '' & pids+=($!)
buildAndUpload 'frogbot-linux-arm' 'linux' 'arm' '' & pids+=($!)
buildAndUpload 'frogbot-linux-ppc64' 'linux' 'ppc64' '' & pids+=($!)
buildAndUpload 'frogbot-linux-ppc64le' 'linux' 'ppc64le' '' & pids+=($!)
buildAndUpload 'frogbot-mac-386' 'darwin' 'amd64' '' & pids+=($!)
buildAndUpload 'frogbot-mac-arm64' 'darwin' 'arm64' '' & pids+=($!)
buildAndUpload 'frogbot-windows-amd64' 'windows' 'amd64' '.exe' & pids+=($!)

# Wait for all background jobs and check for failures
echo "Waiting for all parallel builds to complete..."
failed=0
for pid in "${pids[@]}"; do
  wait $pid || failed=1
done

if [ $failed -eq 1 ]; then
  echo "❌ One or more builds failed!"
  exit 1
fi

echo ""
echo "✅ All builds completed successfully!"
echo ""

jf rt u "./buildscripts/getFrogbot.sh" "$pkgPath/$version/" --flat

