package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/dependencies"
	"github.com/jfrog/jfrog-client-go/http/httpclient"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
)

func VerifyLocalFileMatchesRemote(downloadURL, localPath, serverID string) error {
	remoteDetails, err := getRemoteFileDetails(downloadURL, serverID)
	if err != nil {
		return fmt.Errorf("failed to get remote file details for %q: %w", downloadURL, err)
	}
	if remoteDetails == nil {
		return fmt.Errorf("remote file details are nil for %q", downloadURL)
	}
	if remoteDetails.Checksum.Md5 == "" || remoteDetails.Checksum.Sha1 == "" {
		return fmt.Errorf("remote checksums are missing for %q (md5=%q sha1=%q)", downloadURL, remoteDetails.Checksum.Md5, remoteDetails.Checksum.Sha1)
	}

	localDetails, err := fileutils.GetFileDetails(localPath, true)
	if err != nil {
		return fmt.Errorf("failed to read local file details for %q: %w", localPath, err)
	}

	if localDetails.Checksum.Md5 != remoteDetails.Checksum.Md5 ||
		localDetails.Checksum.Sha1 != remoteDetails.Checksum.Sha1 ||
		(remoteDetails.Checksum.Sha256 != "" && localDetails.Checksum.Sha256 != remoteDetails.Checksum.Sha256) {
		return fmt.Errorf("checksum mismatch for %q: remote md5=%s sha1=%s sha256=%s, local md5=%s sha1=%s sha256=%s",
			localPath,
			remoteDetails.Checksum.Md5, remoteDetails.Checksum.Sha1, remoteDetails.Checksum.Sha256,
			localDetails.Checksum.Md5, localDetails.Checksum.Sha1, localDetails.Checksum.Sha256)
	}

	return nil
}

func getRemoteFileDetails(downloadURL, serverID string) (*fileutils.FileDetails, error) {
	if strings.TrimSpace(serverID) != "" {
		return getRemoteFileDetailsAuthenticated(downloadURL, serverID)
	}
	return getRemoteFileDetailsAnonymous(downloadURL)
}

func getRemoteFileDetailsAuthenticated(downloadURL, serverID string) (*fileutils.FileDetails, error) {
	rtDetails, err := config.GetSpecificConfig(serverID, false, true)
	if err != nil {
		return nil, err
	}
	client, httpClientDetails, err := dependencies.CreateHttpClient(rtDetails)
	if err != nil {
		return nil, err
	}
	remoteDetails, _, err := client.GetRemoteFileDetails(downloadURL, &httpClientDetails)
	return remoteDetails, err
}

func getRemoteFileDetailsAnonymous(downloadURL string) (*fileutils.FileDetails, error) {
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return nil, err
	}
	remoteDetails, _, err := client.GetRemoteFileDetails(downloadURL, httputils.HttpClientDetails{})
	return remoteDetails, err
}

// Small program that fetches Artifactory checksums via GetRemoteFileDetails() function and confirms the local file matches before the release continues.
func main() {
	downloadURL := flag.String("url", "", "Artifactory download URL of the uploaded artifact")
	localPath := flag.String("file", "", "Local file path to verify")
	serverID := flag.String("server-id", "internal", "JFrog CLI server ID used for authenticated HEAD requests (empty for anonymous)")
	flag.Parse()

	if *downloadURL == "" || *localPath == "" {
		fmt.Fprintln(os.Stderr, "Both --url and --file are required")
		flag.Usage()
		os.Exit(1)
	}

	if err := VerifyLocalFileMatchesRemote(*downloadURL, *localPath, *serverID); err != nil {
		fmt.Fprintf(os.Stderr, "Artifact verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Verified %s matches remote artifact at %s\n", *localPath, *downloadURL)
}
