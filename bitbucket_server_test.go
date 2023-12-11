package main

import (
	"flag"
	"fmt"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
	"time"
)

const (
	bitbucketServerIntegrationTokenEnv = "FROGBOT_TESTS_BB_SERVER_TOKEN"
	bitbucketServerApiEndpoint         = "http://localhost:7990/rest"
	bitbucketServerGitCloneUrl         = "http://localhost:7990/scm/frog/integration.git"
)

func buildBitbucketServerClient(t *testing.T, bitbucketServerToken string) vcsclient.VcsClient {
	bbClient, err := vcsclient.NewClientBuilder(vcsutils.BitbucketServer).ApiEndpoint(bitbucketServerApiEndpoint).Token(bitbucketServerToken).Build()
	assert.NoError(t, err)
	return bbClient
}

func buildBitbucketServerIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, bitbucketServerIntegrationTokenEnv)
	testDetails := NewIntegrationTestDetails(integrationRepoToken, string(utils.BitbucketServer), bitbucketServerGitCloneUrl)
	testDetails.ApiEndpoint = bitbucketServerApiEndpoint
	return testDetails
}

func TestBitbucketServer_ScanPullRequestIntegration(t *testing.T) {
	var responseCode = flag.Int("code", 200, "Response code to wait for")
	var timeout = flag.Int("timeout", 2000, "Timeout before giving up in ms")
	var interval = 500
	flag.Parse()

	fmt.Printf("Polling URL `%s` for response code %d for up to %d ms at %d ms intervals\n", "http://localhost:7990/status", *responseCode, *timeout, interval)
	startTime := time.Now()
	timeoutDuration := time.Duration(2000) * time.Millisecond
	for {
		res, err := http.Head("http://localhost:7990/status")
		fmt.Printf("Response header: %v", res)
		if err == nil && res.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(8000)
		elapsed := time.Now().Sub(startTime)
		if elapsed > timeoutDuration {
			fmt.Printf("Timed out\n")
			os.Exit(1)
		}
	}

	testDetails := buildBitbucketServerIntegrationTestDetails(t)
	bbClient := buildBitbucketServerClient(t, testDetails.GitToken)
	runScanPullRequestCmd(t, bbClient, testDetails)
}

//
//func TestBitbucketServer_ScanRepositoryIntegration(t *testing.T) {
//	testDetails := buildBitbucketServerIntegrationTestDetails(t)
//	bbClient := buildBitbucketServerClient(t, testDetails.GitToken)
//	runScanRepositoryCmd(t, bbClient, testDetails)
//}
