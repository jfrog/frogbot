package main

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"testing"
)

const (
	bitbucketServerIntegrationTokenEnv = "FROGBOT_TESTS_BB_SERVER_TOKEN"
	bitbucketServerApiEndpoint         = "http://localhost:7990/rest"
	bitbucketServerGitCloneUrl         = "http://localhost:7990/scm/frog/integration.git"
)

func buildBitbucketServerClient(t *testing.T, bitbucketServerToken string) vcsclient.VcsClient {
	bbClient, err := vcsclient.NewClientBuilder(vcsutils.BitbucketServer).Username("frogbot").ApiEndpoint(bitbucketServerApiEndpoint).Token(bitbucketServerToken).Build()
	assert.NoError(t, err)
	return bbClient
}

func buildBitbucketServerIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, bitbucketServerIntegrationTokenEnv)
	testDetails := NewIntegrationTestDetails(integrationRepoToken, string(utils.BitbucketServer), bitbucketServerGitCloneUrl, "FROG")
	testDetails.ApiEndpoint = bitbucketServerApiEndpoint
	return testDetails
}

func waitForConnection(t *testing.T) {
	log.Info("Waiting for Bitbucket Server to be up and running...")
	retryExecutor := vcsutils.RetryExecutor{
		MaxRetries:               10,
		RetriesIntervalMilliSecs: 60000,
		Logger:                   log.Logger,
	}
	retryExecutor.ExecutionHandler = func() (bool, error) {
		res, err := http.Get("http://localhost:7990/status")
		if err != nil || res.StatusCode != http.StatusOK {
			body, e := io.ReadAll(res.Body)
			err = errors.Join(err, e)
			log.Info(fmt.Sprintf("Status code: %d, Server current state: %s", res.StatusCode, body))
			return true, err
		}
		return false, nil
	}
	require.NoError(t, retryExecutor.Execute())
}

func bitbucketServerTestsInit(t *testing.T) (vcsclient.VcsClient, *IntegrationTestDetails) {
	testDetails := buildBitbucketServerIntegrationTestDetails(t)
	bbClient := buildBitbucketServerClient(t, testDetails.GitToken)
	waitForConnection(t)
	return bbClient, testDetails
}

func TestBitbucketServer_ScanPullRequestIntegration(t *testing.T) {
	bbClient, testDetails := bitbucketServerTestsInit(t)
	runScanPullRequestCmd(t, bbClient, testDetails)
}

func TestBitbucketServer_ScanRepositoryIntegration(t *testing.T) {
	bbClient, testDetails := bitbucketServerTestsInit(t)
	runScanRepositoryCmd(t, bbClient, testDetails)
}
