package main

import (
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"testing"
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
	testDetails := buildBitbucketServerIntegrationTestDetails(t)
	bbClient := buildBitbucketServerClient(t, testDetails.GitToken)
	runScanPullRequestCmd(t, bbClient, testDetails)
}

func TestABitbucketServer_ScanRepositoryIntegration(t *testing.T) {
	testDetails := buildBitbucketServerIntegrationTestDetails(t)
	bbClient := buildBitbucketServerClient(t, testDetails.GitToken)
	runScanRepositoryCmd(t, bbClient, testDetails)
}
