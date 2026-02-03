package main

import (
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	//#nosec G101 -- False positive - no hardcoded credentials.
	bitbucketCloudIntegrationTokenEnv = "FROGBOT_TESTS_BB_CLOUD_TOKEN"
	bitbucketCloudUsername            = "FROGBOT_TESTS_BB_CLOUD_USERNAME"
	bitbucketCloudApiEndpoint         = "https://api.bitbucket.org/2.0"
	bitbucketCloudGitCloneUrl         = "https://bitbucket.org/<workspace>/<repo>.git"
	bitbucketCloudWorkspace           = "<workspace>"
)

func buildBitbucketCloudClient(t *testing.T, bitbucketCloudToken, username string) vcsclient.VcsClient {
	bbClient, err := vcsclient.NewClientBuilder(vcsutils.BitbucketCloud).
		Username(username).
		ApiEndpoint(bitbucketCloudApiEndpoint).
		Token(bitbucketCloudToken).
		Build()
	assert.NoError(t, err)
	return bbClient
}

func buildBitbucketCloudIntegrationTestDetails(t *testing.T, useLocalRepo bool) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, bitbucketCloudIntegrationTokenEnv)
	username := getIntegrationToken(t, bitbucketCloudUsername)
	testDetails := NewIntegrationTestDetails(integrationRepoToken, string(utils.BitbucketCloud), bitbucketCloudGitCloneUrl, bitbucketCloudWorkspace, useLocalRepo)
	testDetails.ApiEndpoint = bitbucketCloudApiEndpoint
	testDetails.GitUsername = username
	return testDetails
}

func bitbucketCloudTestsInit(t *testing.T, useLocalRepo bool) (vcsclient.VcsClient, *IntegrationTestDetails) {
	testDetails := buildBitbucketCloudIntegrationTestDetails(t, useLocalRepo)
	bbClient := buildBitbucketCloudClient(t, testDetails.GitToken, testDetails.GitUsername)
	return bbClient, testDetails
}

func TestBitbucketCloud_ScanPullRequestIntegration(t *testing.T) {
	bbClient, testDetails := bitbucketCloudTestsInit(t, false)
	runScanPullRequestCmd(t, bbClient, testDetails)
}

func TestBitbucketCloud_ScanRepositoryIntegration(t *testing.T) {
	bbClient, testDetails := bitbucketCloudTestsInit(t, false)
	runScanRepositoryCmd(t, bbClient, testDetails)
}

func TestBitbucketCloud_ScanRepositoryWithLocalDirIntegration(t *testing.T) {
	bbClient, testDetails := bitbucketCloudTestsInit(t, true)
	runScanRepositoryCmd(t, bbClient, testDetails)
}
