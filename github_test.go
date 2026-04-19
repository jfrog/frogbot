package main

import (
	"testing"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

const (
	//#nosec G101 -- False positive - no hardcoded credentials.
	githubIntegrationTokenEnv = "FROGBOT_V3_TESTS_GITHUB_TOKEN"
	githubGitCloneUrl         = "https://github.com/frogbot-e2e-test/frogbot-test.git"
	githubRepoOwner           = "frogbot-e2e-test"
)

func buildGitHubClient(t *testing.T, githubToken string) vcsclient.VcsClient {
	githubClient, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(githubToken).Build()
	assert.NoError(t, err)
	return githubClient
}

func buildGitHubIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, githubIntegrationTokenEnv)
	return NewIntegrationTestDetails(integrationRepoToken, string(utils.GitHub), githubGitCloneUrl, githubRepoOwner)
}

func githubTestsInit(t *testing.T) (vcsclient.VcsClient, *IntegrationTestDetails) {
	testDetails := buildGitHubIntegrationTestDetails(t)
	githubClient := buildGitHubClient(t, testDetails.GitToken)
	return githubClient, testDetails
}

func TestGitHub_ScanPullRequestIntegration(t *testing.T) {
	githubClient, testDetails := githubTestsInit(t)
	runScanPullRequestCmd(t, githubClient, testDetails)
}

func TestGitHub_ScanRepositoryIntegration(t *testing.T) {
	githubClient, testDetails := githubTestsInit(t)
	runScanRepositoryCmd(t, githubClient, testDetails)
}
