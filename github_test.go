package main

import (
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	githubIntegrationTokenEnv = "FROGBOT_TESTS_GITHUB_TOKEN"
	githubGitCloneUrl         = "https://github.com/frogbot-test/integration.git"
)

func buildGitHubClient(t *testing.T, githubToken string) vcsclient.VcsClient {
	githubClient, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(githubToken).Build()
	assert.NoError(t, err)
	return githubClient
}

func buildGitHubIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, githubIntegrationTokenEnv)
	return NewIntegrationTestDetails(integrationRepoToken, string(utils.GitHub), githubGitCloneUrl, "frogbot-test")
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
