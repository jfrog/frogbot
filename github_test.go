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
	githubIntegrationTokenEnv = "FROGBOT_TESTS_GITHUB_TOKEN"
	githubGitCloneUrl         = "https://github.com/frogbot-test/integration.git"
)

func buildGitHubClient(t *testing.T, githubToken string) vcsclient.VcsClient {
	githubClient, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(githubToken).Build()
	assert.NoError(t, err)
	return githubClient
}

func buildGitHubIntegrationTestDetails(t *testing.T, useLocalRepo bool) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, githubIntegrationTokenEnv)
	return NewIntegrationTestDetails(integrationRepoToken, string(utils.GitHub), githubGitCloneUrl, "frogbot-test", useLocalRepo)
}

func githubTestsInit(t *testing.T, useLocalRepo bool) (vcsclient.VcsClient, *IntegrationTestDetails) {
	testDetails := buildGitHubIntegrationTestDetails(t, useLocalRepo)
	githubClient := buildGitHubClient(t, testDetails.GitToken)
	return githubClient, testDetails
}

func TestGitHub_ScanPullRequestIntegration(t *testing.T) {
	githubClient, testDetails := githubTestsInit(t, false)
	runScanPullRequestCmd(t, githubClient, testDetails)
}

func TestGitHub_ScanRepositoryIntegration(t *testing.T) {
	githubClient, testDetails := githubTestsInit(t, false)
	runScanRepositoryCmd(t, githubClient, testDetails)
}

func TestGitHub_ScanRepositoryWithLocalDirIntegration(t *testing.T) {
	githubClient, testDetails := githubTestsInit(t, true)
	runScanRepositoryCmd(t, githubClient, testDetails)
}
