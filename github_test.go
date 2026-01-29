package main

import (
	"os"
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

// TODO: Fix scan-pr tests once local directory solution is implemented
func TestGitHub_ScanPullRequestIntegration(t *testing.T) {
	t.Skip("Pull Request Scan is not yes supported in V3. Skipping the test.")
	githubClient, testDetails := githubTestsInit(t)
	runScanPullRequestCmd(t, githubClient, testDetails)
}

// TODO set a profile without JAS for the test
func TestGitHub_ScanRepositoryIntegration(t *testing.T) {
	assert.NoError(t, os.Setenv(utils.EnableFrogbotV3FixEnv, "true"))
	defer func() {
		assert.NoError(t, os.Unsetenv(utils.EnableFrogbotV3FixEnv))
	}()

	githubClient, testDetails := githubTestsInit(t)
	runScanRepositoryCmd(t, githubClient, testDetails)
}
