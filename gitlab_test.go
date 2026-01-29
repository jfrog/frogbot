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
	gitlabIntegrationTokenEnv = "FROGBOT_V3_TESTS_GITLAB_TOKEN"
	gitlabGitCloneUrl         = "https://gitlab.com/frogbot-e2e-test1/frogbot-test.git"
	gitlabRepoOwner           = "frogbot-e2e-test1"
)

func buildGitLabClient(t *testing.T, gitlabToken string) vcsclient.VcsClient {
	azureClient, err := vcsclient.NewClientBuilder(vcsutils.GitLab).Token(gitlabToken).Build()
	assert.NoError(t, err)
	return azureClient
}

func buildGitLabIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, gitlabIntegrationTokenEnv)
	return NewIntegrationTestDetails(integrationRepoToken, string(utils.GitLab), gitlabGitCloneUrl, gitlabRepoOwner)
}

func gitlabTestsInit(t *testing.T) (vcsclient.VcsClient, *IntegrationTestDetails) {
	testDetails := buildGitLabIntegrationTestDetails(t)
	gitlabClient := buildGitLabClient(t, testDetails.GitToken)
	return gitlabClient, testDetails
}

// TODO: Fix scan-pr tests once local directory solution is implemented
func TestGitLab_ScanPullRequestIntegration(t *testing.T) {
	t.Skip("Pull Request Scan is not yes supported in V3. Skipping the test.")
	gitlabClient, testDetails := gitlabTestsInit(t)
	runScanPullRequestCmd(t, gitlabClient, testDetails)
}

// TODO set a profile without JAS for the test
func TestGitLab_ScanRepositoryIntegration(t *testing.T) {
	assert.NoError(t, os.Setenv(utils.EnableFrogbotV3FixEnv, "true"))
	defer func() {
		assert.NoError(t, os.Unsetenv(utils.EnableFrogbotV3FixEnv))
	}()

	gitlabClient, testDetails := gitlabTestsInit(t)
	runScanRepositoryCmd(t, gitlabClient, testDetails)
}
