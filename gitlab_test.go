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
	gitlabIntegrationTokenEnv = "FROGBOT_TESTS_GITLAB_TOKEN"
	gitlabGitCloneUrl         = "https://gitlab.com/frogbot-test2/integration.git"
)

func buildGitLabClient(t *testing.T, gitlabToken string) vcsclient.VcsClient {
	azureClient, err := vcsclient.NewClientBuilder(vcsutils.GitLab).Token(gitlabToken).Build()
	assert.NoError(t, err)
	return azureClient
}

func buildGitLabIntegrationTestDetails(t *testing.T, useLocalRepo bool) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, gitlabIntegrationTokenEnv)
	return NewIntegrationTestDetails(integrationRepoToken, string(utils.GitLab), gitlabGitCloneUrl, "frogbot-test2", useLocalRepo)
}

func gitlabTestsInit(t *testing.T, useLocalRepo bool) (vcsclient.VcsClient, *IntegrationTestDetails) {
	testDetails := buildGitLabIntegrationTestDetails(t, useLocalRepo)
	gitlabClient := buildGitLabClient(t, testDetails.GitToken)
	return gitlabClient, testDetails
}

func TestGitLab_ScanPullRequestIntegration(t *testing.T) {
	gitlabClient, testDetails := gitlabTestsInit(t, false)
	runScanPullRequestCmd(t, gitlabClient, testDetails)
}

func TestGitLab_ScanRepositoryIntegration(t *testing.T) {
	gitlabClient, testDetails := gitlabTestsInit(t, false)
	runScanRepositoryCmd(t, gitlabClient, testDetails)
}

func TestGitLab_ScanRepositoryWithLocalDirIntegration(t *testing.T) {
	gitlabClient, testDetails := gitlabTestsInit(t, true)
	runScanRepositoryCmd(t, gitlabClient, testDetails)
}
