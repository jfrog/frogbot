//go:build integration

package main

import (
	"github.com/jfrog/frogbot/v3/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	//#nosec G101 -- False positive - no hardcoded credentials.
	gitlabIntegrationTokenEnv = "FROGBOT_V3_TESTS_GITLAB_TOKEN"
	gitlabGitCloneUrl         = "https://gitlab.com/frogbot-e2e-test1/frogbot-test.git"
	gitlabRepoOwner           = "frogbot-e2e-test1"
)

func buildGitLabClient(t *testing.T, gitlabToken string) vcsclient.VcsClient {
	gitlabClient, err := vcsclient.NewClientBuilder(vcsutils.GitLab).Token(gitlabToken).Build()
	assert.NoError(t, err)
	return gitlabClient
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

func TestGitLab_ScanPullRequestIntegration(t *testing.T) {
	gitlabClient, testDetails := gitlabTestsInit(t)
	runScanPullRequestCmd(t, gitlabClient, testDetails)
}

func TestGitLab_ScanRepositoryIntegration(t *testing.T) {
	gitlabClient, testDetails := gitlabTestsInit(t)
	runScanRepositoryCmd(t, gitlabClient, testDetails)
}
