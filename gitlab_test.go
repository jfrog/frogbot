package main

import (
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	gitlabIntegrationTokenEnv = "FROGBOT_TESTS_GITLAB_TOKEN"
	gitlabGitCloneUrl         = "https://gitlab.com/frogbot-test2/integration.git"
)

func buildGitlabReposClient(t *testing.T, gitlabToken string) vcsclient.VcsClient {
	azureClient, err := vcsclient.NewClientBuilder(vcsutils.GitLab).Token(gitlabToken).Build()
	assert.NoError(t, err)
	return azureClient
}

func buildGitlabReposIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, gitlabIntegrationTokenEnv)
	testDetails := NewIntegrationTestDetails(integrationRepoToken, string(utils.GitLab), gitlabGitCloneUrl, "frogbot-test2")
	return testDetails
}

func TestGitLab_ScanPullRequestIntegration(t *testing.T) {
	testDetails := buildGitlabReposIntegrationTestDetails(t)
	gitlabClient := buildGitlabReposClient(t, testDetails.GitToken)
	runScanPullRequestCmd(t, gitlabClient, testDetails)
}

func TestGitLabRepos_ScanRepositoryIntegration(t *testing.T) {
	testDetails := buildGitlabReposIntegrationTestDetails(t)
	gitlabClient := buildGitlabReposClient(t, testDetails.GitToken)
	runScanRepositoryCmd(t, gitlabClient, testDetails)
}
