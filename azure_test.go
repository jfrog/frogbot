package main

import (
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	azureIntegrationTokenEnv = "FROGBOT_TESTS_AZURE_TOKEN"
	azureApiEndpoint         = "https://dev.azure.com/frogbot-test"
	azureGitCloneUrl         = "https://frogbot-test@dev.azure.com/frogbot-test/integration/_git/integration"
)

func buildAzureReposClient(t *testing.T, azureToken string) vcsclient.VcsClient {
	azureClient, err := vcsclient.NewClientBuilder(vcsutils.AzureRepos).Project(repoName).ApiEndpoint(azureApiEndpoint).Token(azureToken).Build()
	assert.NoError(t, err)
	return azureClient
}

func buildAzureReposIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := getIntegrationToken(t, azureIntegrationTokenEnv)
	testDetails := NewIntegrationTestDetails(integrationRepoToken, string(utils.AzureRepos), azureGitCloneUrl, "frogbot-test")
	testDetails.ApiEndpoint = azureApiEndpoint
	return testDetails
}

func azureReposTestsInit(t *testing.T) (vcsclient.VcsClient, *IntegrationTestDetails) {
	testDetails := buildAzureReposIntegrationTestDetails(t)
	azureClient := buildAzureReposClient(t, testDetails.GitToken)
	return azureClient, testDetails
}

func TestAzureRepos_ScanPullRequestIntegration(t *testing.T) {
	azureClient, testDetails := azureReposTestsInit(t)
	runScanPullRequestCmd(t, azureClient, testDetails)
}

func TestAzureRepos_ScanRepositoryIntegration(t *testing.T) {
	azureClient, testDetails := azureReposTestsInit(t)
	runScanRepositoryCmd(t, azureClient, testDetails)
}
