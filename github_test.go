package main

import (
	"context"
	"fmt"
	"github.com/jfrog/frogbot/scanpullrequest"
	"github.com/jfrog/frogbot/scanrepository"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strconv"
	"testing"
)

const (
	githubIntegrationTokenEnv = "FROGBOT_TESTS_GITHUB_TOKEN"
)

func buildGitHubClient(t *testing.T, githubToken string) vcsclient.VcsClient {
	githubClient, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(githubToken).Build()
	assert.NoError(t, err)
	return githubClient
}

func buildGitHubIntegrationTestDetails(t *testing.T) *IntegrationTestDetails {
	integrationRepoToken := os.Getenv(githubIntegrationTokenEnv)
	if integrationRepoToken == "" {
		t.Skipf("%s is not set, skipping integration test", githubIntegrationTokenEnv)
	}
	return &IntegrationTestDetails{
		RepoOwner:   repoOwner,
		RepoName:    repoName,
		GitProvider: string(utils.GitHub),
		GitToken:    integrationRepoToken,
		GitCloneURL: fmt.Sprintf("https://github.com/%s/%s.git", repoOwner, repoName),
	}
}

func TestScanPullRequestIntegration(t *testing.T) {
	// Create objects for the test details and the git manager for creating the new source branch and pushing it to the repository
	testDetails := buildGitHubIntegrationTestDetails(t)

	// Change working dir to temp dir for cloning and branch checkout
	tmpDir, restoreFunc := utils.ChangeToTempDirWithCallback(t)
	defer func() {
		assert.NoError(t, restoreFunc())
	}()

	// Get a timestamp based issues-branch name
	currentIssuesBranch := getIssuesBranchName()
	removeBranchFunc := createAndCheckoutIssueBranch(t, testDetails, tmpDir, currentIssuesBranch)
	defer removeBranchFunc()

	// Create a client for REST API request
	githubClient := buildGitHubClient(t, testDetails.GitToken)
	ctx := context.Background()

	// Create a pull request from the timestamp based issue branch against the main branch
	err := githubClient.CreatePullRequest(ctx, repoOwner, repoName, currentIssuesBranch, mainBranch, "scan pull request integration test", "")
	require.NoError(t, err)

	// Find the relevant pull request id
	pullRequests := getOpenPullRequests(t, githubClient, testDetails)
	prId := findRelevantPrID(pullRequests, currentIssuesBranch)
	testDetails.PullRequestID = strconv.Itoa(prId)
	require.NotZero(t, prId)
	defer func() {
		err = githubClient.UpdatePullRequest(ctx, repoOwner, repoName, "test finished", "", mainBranch, prId, vcsutils.Closed)
		assert.NoError(t, err)
	}()

	// Set the required environment variables for the scan-pull-request command
	unsetEnvs := setIntegrationTestEnvs(t, testDetails)
	defer unsetEnvs()

	err = Exec(&scanpullrequest.ScanPullRequestCmd{}, utils.ScanPullRequest)
	// Validate that issues were found and the relevant error returned
	require.Errorf(t, err, scanpullrequest.SecurityIssueFoundErr)

	comments, err := githubClient.ListPullRequestComments(ctx, repoOwner, repoName, prId)
	assert.NoError(t, err)

	// Validate that the relevant vulnerabilities comment has been created
	assert.Len(t, comments, 1)
	comment := comments[0]
	assert.Contains(t, comment.Content, outputwriter.VulnerabilitiesPrBannerSource)

	// Validate that the relevant review comments have been created
	reviewComments, err := githubClient.ListPullRequestReviewComments(ctx, repoOwner, repoName, prId)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(reviewComments), 13)
}

func TestScanRepositoryIntegration(t *testing.T) {
	testDetails := buildGitHubIntegrationTestDetails(t)

	_, restoreFunc := utils.ChangeToTempDirWithCallback(t)
	defer func() {
		assert.NoError(t, restoreFunc())
	}()

	timestamp := getTimestamp()
	// Add a timestamp to the fixing pull requests, to identify them later
	testDetails.CustomBranchName = "frogbot-{IMPACTED_PACKAGE}-{BRANCH_NAME_HASH}-" + timestamp

	// Set the required environment variables for the scan-repository command
	unsetEnvs := setIntegrationTestEnvs(t, testDetails)
	defer unsetEnvs()

	err := Exec(&scanrepository.ScanRepositoryCmd{}, utils.ScanRepository)
	assert.NoError(t, err)

	githubClient := buildGitHubClient(t, testDetails.GitToken)
	gitManager := buildGitManager(t, testDetails)

	pullRequests := getOpenPullRequests(t, githubClient, testDetails)

	expectedBranchName := "frogbot-pyjwt-45ebb5a61916a91ae7c1e3ff7ffb6112-" + timestamp
	assert.NoError(t, gitManager.RemoveRemoteBranch(expectedBranchName))
	prId := findRelevantPrID(pullRequests, expectedBranchName)
	assert.NotZero(t, prId)

	expectedBranchName = "frogbot-pyyaml-985622f4dbf3a64873b6b8440288e005-" + timestamp
	prId = findRelevantPrID(pullRequests, expectedBranchName)
	assert.NoError(t, gitManager.RemoveRemoteBranch(expectedBranchName))
	assert.NotZero(t, prId)
}
