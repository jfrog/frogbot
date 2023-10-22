package main

import (
	"context"
	"fmt"
	"github.com/jfrog/frogbot/scanpullrequest"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strconv"
	"testing"
	"time"
)

const (
	gitProviderTokenEnv = "FROGBOT_INTEGRATION_GITHUB_TOKEN"
	repoOwner           = "jfrog"
	repoName            = "frogbot-integration-tests"
	issuesBranch        = "issues-branch"
	mainBranch          = "main"
	gitProvider         = "github"
)

func buildGitHubClient(t *testing.T, githubToken string) vcsclient.VcsClient {
	githubClient, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(githubToken).Build()
	assert.NoError(t, err)
	return githubClient
}

func buildGitHubIntegrationTestDetails() *utils.IntegrationTestDetails {
	return &utils.IntegrationTestDetails{
		RepoOwner:   repoOwner,
		RepoName:    repoName,
		GitProvider: gitProvider,
		GitToken:    os.Getenv(gitProviderTokenEnv),
		GitCloneURL: fmt.Sprintf("https://github.com/%s/%s.git", repoOwner, repoName),
	}
}

func buildGitManager(t *testing.T, testDetails *utils.IntegrationTestDetails) *utils.GitManager {
	gitManager, err := utils.NewGitManager().SetAuth("", testDetails.GitToken).SetRemoteGitUrl(testDetails.GitCloneURL)
	assert.NoError(t, err)
	return gitManager
}

func getIssuesBranchName() string {
	return fmt.Sprintf("%s-%s", issuesBranch, strconv.FormatInt(time.Now().Unix(), 10))
}

func setIntegrationTestEnvs(t *testing.T, testDetails *utils.IntegrationTestDetails) func() {
	unsetEnvs := utils.SetEnvsAndAssertWithCallback(t, map[string]string{
		utils.RequirementsFileEnv: "requirements.txt",
		utils.GitPullRequestIDEnv: testDetails.PullRequestID,
		utils.GitProvider:         testDetails.GitProvider,
		utils.GitTokenEnv:         testDetails.GitToken,
		utils.GitRepoEnv:          testDetails.RepoName,
		utils.GitRepoOwnerEnv:     testDetails.RepoOwner,
	})
	return unsetEnvs
}

func createAndCheckoutIssueBranch(t *testing.T, testDetails *utils.IntegrationTestDetails, tmpDir, currentIssuesBranch string) {
	gitManager := buildGitManager(t, testDetails)
	// buildGitManager in an empty directory automatically creates a default .git folder, which prevents cloning.
	// So we remove the default .git and clone the repository with its .git content
	err := vcsutils.RemoveTempDir(".git")
	require.NoError(t, err)
	err = gitManager.Clone(tmpDir, issuesBranch)
	require.NoError(t, err)
	err = gitManager.CreateBranchAndCheckout(currentIssuesBranch)
	require.NoError(t, err)
	err = gitManager.Push(false, currentIssuesBranch)
	require.NoError(t, err)
}

func findRelevantPrID(t *testing.T, client vcsclient.VcsClient, testDetails *utils.IntegrationTestDetails, currentIssuesBranch string) (prId int) {
	ctx := context.Background()
	pullRequests, err := client.ListOpenPullRequests(ctx, testDetails.RepoOwner, testDetails.RepoName)
	require.NoError(t, err)
	for _, pr := range pullRequests {
		if pr.Source.Name == currentIssuesBranch && pr.Target.Name == mainBranch {
			prId = int(pr.ID)
			testDetails.PullRequestID = strconv.Itoa(prId)
			return
		}
	}
	return
}

func TestScanPullRequestIntegration(t *testing.T) {
	// Change working dir to temp dir for cloning and branch checkout
	tmpDir, callback := utils.ChangeToTempDirWithCallback(t)
	defer func() {
		assert.NoError(t, callback())
	}()

	// Create objects for the test details and the git manager for creating the new source branch and pushing it to the repository
	testDetails := buildGitHubIntegrationTestDetails()

	// Get a timestamp based issues-branch name
	currentIssuesBranch := getIssuesBranchName()
	createAndCheckoutIssueBranch(t, testDetails, tmpDir, currentIssuesBranch)

	// Create a client for REST API request
	githubClient := buildGitHubClient(t, testDetails.GitToken)
	ctx := context.Background()

	// Create a pull request from the timestamp based issue branch against the main branch
	err := githubClient.CreatePullRequest(ctx, repoOwner, repoName, currentIssuesBranch, mainBranch, "scan pull request integration test", "")
	require.NoError(t, err)

	// Find the relevant pull request id
	prId := findRelevantPrID(t, githubClient, testDetails, currentIssuesBranch)
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
