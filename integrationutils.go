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
	"strings"
	"testing"
	"time"
)

const (
	repoOwner    = "frogbot-test"
	repoName     = "integration"
	issuesBranch = "issues-branch"
	mainBranch   = "main"
)

type IntegrationTestDetails struct {
	RepoName         string
	RepoOwner        string
	GitToken         string
	GitCloneURL      string
	GitProvider      string
	GitProject       string
	ApiEndpoint      string
	PullRequestID    string
	CustomBranchName string
}

func NewIntegrationTestDetails(token, gitProvider, gitCloneUrl string) *IntegrationTestDetails {
	return &IntegrationTestDetails{
		GitProject:  repoName,
		RepoOwner:   "frog",
		RepoName:    repoName,
		GitToken:    token,
		GitProvider: gitProvider,
		GitCloneURL: gitCloneUrl,
	}
}

func buildGitManager(t *testing.T, testDetails *IntegrationTestDetails) *utils.GitManager {
	gitManager, err := utils.NewGitManager().
		SetAuth("frogbot", testDetails.GitToken).
		SetEmailAuthor("frogbot-test@jfrog.com").
		SetRemoteGitUrl(testDetails.GitCloneURL)
	assert.NoError(t, err)
	return gitManager
}

func getIssuesBranchName() string {
	return fmt.Sprintf("%s-%s", issuesBranch, getTimestamp())
}

func getTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func setIntegrationTestEnvs(t *testing.T, testDetails *IntegrationTestDetails) func() {
	// Frogbot sanitizes all the environment variables that start with 'JF',
	// so we restore them at the end of the test to avoid collisions with other tests
	envRestoreFunc := getJfrogEnvRestoreFunc(t)
	unsetEnvs := utils.SetEnvsAndAssertWithCallback(t, map[string]string{
		utils.RequirementsFileEnv:   "requirements.txt",
		utils.GitPullRequestIDEnv:   testDetails.PullRequestID,
		utils.GitProvider:           testDetails.GitProvider,
		utils.GitTokenEnv:           testDetails.GitToken,
		utils.GitRepoEnv:            testDetails.RepoName,
		utils.GitRepoOwnerEnv:       testDetails.RepoOwner,
		utils.BranchNameTemplateEnv: testDetails.CustomBranchName,
		utils.GitApiEndpointEnv:     testDetails.ApiEndpoint,
		utils.GitProjectEnv:         testDetails.GitProject,
		utils.GitBaseBranchEnv:      mainBranch,
	})
	return func() {
		envRestoreFunc()
		unsetEnvs()
	}
}

func createAndCheckoutIssueBranch(t *testing.T, testDetails *IntegrationTestDetails, tmpDir, currentIssuesBranch string) func() {
	gitManager := buildGitManager(t, testDetails)
	// buildGitManager in an empty directory automatically creates a default .git folder, which prevents cloning.
	// So we remove the default .git and clone the repository with its .git content
	err := vcsutils.RemoveTempDir(".git")
	require.NoError(t, err)

	err = gitManager.Clone(tmpDir, issuesBranch)
	require.NoError(t, err)

	err = gitManager.CreateBranchAndCheckout(currentIssuesBranch)
	require.NoError(t, err)

	// This step is necessary because GitHub limits the number of pull requests from the same commit of the source branch
	_, err = os.Create("emptyfile.txt")
	assert.NoError(t, err)
	err = gitManager.AddAllAndCommit("emptyfile added")
	assert.NoError(t, err)

	err = gitManager.Push(false, currentIssuesBranch)
	require.NoError(t, err)
	return func() {
		// Remove the branch from remote
		err := gitManager.RemoveRemoteBranch(currentIssuesBranch)
		assert.NoError(t, err)
	}
}

func findRelevantPrID(pullRequests []vcsclient.PullRequestInfo, branch string) (prId int) {
	for _, pr := range pullRequests {
		if pr.Source.Name == branch && pr.Target.Name == mainBranch {
			prId = int(pr.ID)
			return
		}
	}
	return
}

func getOpenPullRequests(t *testing.T, client vcsclient.VcsClient, testDetails *IntegrationTestDetails) []vcsclient.PullRequestInfo {
	ctx := context.Background()
	pullRequests, err := client.ListOpenPullRequests(ctx, testDetails.RepoOwner, testDetails.RepoName)
	require.NoError(t, err)
	return pullRequests
}

func runScanPullRequestCmd(t *testing.T, client vcsclient.VcsClient, testDetails *IntegrationTestDetails) {
	// Change working dir to temp dir for cloning and branch checkout
	tmpDir, restoreFunc := utils.ChangeToTempDirWithCallback(t)
	defer func() {
		assert.NoError(t, restoreFunc())
	}()

	// Get a timestamp based issues-branch
	currentIssuesBranch := getIssuesBranchName()
	removeBranchFunc := createAndCheckoutIssueBranch(t, testDetails, tmpDir, currentIssuesBranch)
	defer removeBranchFunc()

	ctx := context.Background()
	// Create a pull request from the timestamp based issue branch against the main branch
	err := client.CreatePullRequest(ctx, "frog", repoName, currentIssuesBranch, mainBranch, "scan pull request integration test", "")
	require.NoError(t, err)

	// Find the relevant pull request id
	pullRequests := getOpenPullRequests(t, client, testDetails)
	prId := findRelevantPrID(pullRequests, currentIssuesBranch)
	testDetails.PullRequestID = strconv.Itoa(prId)
	require.NotZero(t, prId)
	defer func() {
		err = client.UpdatePullRequest(ctx, repoOwner, repoName, "scan pr test finished", "", "", prId, vcsutils.Closed)
		assert.NoError(t, err)
	}()

	// Set the required environment variables for the scan-pull-request command
	unsetEnvs := setIntegrationTestEnvs(t, testDetails)
	defer unsetEnvs()

	err = Exec(&scanpullrequest.ScanPullRequestCmd{}, utils.ScanPullRequest)
	// Validate that issues were found and the relevant error returned
	require.Errorf(t, err, scanpullrequest.SecurityIssueFoundErr)

	validateResults(t, ctx, client, prId)
}

func runScanRepositoryCmd(t *testing.T, client vcsclient.VcsClient, testDetails *IntegrationTestDetails) {
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

	gitManager := buildGitManager(t, testDetails)

	pullRequests := getOpenPullRequests(t, client, testDetails)

	expectedBranchName := "frogbot-pyjwt-45ebb5a61916a91ae7c1e3ff7ffb6112-" + timestamp
	assert.NoError(t, gitManager.RemoveRemoteBranch(expectedBranchName))
	prId := findRelevantPrID(pullRequests, expectedBranchName)
	assert.NotZero(t, prId)
	ctx := context.Background()
	err = client.UpdatePullRequest(ctx, repoOwner, repoName, "scan repository test finished", "", "", prId, vcsutils.Closed)
	assert.NoError(t, err)

	expectedBranchName = "frogbot-pyyaml-985622f4dbf3a64873b6b8440288e005-" + timestamp
	prId = findRelevantPrID(pullRequests, expectedBranchName)
	assert.NoError(t, gitManager.RemoveRemoteBranch(expectedBranchName))
	assert.NotZero(t, prId)
	err = client.UpdatePullRequest(ctx, "frog", repoName, "scan repository test finished", "", "", prId, vcsutils.Closed)
	assert.NoError(t, err)
}

func validateResults(t *testing.T, ctx context.Context, client vcsclient.VcsClient, prId int) {
	comments, err := client.ListPullRequestComments(ctx, "frog", repoName, prId)
	assert.NoError(t, err)

	switch client.(type) {
	case *vcsclient.GitHubClient:
		// Validate that the relevant vulnerabilities comment has been created
		assert.Len(t, comments, 1)
		comment := comments[0]
		assert.Contains(t, comment.Content, outputwriter.VulnerabilitiesPrBannerSource)

		// Validate that the relevant review comments have been created
		reviewComments, err := client.ListPullRequestReviewComments(ctx, repoOwner, repoName, prId)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(reviewComments), 13)
	case *vcsclient.AzureReposClient:
		// In azure repos, there is no separation between comments and review comments
		assert.GreaterOrEqual(t, len(comments), 14)
		bannerExists, bannerOccurreneces := isCommentsContainsBanner(comments, outputwriter.VulnerabilitiesPrBannerSource)
		assert.True(t, bannerExists)
		assert.Equal(t, 1, bannerOccurreneces)
	}
}

func getJfrogEnvRestoreFunc(t *testing.T) func() {
	jfrogEnvs := make(map[string]string)
	for _, env := range os.Environ() {
		envSplit := strings.Split(env, "=")
		key := envSplit[0]
		val := envSplit[1]
		if strings.HasPrefix(key, "JF_") {
			jfrogEnvs[key] = val
		}
	}

	return func() {
		for key, val := range jfrogEnvs {
			assert.NoError(t, os.Setenv(key, val))
		}
	}
}

// This function retrieves the relevant VCS provider access token based on the corresponding environment variable.
// If the environment variable is empty, the test is skipped.
func getIntegrationToken(t *testing.T, tokenEnv string) string {
	integrationRepoToken := os.Getenv(tokenEnv)
	if integrationRepoToken == "" {
		t.Skipf("%s is not set, skipping integration test", tokenEnv)
	}
	return integrationRepoToken
}

func isCommentsContainsBanner(comments []vcsclient.CommentInfo, banner outputwriter.ImageSource) (bool, int) {
	var isContains bool
	var occurrences int
	for _, c := range comments {
		if strings.Contains(c.Content, string(banner)) {
			isContains = true
			occurrences++
		}
	}

	return isContains, occurrences
}
