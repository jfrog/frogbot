//go:build integration

package main

import (
	"context"
	"fmt"
	"github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jfrog/frogbot/v2/scanpullrequest"
	"github.com/jfrog/frogbot/v2/scanrepository"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
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
	repoName               = "frogbot-test-v2"
	issuesBranch           = "issues-branch"
	mainBranch             = "main"
	gitUsername            = "frogbot-e2e-test"
	expectedNumberOfIssues = 10
)

type IntegrationTestDetails struct {
	RepoName         string
	RepoOwner        string
	GitToken         string
	GitCloneURL      string
	GitProvider      string
	GitProject       string
	GitUsername      string
	ApiEndpoint      string
	PullRequestID    string
	CustomBranchName string
	UseLocalRepo     bool
}

func NewIntegrationTestDetails(token, gitProvider, gitCloneUrl, repoOwner string, useLocalRepo bool) *IntegrationTestDetails {
	return &IntegrationTestDetails{
		GitProject:   repoName,
		RepoOwner:    repoOwner,
		RepoName:     repoName,
		GitToken:     token,
		GitUsername:  gitUsername,
		GitProvider:  gitProvider,
		GitCloneURL:  gitCloneUrl,
		UseLocalRepo: useLocalRepo,
	}
}

func buildGitManager(t *testing.T, testDetails *IntegrationTestDetails) *utils.GitManager {
	gitManager, err := utils.NewGitManager().
		SetAuth(testDetails.GitUsername, testDetails.GitToken).
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
		utils.RequirementsFileEnv:      "requirements.txt",
		utils.GitPullRequestIDEnv:      testDetails.PullRequestID,
		utils.GitProvider:              testDetails.GitProvider,
		utils.GitTokenEnv:              testDetails.GitToken,
		utils.GitRepoEnv:               testDetails.RepoName,
		utils.GitRepoOwnerEnv:          testDetails.RepoOwner,
		utils.BranchNameTemplateEnv:    testDetails.CustomBranchName,
		utils.GitApiEndpointEnv:        testDetails.ApiEndpoint,
		utils.GitProjectEnv:            testDetails.GitProject,
		utils.GitUsernameEnv:           testDetails.GitUsername,
		utils.GitBaseBranchEnv:         mainBranch,
		utils.GitUseLocalRepositoryEnv: fmt.Sprintf("%t", testDetails.UseLocalRepo),
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

	err = gitManager.CreateBranchAndCheckout(currentIssuesBranch, false)
	require.NoError(t, err)

	// This step is necessary because GitHub limits the number of pull requests from the same commit of the source branch
	_, err = os.Create("emptyfile.txt")
	assert.NoError(t, err)
	err = gitManager.AddAllAndCommit("emptyfile added", "")
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
	err := client.CreatePullRequest(ctx, testDetails.RepoOwner, testDetails.RepoName, currentIssuesBranch, mainBranch, "scan pull request integration test", "")
	require.NoError(t, err)

	// Find the relevant pull request id
	pullRequests := getOpenPullRequests(t, client, testDetails)
	prId := findRelevantPrID(pullRequests, currentIssuesBranch)
	testDetails.PullRequestID = strconv.Itoa(prId)
	defer func() {
		if prId != 0 {
			closePullRequest(t, client, testDetails, prId)
		}
	}()
	require.NotZero(t, prId)

	// Set the required environment variables for the scan-pull-request command
	unsetEnvs := setIntegrationTestEnvs(t, testDetails)
	defer unsetEnvs()

	err = Exec(&scanpullrequest.ScanPullRequestCmd{}, utils.ScanPullRequest)
	// Validate that issues were found and the relevant error returned
	require.Errorf(t, err, scanpullrequest.SecurityIssueFoundErr)

	validateResults(t, ctx, client, testDetails, prId)
}

func runScanRepositoryCmd(t *testing.T, client vcsclient.VcsClient, testDetails *IntegrationTestDetails) {
	testTempDir, restoreFunc := utils.ChangeToTempDirWithCallback(t)
	defer func() {
		assert.NoError(t, restoreFunc())
	}()

	// When testing using local repository clone the repository before the test starts so we can work with it as if it existed locally
	if testDetails.UseLocalRepo {
		cloneOptions := &git.CloneOptions{
			URL: testDetails.GitCloneURL,
			Auth: &githttp.BasicAuth{
				Username: testDetails.GitUsername,
				Password: testDetails.GitToken,
			},
			RemoteName:    "origin",
			ReferenceName: utils.GetFullBranchName("main"),
			SingleBranch:  true,
			Depth:         1,
			Tags:          git.NoTags,
		}
		_, err := git.PlainClone(testTempDir, false, cloneOptions)
		require.NoError(t, err)
	}
	timestamp := getTimestamp()
	// Add a timestamp to the fixing pull requests, to identify them later
	testDetails.CustomBranchName = "frogbot-{IMPACTED_PACKAGE}-{BRANCH_NAME_HASH}-" + timestamp

	// Set the required environment variables for the scan-repository command
	unsetEnvs := setIntegrationTestEnvs(t, testDetails)
	defer unsetEnvs()

	err := Exec(&scanrepository.ScanRepositoryCmd{}, utils.ScanRepository)
	require.NoError(t, err)

	gitManager := buildGitManager(t, testDetails)
	pullRequests := getOpenPullRequests(t, client, testDetails)

	// Collect frogbot PRs created by this test run and register cleanup before asserting,
	// so branches and PRs are always removed whether the test passes or fails.
	var frogbotPRs []vcsclient.PullRequestInfo
	for _, pr := range pullRequests {
		if strings.HasPrefix(pr.Source.Name, "frogbot-") && strings.HasSuffix(pr.Source.Name, "-"+timestamp) {
			frogbotPRs = append(frogbotPRs, pr)
		}
	}
	t.Cleanup(func() {
		for _, pr := range frogbotPRs {
			closePullRequest(t, client, testDetails, int(pr.ID))
			assert.NoError(t, gitManager.RemoveRemoteBranch(pr.Source.Name))
		}
	})

	assert.True(t, len(frogbotPRs) > 0, "expected at least one frogbot fix PR to be created")
}

func validateResults(t *testing.T, ctx context.Context, client vcsclient.VcsClient, testDetails *IntegrationTestDetails, prID int) {
	comments, err := client.ListPullRequestComments(ctx, testDetails.RepoOwner, testDetails.RepoName, prID)
	require.NoError(t, err)

	switch client.(type) {
	case *vcsclient.GitHubClient:
		validateGitHubComments(t, comments)
	case *vcsclient.AzureReposClient:
		validateAzureComments(t, comments)
	case *vcsclient.BitbucketServerClient:
		validateBitbucketServerComments(t, comments)
	case *vcsclient.GitLabClient:
		validateGitLabComments(t, comments)
	}
}

func validateGitHubComments(t *testing.T, comments []vcsclient.CommentInfo) {
	assert.True(t, containsCommentMentioning(comments, string(outputwriter.VulnerabilitiesPrBannerSource)),
		"expected a PR comment containing the Frogbot banner")
	assert.True(t, containsCommentMentioning(comments, "axios:0.21.1"),
		"expected a PR comment mentioning the vulnerable dependency axios:0.21.1")
	assert.True(t, containsCommentMentioning(comments, "CVE-"),
		"expected a PR comment with CVE findings")
}

func containsCommentMentioning(comments []vcsclient.CommentInfo, text string) bool {
	for _, c := range comments {
		if strings.Contains(c.Content, text) {
			return true
		}
	}
	return false
}

func validateAzureComments(t *testing.T, comments []vcsclient.CommentInfo) {
	assert.GreaterOrEqual(t, len(comments), expectedNumberOfIssues)
	assertBannerExists(t, comments, string(outputwriter.VulnerabilitiesPrBannerSource))
}

func validateBitbucketServerComments(t *testing.T, comments []vcsclient.CommentInfo) {
	assert.GreaterOrEqual(t, len(comments), expectedNumberOfIssues)
	assertBannerExists(t, comments, outputwriter.GetSimplifiedTitle(outputwriter.VulnerabilitiesPrBannerSource))
}

func validateGitLabComments(t *testing.T, comments []vcsclient.CommentInfo) {
	assert.GreaterOrEqual(t, len(comments), expectedNumberOfIssues)
	assertBannerExists(t, comments, string(outputwriter.VulnerabilitiesMrBannerSource))
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

func assertBannerExists(t *testing.T, comments []vcsclient.CommentInfo, banner string) {
	var isContains bool
	var occurrences int
	for _, c := range comments {
		if strings.Contains(c.Content, banner) {
			isContains = true
			occurrences++
		}
	}

	assert.True(t, isContains)
	assert.Equal(t, 1, occurrences)
}

func closePullRequest(t *testing.T, client vcsclient.VcsClient, testDetails *IntegrationTestDetails, prID int) {
	targetBranch := mainBranch
	if _, isAzureClient := client.(*vcsclient.AzureReposClient); isAzureClient {
		// The Azure API requires not adding parameters that won't be updated, so we omit the targetBranch in that case
		targetBranch = ""
	}
	err := client.UpdatePullRequest(context.Background(), testDetails.RepoOwner, testDetails.RepoName, "integration test finished", "", targetBranch, prID, vcsutils.Closed)
	assert.NoError(t, err)
}
