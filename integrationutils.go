package main

import (
	"context"
	"fmt"
	"github.com/jfrog/frogbot/utils"
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
	PullRequestID    string
	CustomBranchName string
}

func buildGitManager(t *testing.T, testDetails *IntegrationTestDetails) *utils.GitManager {
	gitManager, err := utils.NewGitManager().SetAuth("", testDetails.GitToken).SetRemoteGitUrl(testDetails.GitCloneURL)
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
