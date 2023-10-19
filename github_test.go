package main

import (
	"context"
	"github.com/jfrog/frogbot/scanpullrequest"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
)

const (
	gitProviderTokenEnv = "FROGBOT_INTEGRATION_GITHUB_TOKEN"
	repoOwner           = "omerzi"
	repoName            = "flask-webgoat"
	issuesBranch        = "issues-branch"
	mainBranch          = "main"
	gitProvider         = "github"
)

func buildGitHubClient(t *testing.T) (vcsclient.VcsClient, string) {
	token := os.Getenv(gitProviderTokenEnv)
	githubClient, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(token).Build()
	assert.NoError(t, err)
	return githubClient, token
}

func TestScanPullRequestIntegration(t *testing.T) {
	githubClient, githubToken := buildGitHubClient(t)
	ctx := context.Background()
	err := githubClient.CreatePullRequest(ctx, repoOwner, repoName, issuesBranch, mainBranch, "scan pull request integration test", "")
	assert.NoError(t, err)
	pullRequests, err := githubClient.ListOpenPullRequests(ctx, repoOwner, repoName)
	assert.NoError(t, err)
	prID := 0
	for _, pr := range pullRequests {
		if pr.Source.Name == issuesBranch && pr.Target.Name == mainBranch {
			prID = int(pr.ID)
			break
		}
	}
	defer func() {
		err = githubClient.UpdatePullRequest(ctx, repoOwner, repoName, "[CLOSED] test finished", "", mainBranch, prID, vcsutils.Closed)
		assert.NoError(t, err)
	}()

	unsetEnvs := utils.SetEnvsAndAssertWithCallback(t, map[string]string{
		utils.RequirementsFileEnv: "requirements.txt",
		utils.GitPullRequestIDEnv: strconv.Itoa(prID),
		utils.GitProvider:         gitProvider,
		utils.GitTokenEnv:         githubToken,
		utils.GitRepoEnv:          repoName,
		utils.GitRepoOwnerEnv:     repoOwner,
	})
	defer unsetEnvs()

	err = Exec(scanpullrequest.ScanAllPullRequestsCmd{}, utils.ScanPullRequest)
	assert.Errorf(t, err, scanpullrequest.SecurityIssueFoundErr)

	comments, err := githubClient.ListPullRequestComments(ctx, repoOwner, repoName, prID)
	assert.NoError(t, err)

	assert.Len(t, comments, 1)
	comment := comments[0]
	assert.Contains(t, comment.Content, outputwriter.VulnerabilitiesPrBannerSource)

	reviewComments, err := githubClient.ListPullRequestReviewComments(ctx, repoOwner, repoName, prID)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(reviewComments), 13)
}
