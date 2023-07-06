package commands

import (
	"context"
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
)

var mockPr = vcsclient.PullRequestInfo{
	ID:     1,
	Source: vcsclient.BranchInfo{Name: "pr"},
	Target: vcsclient.BranchInfo{Name: "main"},
}

var gitParams = &utils.Repository{
	OutputWriter: &utils.SimplifiedOutput{},
	Params: utils.Params{
		Git: utils.Git{
			ClientInfo: utils.ClientInfo{
				RepoOwner: "repo-owner",
				Branches:  []string{"master"},
				RepoName:  "repo-name",
			},
		},
	},
}

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=testdata/vcsclientmock.go -package=testdata github.com/jfrog/froggit-go/vcsclient VcsClient
func TestShouldScanPullRequestNewPR(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesPrBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldNotScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesPrBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func TestShouldNotScanPullRequest(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func mockVcsClient(t *testing.T) *testdata.MockVcsClient {
	mockCtrl := gomock.NewController(t)
	return testdata.NewMockVcsClient(mockCtrl)
}

func TestShouldNotScanPullRequestError(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{}, fmt.Errorf("Bad Request"))
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.Error(t, err)
	assert.False(t, shouldScan)
}

func TestScanAllPullRequestsMultiRepo(t *testing.T) {
	server, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	failOnSecurityIssues := false
	firstRepoParams := utils.Params{
		Scan: utils.Scan{
			FailOnSecurityIssues: &failOnSecurityIssues,
			Projects: []utils.Project{{
				WorkingDirs: []string{utils.RootDir},
				UseWrapper:  &utils.TrueVal,
			}},
		},
		Git: utils.Git{
			ClientInfo: utils.ClientInfo{
				RepoOwner: "repo-owner",
				Branches:  []string{"main"},
				RepoName:  "test-proj-with-vulnerability",
			},
		},
	}
	secondRepoParams := utils.Params{
		Git: utils.Git{
			ClientInfo: utils.ClientInfo{
				RepoOwner: "repo-owner",
				Branches:  []string{"main"},
				RepoName:  "test-proj-pip-with-vulnerability",
			},
		},
		Scan: utils.Scan{
			FailOnSecurityIssues: &failOnSecurityIssues,
			Projects:             []utils.Project{{WorkingDirs: []string{utils.RootDir}, UseWrapper: &utils.TrueVal}}},
	}

	configAggregator := utils.RepoAggregator{
		{
			OutputWriter: &utils.SimplifiedOutput{},
			Server:       server,
			Params:       firstRepoParams,
		},
		{
			OutputWriter: &utils.SimplifiedOutput{},
			Server:       server,
			Params:       secondRepoParams,
		},
	}

	tmpDir, cleanUp := utils.PrepareTestEnvironment(t, "", "scanpullrequests")
	defer cleanUp()

	client := mockVcsClient(t)
	client.EXPECT().ListPullRequestComments(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
	client.EXPECT().ListOpenPullRequests(gomock.Any(), gomock.Any(), gomock.Any()).Return([]vcsclient.PullRequestInfo{mockPr}, nil).AnyTimes()
	client.EXPECT().GetRepositoryInfo(gomock.Any(), gomock.Any(), gomock.Any()).Return(vcsclient.RepositoryInfo{CloneInfo: vcsclient.CloneInfo{}, RepositoryVisibility: 0}, nil).AnyTimes()
	client.EXPECT().GetRepositoryEnvironmentInfo(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(vcsclient.RepositoryEnvironmentInfo{Reviewers: []string{"reviewer"}}, nil).AnyTimes()
	client.EXPECT().AddPullRequestComment(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	scanAllPullRequestsCmd := &ScanAllPullRequestsCmd{true, tmpDir}
	err := scanAllPullRequestsCmd.Run(configAggregator, client)
	assert.NoError(t, err)
}

func TestScanAllPullRequests(t *testing.T) {
	// This integration test, requires JFrog platform connection details
	server, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	falseVal := false
	gitParams.Git.GitProvider = vcsutils.BitbucketServer
	params := utils.Params{
		Scan: utils.Scan{
			FailOnSecurityIssues: &falseVal,
			Projects: []utils.Project{{
				WorkingDirs: []string{"."},
				UseWrapper:  &utils.TrueVal,
			}},
		},
		Git: gitParams.Git,
	}
	repoParams := &utils.Repository{
		OutputWriter: &utils.SimplifiedOutput{},
		Server:       server,
		Params:       params,
	}
	paramsAggregator := utils.RepoAggregator{}
	paramsAggregator = append(paramsAggregator, *repoParams)
	wd, cleanUp := utils.PrepareTestEnvironment(t, "test-proj-with-vulnerability", "scanpullrequests")
	defer cleanUp()
	err := os.Chdir(wd)
	assert.NoError(t, err)

	client := mockVcsClient(t)
	client.EXPECT().ListOpenPullRequests(context.Background(), gomock.Any(), gomock.Any()).Return([]vcsclient.PullRequestInfo{mockPr, mockPr}, nil)
	client.EXPECT().ListPullRequestComments(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
	client.EXPECT().AddPullRequestComment(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	scanAllPullRequestsCmd := &ScanAllPullRequestsCmd{dryRun: true, dryRunRepoPath: wd}
	err = scanAllPullRequestsCmd.Run(paramsAggregator, client)
	assert.NoError(t, err)
}

func TestScanAllPullRequestsClean(t *testing.T) {
	// This integration test, requires JFrog platform connection details
	server, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	falseVal := false
	gitParams.Git.GitProvider = vcsutils.BitbucketServer
	params := utils.Params{
		Scan: utils.Scan{
			FailOnSecurityIssues: &falseVal,
			Projects: []utils.Project{{
				WorkingDirs: []string{"."},
				UseWrapper:  &utils.TrueVal,
			}},
		},
		Git: gitParams.Git,
	}
	repoParams := &utils.Repository{
		OutputWriter: &utils.SimplifiedOutput{},
		Server:       server,
		Params:       params,
	}
	paramsAggregator := utils.RepoAggregator{}
	paramsAggregator = append(paramsAggregator, *repoParams)
	wd, cleanUp := utils.PrepareTestEnvironment(t, "test-proj-clean", "scanpullrequests")
	defer cleanUp()
	err := os.Chdir(wd)
	assert.NoError(t, err)

	client := mockVcsClient(t)
	client.EXPECT().ListOpenPullRequests(context.Background(), gomock.Any(), gomock.Any()).Return([]vcsclient.PullRequestInfo{mockPr}, nil)
	client.EXPECT().ListPullRequestComments(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
	// Successful comment
	client.EXPECT().AddPullRequestComment(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	scanAllPullRequestsCmd := &ScanAllPullRequestsCmd{dryRun: true, dryRunRepoPath: wd}
	err = scanAllPullRequestsCmd.Run(paramsAggregator, client)
	assert.NoError(t, err)
}
