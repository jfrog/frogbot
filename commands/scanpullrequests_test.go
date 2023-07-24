package commands

import (
	"context"
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
)

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

type MockParams struct {
	repoName         string
	repoOwner        string
	sourceBranchName string
	targetBranchName string
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
				InstallCommandName: "npm",
				InstallCommandArgs: []string{"i"},
				WorkingDirs:        []string{utils.RootDir},
				UseWrapper:         &utils.TrueVal,
			}},
		},
		Git: gitParams.Git,
	}
	secondRepoParams := utils.Params{
		Git: gitParams.Git,
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
	mockParams := []MockParams{
		{gitParams.RepoName, gitParams.RepoOwner, "test-proj-with-vulnerability", "test-proj"},
		{gitParams.RepoName, gitParams.RepoOwner, "test-proj-pip-with-vulnerability", "test-proj-pip"},
	}
	var frogbotMessages []string
	client := getMockClient(t, &frogbotMessages, mockParams...)
	scanAllPullRequestsCmd := &ScanAllPullRequestsCmd{}
	err := scanAllPullRequestsCmd.Run(configAggregator, client)
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 4)
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
				InstallCommandName: "npm",
				InstallCommandArgs: []string{"i"},
				WorkingDirs:        []string{"."},
				UseWrapper:         &utils.TrueVal,
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
	var frogbotMessages []string
	client := getMockClient(t, &frogbotMessages, MockParams{repoParams.RepoName, repoParams.RepoOwner, "test-proj-with-vulnerability", "test-proj"})
	scanAllPullRequestsCmd := &ScanAllPullRequestsCmd{}
	err := scanAllPullRequestsCmd.Run(paramsAggregator, client)
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 2)
}

func getMockClient(t *testing.T, frogbotMessages *[]string, mockParams ...MockParams) *testdata.MockVcsClient {
	// Init mock
	client := mockVcsClient(t)
	for _, params := range mockParams {
		sourceBranchInfo := vcsclient.BranchInfo{Name: params.sourceBranchName, Repository: params.repoName, Owner: params.repoOwner}
		targetBranchInfo := vcsclient.BranchInfo{Name: params.targetBranchName, Repository: params.repoName, Owner: params.repoOwner}
		// Return 2 pull requests to scan, the first with issues the second "clean".
		client.EXPECT().ListOpenPullRequests(context.Background(), params.repoOwner, params.repoName).Return([]vcsclient.PullRequestInfo{{ID: 1, Source: sourceBranchInfo, Target: targetBranchInfo}, {ID: 2, Source: targetBranchInfo, Target: targetBranchInfo}}, nil)
		// Return empty comments slice so expect the code to scan both pull requests.
		client.EXPECT().ListPullRequestComments(context.Background(), params.repoOwner, params.repoName, gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
		// Copy test project according to the given branch name, instead of download it.
		client.EXPECT().DownloadRepository(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(fakeRepoDownload).AnyTimes()
		// Capture the result comment post
		client.EXPECT().AddPullRequestComment(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _, _, content string, _ int) error {
			*frogbotMessages = append(*frogbotMessages, content)
			return nil
		}).AnyTimes()
		// Return private repositories visibility
		client.EXPECT().GetRepositoryInfo(context.Background(), gomock.Any(), gomock.Any()).Return(vcsclient.RepositoryInfo{RepositoryVisibility: vcsclient.Private}, nil).AnyTimes()
	}
	return client
}

// To accurately simulate the "real" repository download, the tests project must be located in the same directory.
// The process involves the following steps:
// 1. First, the "test-proj-with-vulnerability" project, which includes a "test-proj" directory, will be copied to a temporary directory with a random name. This project will be utilized during the source auditing phase to mimic a pull request with a new vulnerable dependency.
// 2. Next, a second "download" will take place within the first temporary directory. As a result, the "test-proj" directory will be discovered and copied to a second temporary directory with another random name. This copied version will be used during the target auditing phase.
func fakeRepoDownload(_ context.Context, _, _, testProject, targetDir string) error {
	sourceDir, err := filepath.Abs(filepath.Join("testdata", "scanpullrequests", testProject))
	if err != nil {
		return err
	}
	return fileutils.CopyDir(sourceDir, targetDir, true, []string{})
}
