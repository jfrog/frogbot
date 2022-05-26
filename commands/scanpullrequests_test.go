package commands

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

var params = &utils.FrogbotParams{
	GitParam: utils.GitParam{
		RepoOwner:  "repo-owner",
		Repo:       "repo-name",
		BaseBranch: "master",
	},
}

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=testdata/vcsclientmock.go -package=testdata github.com/jfrog/froggit-go/vcsclient VcsClient
func TestShouldScanPullRequestNewPR(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldNotScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func TestShouldNotScanPullRequest(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(params, client, prID)
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
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{}, fmt.Errorf("Bad Request"))
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.Error(t, err)
	assert.False(t, shouldScan)
}

func TestScanAllPullRequests(t *testing.T) {
	// This integration test, requires JFrog platform connection details
	jfrogParams, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	params := &utils.FrogbotParams{
		JFrogEnvParams:     jfrogParams,
		GitParam:           params.GitParam,
		InstallCommandName: "npm",
		InstallCommandArgs: []string{"i"},
	}
	// Init mock
	client := mockVcsClient(t)
	sourceBranchInfo := vcsclient.BranchInfo{Name: "test-proj-with-vulnerability", Repository: params.Repo}
	targetBranchInfo := vcsclient.BranchInfo{Name: "test-proj", Repository: params.Repo}
	// Return 2 pull requests to scan, the first with issues the seconde "clean".
	client.EXPECT().ListOpenPullRequests(context.Background(), params.RepoOwner, params.Repo).Return([]vcsclient.PullRequestInfo{{ID: 0, Source: sourceBranchInfo, Target: targetBranchInfo}, {ID: 1, Source: targetBranchInfo, Target: targetBranchInfo}}, nil)
	// Return empty comments slice so expect the code to scan both pull requests.
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
	// Copy test project according to the given branch name, instead of download it.
	client.EXPECT().DownloadRepository(context.Background(), params.RepoOwner, sourceBranchInfo.Repository, gomock.Any(), gomock.Any()).DoAndReturn(fakeRepoDownload).AnyTimes()
	// Capture the result comment post
	var frogbotMessages []string
	client.EXPECT().AddPullRequestComment(context.Background(), params.RepoOwner, params.Repo, gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _, _, content string, _ int) error {
		frogbotMessages = append(frogbotMessages, content)
		return nil
	}).AnyTimes()
	scanAllPullRequestsCmd := ScanAllPullRequestsCmd{}
	err := scanAllPullRequestsCmd.Run(params, client)
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 2)
	expectedMessage := "🐸 Frogbot scanned this pull request and found the issues blow: \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n\n| SEVERITY | IMPACTED PACKAGE | VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n:--: | -- | -- | -- | -- | :--: | --\n| 💀 Critical | minimist | 1.2.5 | [1.2.6] | minimist | 1.2.5 | CVE-2021-44906 "
	assert.Equal(t, expectedMessage, frogbotMessages[0])
	expectedMessage = "🐸 Frogbot scanned this pull request and found that it did not add vulnerable dependencies. \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n"
	assert.Equal(t, expectedMessage, frogbotMessages[1])
}

func fakeRepoDownload(_ context.Context, _, _, testProject, localPath string) error {
	// In order to mimic the "real" repository download the tests project have to be in the same dir:
	// First test-proj-with-vulnerability(that contains a "test-proj" dir) will be copied to a temp (random) dir.
	// This project will be used in the source auditing phase - mimic a PR with a new vulnerable dependency.
	// Seconde "download" will ocurre inside the first temp dir, therefore the "test-proj" will be found and will
	// be copied to the second (random) temp dir and will be used in the target auditing phase.
	err := fileutils.CopyDir(filepath.Join(testProject), localPath, true, []string{})
	if err != nil {
		return err
	}
	return fileutils.CopyDir(filepath.Join("testdata", "scanpullrequests", testProject), localPath, true, []string{})
}
