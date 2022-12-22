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

var gitParams = &utils.FrogbotRepoConfig{
	Params: utils.Params{
		Git: utils.Git{
			RepoOwner: "repo-owner",
			Branches:  []string{"master"},
			RepoName:  "repo-name",
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
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
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
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
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
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
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
	firstRepoParams := utils.Params{
		Scan: utils.Scan{
			Projects: []utils.Project{{
				InstallCommandName: "npm",
				InstallCommandArgs: []string{"i"},
				WorkingDirs:        []string{"."},
			},
			}},
		Git: gitParams.Git,
	}
	secondRepoParams := utils.Params{Git: gitParams.Git}
	configAggregator := utils.FrogbotConfigAggregator{
		{
			Server: server,
			Params: firstRepoParams,
		},
		{
			Server: server,
			Params: secondRepoParams,
		},
	}
	mockParams := []MockParams{
		{gitParams.RepoName, gitParams.RepoOwner, "test-proj-with-vulnerability", "test-proj"},
		{gitParams.RepoName, gitParams.RepoOwner, "test-proj-pip-with-vulnerability", "test-proj-pip"},
	}
	var frogbotMessages []string
	client := getMockClient(t, &frogbotMessages, mockParams...)
	scanAllPullRequestsCmd := ScanAllPullRequestsCmd{}
	err := scanAllPullRequestsCmd.Run(configAggregator, client)
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 4)
	expectedMessage := "Frogbot scanned this pull request and found the issues blow: \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n\n| SEVERITY | IMPACTED PACKAGE | VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n:--: | -- | -- | -- | -- | :--: | --\n| Critical | minimist | 1.2.5 | [1.2.6] | minimist | 1.2.5 | CVE-2021-44906 "
	assert.Equal(t, expectedMessage, frogbotMessages[0])
	expectedMessage = "Frogbot scanned this pull request and found that it did not add vulnerable dependencies. \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n"
	assert.Equal(t, expectedMessage, frogbotMessages[1])
	expectedMessage = "Frogbot scanned this pull request and found the issues blow: \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n\n| SEVERITY | IMPACTED PACKAGE | VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n:--: | -- | -- | -- | -- | :--: | --\n|     High | pyjwt | 1.7.1 | [2.4.0] | pyjwt | 1.7.1 | CVE-2022-29217 "
	assert.Equal(t, expectedMessage, frogbotMessages[2])
	expectedMessage = "Frogbot scanned this pull request and found that it did not add vulnerable dependencies. \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n"
	assert.Equal(t, expectedMessage, frogbotMessages[3])
}

func TestScanAllPullRequests(t *testing.T) {
	// This integration test, requires JFrog platform connection details
	server, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	falseVal := false
	params := utils.Params{
		Scan: utils.Scan{
			FailOnSecurityIssues: &falseVal,
			Projects: []utils.Project{{
				InstallCommandName: "npm",
				InstallCommandArgs: []string{"i"},
				WorkingDirs:        []string{"."},
			}},
		},
		Git: gitParams.Git,
	}
	repoParams := &utils.FrogbotRepoConfig{
		Server: server,
		Params: params,
	}
	paramsAggregator := utils.FrogbotConfigAggregator{}
	paramsAggregator = append(paramsAggregator, *repoParams)
	var frogbotMessages []string
	client := getMockClient(t, &frogbotMessages, MockParams{repoParams.RepoName, repoParams.RepoOwner, "test-proj-with-vulnerability", "test-proj"})
	scanAllPullRequestsCmd := ScanAllPullRequestsCmd{}
	err := scanAllPullRequestsCmd.Run(paramsAggregator, client)
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 2)
	expectedMessage := "Frogbot scanned this pull request and found the issues blow: \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n\n| SEVERITY | IMPACTED PACKAGE | VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n:--: | -- | -- | -- | -- | :--: | --\n|  Critical | minimist | 1.2.5 | [1.2.6] | minimist | 1.2.5 | CVE-2021-44906 "
	assert.Equal(t, expectedMessage, frogbotMessages[0])
	expectedMessage = "Frogbot scanned this pull request and found that it did not add vulnerable dependencies. \n\n\n[What is Frogbot?](https://github.com/jfrog/frogbot#readme)\n"
	assert.Equal(t, expectedMessage, frogbotMessages[1])
}

func getMockClient(t *testing.T, frogbotMessages *[]string, mockParams ...MockParams) *testdata.MockVcsClient {
	// Init mock
	client := mockVcsClient(t)
	for _, params := range mockParams {
		sourceBranchInfo := vcsclient.BranchInfo{Name: params.sourceBranchName, Repository: params.repoName}
		targetBranchInfo := vcsclient.BranchInfo{Name: params.targetBranchName, Repository: params.repoName}
		// Return 2 pull requests to scan, the first with issues the second "clean".
		client.EXPECT().ListOpenPullRequests(context.Background(), params.repoOwner, params.repoName).Return([]vcsclient.PullRequestInfo{{ID: 0, Source: sourceBranchInfo, Target: targetBranchInfo}, {ID: 1, Source: targetBranchInfo, Target: targetBranchInfo}}, nil)
		// Return empty comments slice so expect the code to scan both pull requests.
		client.EXPECT().ListPullRequestComments(context.Background(), params.repoOwner, params.repoName, gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
		// Copy test project according to the given branch name, instead of download it.
		client.EXPECT().DownloadRepository(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(fakeRepoDownload).AnyTimes()
		// Capture the result comment post
		client.EXPECT().AddPullRequestComment(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _, _, content string, _ int) error {
			*frogbotMessages = append(*frogbotMessages, content)
			return nil
		}).AnyTimes()
	}
	return client
}

func fakeRepoDownload(_ context.Context, _, _, testProject, localPath string) error {
	// In order to mimic the "real" repository download the tests project have to be in the same dir:
	// First test-proj-with-vulnerability (that includes a "test-proj" dir) will be copied to a temp (random) dir.
	// This project will be used in the source auditing phase - mimic a PR with a new vulnerable dependency.
	// Second "download" will occur inside the first temp dir. Therefor the "test-proj" will be found and will
	// be copied to the second (random) temp dir and will be used in the target auditing phase.
	err := fileutils.CopyDir(filepath.Join(testProject), localPath, true, []string{})
	if err != nil {
		return err
	}
	return fileutils.CopyDir(filepath.Join("testdata", "scanpullrequests", testProject), localPath, true, []string{})
}
