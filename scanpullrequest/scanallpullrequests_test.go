package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/golang/mock/gomock"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/v2/testdata"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

var (
	gitParams = &utils.Repository{
		OutputWriter: &outputwriter.SimplifiedOutput{},
		Params: utils.Params{
			Git: utils.Git{
				RepoOwner: "repo-owner",
				Branches:  []string{"master"},
				RepoName:  "repo-name",
			},
		},
	}
	allPrIntegrationPath = filepath.Join(outputwriter.TestMessagesDir, "integration")
)

type MockParams struct {
	repoName         string
	repoOwner        string
	sourceBranchName string
	targetBranchName string
}

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=../testdata/vcsclientmock.go -package=testdata github.com/jfrog/froggit-go/vcsclient VcsClient
func TestShouldScanPullRequestNewPR(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: outputwriter.GetSimplifiedTitle(outputwriter.VulnerabilitiesPrBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldNotScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + outputwriter.MarkAsBold(outputwriter.GetSimplifiedTitle(outputwriter.VulnerabilitiesPrBannerSource)) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
		{Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + outputwriter.MarkAsBold(outputwriter.GetSimplifiedTitle(outputwriter.NoVulnerabilityPrBannerSource)) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func TestShouldNotScanPullRequest(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + outputwriter.MarkAsBold(outputwriter.GetSimplifiedTitle(outputwriter.NoVulnerabilityPrBannerSource)) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func TestShouldNotScanPullRequestError(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{}, fmt.Errorf("Bad Request"))
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.Error(t, err)
	assert.False(t, shouldScan)
}

func TestScanAllPullRequestsMultiRepo(t *testing.T) {
	server, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(&server)
	assert.NoError(t, err)

	_, restoreJfrogHomeFunc := utils.CreateTempJfrogHomeWithCallback(t)
	defer restoreJfrogHomeFunc()

	failOnSecurityIssues := false
	firstRepoParams := utils.Params{
		JFrogPlatform: utils.JFrogPlatform{XrayVersion: xrayVersion, XscVersion: xscVersion},
		Scan: utils.Scan{
			AddPrCommentOnSuccess: true,
			FailOnSecurityIssues:  &failOnSecurityIssues,
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
		Git:           gitParams.Git,
		JFrogPlatform: utils.JFrogPlatform{XrayVersion: xrayVersion, XscVersion: xscVersion},
		Scan: utils.Scan{
			AddPrCommentOnSuccess: true,
			FailOnSecurityIssues:  &failOnSecurityIssues,
			Projects:              []utils.Project{{WorkingDirs: []string{utils.RootDir}, UseWrapper: &utils.TrueVal}}},
	}

	configAggregator := utils.RepoAggregator{
		utils.Repository{
			OutputWriter: &outputwriter.StandardOutput{},
			Server:       server,
			Params:       firstRepoParams,
		},
		utils.Repository{
			OutputWriter: &outputwriter.StandardOutput{},
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
	err = scanAllPullRequestsCmd.Run(configAggregator, client, utils.MockHasConnection())
	if assert.NoError(t, err) {
		assert.Len(t, frogbotMessages, 4)
		expectedMessage := outputwriter.GetOutputFromFile(t, filepath.Join(allPrIntegrationPath, "test_proj_with_vulnerability_standard.md"))
		assert.Equal(t, expectedMessage, frogbotMessages[0])
		expectedMessage = outputwriter.GetPRSummaryContentNoIssues(t, outputwriter.TestSummaryCommentDir, true, false)
		assert.Equal(t, expectedMessage, frogbotMessages[1])
		expectedMessage = outputwriter.GetOutputFromFile(t, filepath.Join(allPrIntegrationPath, "test_proj_pip_with_vulnerability.md"))
		assert.Equal(t, expectedMessage, frogbotMessages[2])
		expectedMessage = outputwriter.GetPRSummaryContentNoIssues(t, outputwriter.TestSummaryCommentDir, true, false)
		assert.Equal(t, expectedMessage, frogbotMessages[3])
	}
}

func TestScanAllPullRequests(t *testing.T) {
	// This integration test, requires JFrog platform connection details
	server, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(&server)
	assert.NoError(t, err)

	falseVal := false
	gitParams.Git.GitProvider = vcsutils.BitbucketServer
	params := utils.Params{
		JFrogPlatform: utils.JFrogPlatform{XrayVersion: xrayVersion, XscVersion: xscVersion},
		Scan: utils.Scan{
			AddPrCommentOnSuccess: true,
			FailOnSecurityIssues:  &falseVal,
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
		OutputWriter: &outputwriter.SimplifiedOutput{},
		Server:       server,
		Params:       params,
	}
	paramsAggregator := utils.RepoAggregator{}
	paramsAggregator = append(paramsAggregator, *repoParams)
	var frogbotMessages []string
	client := getMockClient(t, &frogbotMessages, MockParams{repoParams.RepoName, repoParams.RepoOwner, "test-proj-with-vulnerability", "test-proj"})
	scanAllPullRequestsCmd := &ScanAllPullRequestsCmd{}
	err = scanAllPullRequestsCmd.Run(paramsAggregator, client, utils.MockHasConnection())
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 2)
	expectedMessage := outputwriter.GetOutputFromFile(t, filepath.Join(allPrIntegrationPath, "test_proj_with_vulnerability_simplified.md"))
	assert.Equal(t, expectedMessage, frogbotMessages[0])
	expectedMessage = outputwriter.GetPRSummaryContentNoIssues(t, outputwriter.TestSummaryCommentDir, true, true)
	assert.Equal(t, expectedMessage, frogbotMessages[1])
}

func TestIsPullRequestFromSameRepository(t *testing.T) {
	testCases := []struct {
		name     string
		source   vcsclient.BranchInfo
		target   vcsclient.BranchInfo
		expected bool
	}{
		{name: "same repository", source: vcsclient.BranchInfo{Owner: "owner", Repository: "repo"}, target: vcsclient.BranchInfo{Owner: "owner", Repository: "repo"}, expected: true},
		{name: "same repository different case", source: vcsclient.BranchInfo{Owner: "OWNER", Repository: "Repo"}, target: vcsclient.BranchInfo{Owner: "owner", Repository: "repo"}, expected: true},
		{name: "fork with different owner", source: vcsclient.BranchInfo{Owner: "attacker", Repository: "repo"}, target: vcsclient.BranchInfo{Owner: "owner", Repository: "repo"}, expected: false},
		{name: "fork with different repository name", source: vcsclient.BranchInfo{Owner: "owner", Repository: "repo-fork"}, target: vcsclient.BranchInfo{Owner: "owner", Repository: "repo"}, expected: false},
		{name: "missing source owner", source: vcsclient.BranchInfo{Repository: "repo"}, target: vcsclient.BranchInfo{Owner: "owner", Repository: "repo"}, expected: false},
		{name: "missing source repository", source: vcsclient.BranchInfo{Owner: "owner"}, target: vcsclient.BranchInfo{Owner: "owner", Repository: "repo"}, expected: false},
		{name: "missing source and target owner", source: vcsclient.BranchInfo{Repository: "repo"}, target: vcsclient.BranchInfo{Repository: "repo"}, expected: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pr := vcsclient.PullRequestInfo{Source: testCase.source, Target: testCase.target}
			assert.Equal(t, testCase.expected, isPullRequestFromSameRepository(pr))
		})
	}
}

func TestIsUntrustedScanAllPrsAllowed(t *testing.T) {
	testCases := []struct {
		name          string
		envValue      string
		expected      bool
		expectedError bool
	}{
		{name: "unset", envValue: "", expected: false},
		{name: "true", envValue: "true", expected: true},
		{name: "TRUE with spaces", envValue: " TRUE ", expected: true},
		{name: "false", envValue: "false", expected: false},
		{name: "invalid", envValue: "yes please", expectedError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(utils.AllowUntrustedScanAllPrsEnv, testCase.envValue)
			allowed, err := isUntrustedScanAllPrsAllowed()
			if testCase.expectedError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, allowed)
		})
	}
}

func TestScanAllPullRequestsTrustFilter(t *testing.T) {
	sameRepo := vcsclient.BranchInfo{Name: "feature", Owner: "repo-owner", Repository: "repo-name"}
	target := vcsclient.BranchInfo{Name: "main", Owner: "repo-owner", Repository: "repo-name"}
	testCases := []struct {
		name           string
		source         vcsclient.BranchInfo
		allowUntrusted bool
		expectScan     bool
	}{
		{name: "same repository", source: sameRepo, expectScan: true},
		{name: "same repository different case", source: vcsclient.BranchInfo{Name: "feature", Owner: "REPO-OWNER", Repository: "Repo-Name"}, expectScan: true},
		{name: "fork is skipped", source: vcsclient.BranchInfo{Name: "feature", Owner: "attacker", Repository: "repo-name"}, expectScan: false},
		{name: "missing source details are skipped", source: vcsclient.BranchInfo{Name: "feature"}, expectScan: false},
		{name: "fork is scanned when untrusted scans are allowed", source: vcsclient.BranchInfo{Name: "feature", Owner: "attacker", Repository: "repo-name"}, allowUntrusted: true, expectScan: true},
		{name: "missing source details are scanned when untrusted scans are allowed", source: vcsclient.BranchInfo{Name: "feature"}, allowUntrusted: true, expectScan: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := CreateMockVcsClient(t)
			repo := utils.Repository{
				OutputWriter: &outputwriter.SimplifiedOutput{},
				Params:       utils.Params{Git: utils.Git{RepoOwner: "repo-owner", RepoName: "repo-name"}},
			}
			client.EXPECT().ListOpenPullRequests(context.Background(), repo.RepoOwner, repo.RepoName).Return([]vcsclient.PullRequestInfo{{ID: 1, Source: testCase.source, Target: target}}, nil)
			if testCase.expectScan {
				// The failure stops the flow right after the filter, which is enough to know the pull request was not skipped.
				client.EXPECT().ListPullRequestComments(context.Background(), repo.RepoOwner, repo.RepoName, 1).Return(nil, errors.New("stop"))
			}
			err := scanAllPullRequests(repo, client, testCase.allowUntrusted)
			if testCase.expectScan {
				assert.ErrorContains(t, err, "pull request #1")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScanAllPullRequestsRunGate(t *testing.T) {
	testCases := []struct {
		name        string
		gitProvider vcsutils.VcsProvider
		envValue    string
		expectedErr string
	}{
		{name: "github without frogbot environment is blocked", gitProvider: vcsutils.GitHub, expectedErr: noGitHubEnvErr},
		{name: "github without frogbot environment is blocked even when untrusted scans are allowed", gitProvider: vcsutils.GitHub, envValue: "true", expectedErr: noGitHubEnvErr},
		{name: "non github provider is not gated", gitProvider: vcsutils.GitLab},
		{name: "invalid env value", gitProvider: vcsutils.GitLab, envValue: "bad", expectedErr: utils.AllowUntrustedScanAllPrsEnv},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(utils.GitHubActionsEnv, "true")
			t.Setenv(utils.AllowUntrustedScanAllPrsEnv, testCase.envValue)
			client := CreateMockVcsClient(t)
			repo := utils.Repository{
				OutputWriter: &outputwriter.SimplifiedOutput{},
				Params:       utils.Params{Git: utils.Git{RepoOwner: "repo-owner", RepoName: "repo-name", VcsInfo: vcsclient.VcsInfo{}}},
			}
			repo.GitProvider = testCase.gitProvider
			switch {
			case testCase.gitProvider == vcsutils.GitHub:
				client.EXPECT().GetRepositoryInfo(context.Background(), repo.RepoOwner, repo.RepoName).Return(vcsclient.RepositoryInfo{RepositoryVisibility: vcsclient.Public}, nil)
				client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), repo.RepoOwner, repo.RepoName, "frogbot").Return(vcsclient.RepositoryEnvironmentInfo{}, errors.New("404"))
			case testCase.expectedErr == "":
				client.EXPECT().ListOpenPullRequests(context.Background(), repo.RepoOwner, repo.RepoName).Return([]vcsclient.PullRequestInfo{}, nil)
			}
			err := (&ScanAllPullRequestsCmd{}).Run(utils.RepoAggregator{repo}, client, utils.MockHasConnection())
			if testCase.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCase.expectedErr)
			}
		})
	}
}

func getMockClient(t *testing.T, frogbotMessages *[]string, mockParams ...MockParams) *testdata.MockVcsClient {
	// Init mock
	client := CreateMockVcsClient(t)
	for _, params := range mockParams {
		sourceBranchInfo := vcsclient.BranchInfo{Name: params.sourceBranchName, Repository: params.repoName, Owner: params.repoOwner}
		targetBranchInfo := vcsclient.BranchInfo{Name: params.targetBranchName, Repository: params.repoName, Owner: params.repoOwner}
		// Return 2 pull requests to scan, the first with issues the second "clean".
		client.EXPECT().ListOpenPullRequests(context.Background(), params.repoOwner, params.repoName).Return([]vcsclient.PullRequestInfo{{ID: 1, Source: sourceBranchInfo, Target: targetBranchInfo, Author: "a"}, {ID: 2, Source: targetBranchInfo, Target: targetBranchInfo, Author: "a"}}, nil)
		// Return empty comments slice so expect the code to scan both pull requests.
		client.EXPECT().ListPullRequestComments(context.Background(), params.repoOwner, params.repoName, gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
		client.EXPECT().ListPullRequestReviewComments(context.Background(), params.repoOwner, params.repoName, gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
		// Copy test project according to the given branch name, instead of download it.
		client.EXPECT().DownloadRepository(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(fakeRepoDownload).AnyTimes()
		// Capture the result comment post
		client.EXPECT().AddPullRequestComment(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _, _, content string, _ int) error {
			*frogbotMessages = append(*frogbotMessages, content)
			return nil
		}).AnyTimes()
		client.EXPECT().AddPullRequestReviewComments(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _, _, content string, _ int) error {
			*frogbotMessages = append(*frogbotMessages, content)
			return nil
		}).AnyTimes()
		client.EXPECT().DeletePullRequestComment(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		client.EXPECT().DeletePullRequestReviewComments(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		// Return private repositories visibility
		client.EXPECT().GetRepositoryInfo(context.Background(), gomock.Any(), gomock.Any()).Return(vcsclient.RepositoryInfo{RepositoryVisibility: vcsclient.Private}, nil).AnyTimes()
		// Return latest commit info for XSC context.
		client.EXPECT().GetLatestCommit(context.Background(), params.repoOwner, params.repoName, gomock.Any()).Return(vcsclient.CommitInfo{}, nil).AnyTimes()
		client.EXPECT().GetModifiedFiles(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).Return([]string{}, nil).AnyTimes()
	}
	return client
}

// To accurately simulate the "real" repository download, the tests project must be located in the same directory.
// The process involves the following steps:
// 1. First, the "test-proj-with-vulnerability" project, which includes a "test-proj" directory, will be copied to a temporary directory with a random name. This project will be utilized during the source auditing phase to mimic a pull request with a new vulnerable dependency.
// 2. Next, a second "download" will take place within the first temporary directory. As a result, the "test-proj" directory will be discovered and copied to a second temporary directory with another random name. This copied version will be used during the target auditing phase.
func fakeRepoDownload(_ context.Context, _, _, testProject, targetDir string) error {
	sourceDir, err := filepath.Abs(filepath.Join("..", "testdata", "scanallpullrequests", testProject))
	if err != nil {
		return err
	}
	return biutils.CopyDir(sourceDir, targetDir, true, []string{})
}

func CreateMockVcsClient(t *testing.T) *testdata.MockVcsClient {
	return testdata.NewMockVcsClient(gomock.NewController(t))
}
