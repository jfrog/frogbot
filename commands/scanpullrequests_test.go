package commands

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
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
	client, finish := mockVcsClient(t)
	defer finish()
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldScanPullRequestReScan(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
	}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldNotScanPullRequestReScan(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func TestShouldNotScanPullRequest(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), params.RepoOwner, params.Repo, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(params, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func mockVcsClient(t *testing.T) (*testdata.MockVcsClient, func()) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	return testdata.NewMockVcsClient(mockCtrl), mockCtrl.Finish
}
