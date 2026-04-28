package utils

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/v2/testdata"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetSastChangedFilesOnly(t *testing.T) {
	sd := NewScanDetails(nil, nil, &Git{}).SetSastChangedFilesOnly(true)
	assert.True(t, sd.SastChangedFilesOnly)
}

func TestSetXscPRGitInfoContext_PopulatesChangedFiles(t *testing.T) {
	const (
		repoOwner      = "acme"
		repoName       = "app"
		sourceBranch   = "feature"
		targetBranch   = "main"
	)
	ctrl := gomock.NewController(t)
	client := testdata.NewMockVcsClient(ctrl)
	prDetails := vcsclient.PullRequestInfo{
		ID:     1,
		Title:  "t",
		Source: vcsclient.BranchInfo{Name: sourceBranch},
		Target: vcsclient.BranchInfo{Name: targetBranch},
	}
	commit := vcsclient.CommitInfo{Hash: "a", Message: "m", AuthorName: "a"}
	client.EXPECT().GetLatestCommit(context.Background(), repoOwner, repoName, sourceBranch).Return(commit, nil)
	client.EXPECT().GetLatestCommit(context.Background(), repoOwner, repoName, targetBranch).Return(commit, nil)
	changed := []string{"dir/a.go", "b.go"}
	client.EXPECT().GetModifiedFiles(context.Background(), repoOwner, repoName, targetBranch, sourceBranch).Return(changed, nil)

	git := &Git{
		GitProvider:        vcsutils.GitHub,
		RepoOwner:          repoOwner,
		RepoName:           repoName,
		RepositoryCloneUrl: "https://github.com/" + repoOwner + "/" + repoName + ".git",
	}
	sd := NewScanDetails(client, nil, git).SetXscPRGitInfoContext("", client, prDetails)
	require.NotNil(t, sd.XscGitInfoContext)
	assert.Equal(t, changed, sd.XscGitInfoContext.ChangedFiles)
}

func TestSetXscPRGitInfoContext_IgnoresGetModifiedFilesError(t *testing.T) {
	const (
		repoOwner    = "acme"
		repoName     = "app"
		sourceBranch = "feature"
		targetBranch = "main"
	)
	ctrl := gomock.NewController(t)
	client := testdata.NewMockVcsClient(ctrl)
	prDetails := vcsclient.PullRequestInfo{
		ID:     1,
		Title:  "t",
		Source: vcsclient.BranchInfo{Name: sourceBranch},
		Target: vcsclient.BranchInfo{Name: targetBranch},
	}
	commit := vcsclient.CommitInfo{Hash: "a", Message: "m", AuthorName: "a"}
	client.EXPECT().GetLatestCommit(context.Background(), repoOwner, repoName, sourceBranch).Return(commit, nil)
	client.EXPECT().GetLatestCommit(context.Background(), repoOwner, repoName, targetBranch).Return(commit, nil)
	client.EXPECT().GetModifiedFiles(context.Background(), repoOwner, repoName, targetBranch, sourceBranch).Return(nil, errors.New("vcs error"))

	git := &Git{
		GitProvider:        vcsutils.GitHub,
		RepoOwner:          repoOwner,
		RepoName:           repoName,
		RepositoryCloneUrl: "https://github.com/" + repoOwner + "/" + repoName + ".git",
	}
	sd := NewScanDetails(client, nil, git).SetXscPRGitInfoContext("", client, prDetails)
	require.NotNil(t, sd.XscGitInfoContext)
	assert.Nil(t, sd.XscGitInfoContext.ChangedFiles)
}

func TestGetFullPathWorkingDirs(t *testing.T) {
	sampleProject := Project{
		WorkingDirs: []string{filepath.Join("a", "b"), filepath.Join("a", "b", "c"), ".", filepath.Join("c", "d", "e", "f")},
	}
	baseWd := "tempDir"
	fullPathWds := GetFullPathWorkingDirs(sampleProject.WorkingDirs, baseWd)
	expectedWds := []string{filepath.Join("tempDir", "a", "b"), filepath.Join("tempDir", "a", "b", "c"), "tempDir", filepath.Join("tempDir", "c", "d", "e", "f")}
	for _, expectedWd := range expectedWds {
		assert.Contains(t, fullPathWds, expectedWd)
	}
}
