package application

import (
	"context"
	utils "github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"strings"
)

type ApplicationManager struct {
	vcsClient  vcsclient.VcsClient
	gitDetails utils.Git
}

func NewApplicationManager(vcsClient vcsclient.VcsClient, gitDetails utils.Git) *ApplicationManager {
	return &ApplicationManager{
		vcsClient:  vcsClient,
		gitDetails: gitDetails,
	}
}

type ApplicationCommitInfo struct {
	VcsUrl         string `json:"vcs_url"`
	CommitHash     string `json:"commit_hash"`
	ParentHash     string `json:"parent_hash"`
	Branch         string `json:"branch"`
	AuthorEmail    string `json:"author_email"`
	AuthorName     string `json:"author_name"`
	AuthorDate     int64  `json:"author_date"`
	CommitterEmail string `json:"committer_email"`
	CommitterName  string `json:"committer_name"`
	CommitterDate  int64  `json:"committer_date"`
	MessageSubject string `json:"message_subject"`
	ChangedFiles   []byte `json:"changed_files"`
}

func (ap *ApplicationManager) CreateApplicationCommitInfo() (*ApplicationCommitInfo, error) {
	latestCommit, err := ap.vcsClient.GetLatestCommit(context.Background(), ap.gitDetails.PullRequestDetails.Source.Owner,
		ap.gitDetails.PullRequestDetails.Source.Repository, ap.gitDetails.PullRequestDetails.Source.Name)
	if err != nil {
		return nil, err
	}
	changedFiles, err := ap.vcsClient.GetModifiedFiles(context.Background(), ap.gitDetails.PullRequestDetails.Source.Owner,
		ap.gitDetails.PullRequestDetails.Source.Repository, latestCommit.Hash, latestCommit.ParentHashes[0])
	if err != nil {
		return nil, err
	}
	return &ApplicationCommitInfo{
		VcsUrl:         ap.gitDetails.RepositoryCloneUrl,
		CommitHash:     latestCommit.Hash,
		ParentHash:     latestCommit.ParentHashes[0],
		Branch:         ap.gitDetails.PullRequestDetails.Source.Name,
		AuthorEmail:    latestCommit.AuthorEmail,
		AuthorName:     latestCommit.AuthorName,
		AuthorDate:     latestCommit.AuthorDate,
		CommitterDate:  latestCommit.Timestamp,
		CommitterName:  latestCommit.CommitterName,
		CommitterEmail: latestCommit.CommitterEmail,
		MessageSubject: latestCommit.Message,
		ChangedFiles:   []byte(strings.Join(changedFiles, ",")),
	}, nil
}
