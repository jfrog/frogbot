package utils

import (
	"context"
	"github.com/jfrog/jfrog-cli-security/utils/application"
	"github.com/jfrog/jfrog-client-go/application/services"
	"strings"
)

func SendCommitInfo(scanDetails *ScanDetails) (err error) {
	latestCommit, err := scanDetails.client.GetLatestCommit(context.Background(), scanDetails.Git.PullRequestDetails.Source.Owner,
		scanDetails.Git.PullRequestDetails.Source.Repository, scanDetails.Git.PullRequestDetails.Source.Name)
	if err != nil {
		return
	}
	changedFiles, err := scanDetails.client.GetModifiedFiles(context.Background(), scanDetails.Git.PullRequestDetails.Source.Owner,
		scanDetails.Git.PullRequestDetails.Source.Repository, latestCommit.Hash, latestCommit.ParentHashes[0])
	if err != nil {
		return
	}
	commitInfo := services.CreateApplicationCommitInfo{
		GitRepoUrl:     scanDetails.Git.RepositoryCloneUrl,
		CommitHash:     latestCommit.Hash,
		ParentHash:     latestCommit.ParentHashes[0],
		Branch:         scanDetails.Git.PullRequestDetails.Source.Name,
		AuthorEmail:    latestCommit.AuthorEmail,
		AuthorName:     latestCommit.AuthorName,
		AuthorDate:     latestCommit.AuthorDate,
		CommitterDate:  latestCommit.Timestamp,
		CommitterName:  latestCommit.CommitterName,
		CommitterEmail: latestCommit.CommitterEmail,
		MessageSubject: latestCommit.Message,
		ChangedFiles:   []byte(strings.Join(changedFiles, ",")),
	}

	return application.SendCommitInfo(scanDetails.ApplicationKey, scanDetails.ServerDetails, commitInfo)
}
