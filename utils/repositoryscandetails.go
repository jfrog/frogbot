package utils

import (
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
)

type RepositoryScanDetails struct {
	*ScanDetails
	baseBranch string
}

func NewRepositoryScanDetails(client vcsclient.VcsClient, repository *Repository) *RepositoryScanDetails {
	return &RepositoryScanDetails{ScanDetails: newScanDetails(client, repository)}
}

func (rsd *RepositoryScanDetails) SetBaseBranch(branch string) *RepositoryScanDetails {
	rsd.baseBranch = branch
	return rsd
}

func (rsd *RepositoryScanDetails) BaseBranch() string {
	return rsd.baseBranch
}

func (rsd *RepositoryScanDetails) SetRepoOwner(owner string) *RepositoryScanDetails {
	rsd.git.RepoOwner = owner
	return rsd
}

func (rsd *RepositoryScanDetails) RepoOwner() string {
	return rsd.git.RepoOwner
}

func (rsd *RepositoryScanDetails) SetRepoName(repoName string) *RepositoryScanDetails {
	rsd.git.RepoName = repoName
	return rsd
}

func (rsd *RepositoryScanDetails) RepoName() string {
	return rsd.git.RepoName
}

func (rsd *RepositoryScanDetails) BranchNameTemplate() string {
	return rsd.git.BranchNameTemplate
}

func (rsd *RepositoryScanDetails) CommitMessageTemplate() string {
	return rsd.git.CommitMessageTemplate
}

func (rsd *RepositoryScanDetails) PullRequestTitleTemplate() string {
	return rsd.git.PullRequestTitleTemplate
}

func (rsd *RepositoryScanDetails) EmailAuthor() string {
	return rsd.git.EmailAuthor
}

func (rsd *RepositoryScanDetails) GitProvider() vcsutils.VcsProvider {
	return rsd.git.GitProvider
}

func (rsd *RepositoryScanDetails) VcsInfo() vcsclient.VcsInfo {
	return rsd.git.VcsInfo
}

func (rsd *RepositoryScanDetails) SetAggregateFixes(toAggregate bool) *RepositoryScanDetails {
	rsd.git.AggregateFixes = toAggregate
	return rsd
}

func (rsd *RepositoryScanDetails) AggregateFixes() bool {
	return rsd.git.AggregateFixes
}
