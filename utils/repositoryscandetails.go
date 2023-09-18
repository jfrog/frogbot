package utils

import (
	"context"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
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

func (rsd *RepositoryScanDetails) SetRepositoryCloneUrl(cloneUrl string) *RepositoryScanDetails {
	rsd.git.RepositoryCloneUrl = cloneUrl
	return rsd
}

func (rsd *RepositoryScanDetails) SetXscGitInfoContext(scannedBranch, gitProject string, client vcsclient.VcsClient) *RepositoryScanDetails {
	XscGitInfoContext, err := rsd.createGitInfoContext(scannedBranch, gitProject, client)
	if err != nil {
		log.Debug("failed trying to create GitInfoContext for Xsc with the following error: ", err.Error())
		return rsd
	}
	rsd.xrayGraphScanParams.XscGitInfoContext = XscGitInfoContext
	return rsd
}

// CreateGitInfoContext Creates GitInfoContext for XSC scans, this is optional.
// ScannedBranch - name of the branch we are scanning.
// GitProject - [Optional] relevant for azure repos and Bitbucket server.
// Client vscClient
func (rsd *RepositoryScanDetails) createGitInfoContext(scannedBranch, gitProject string, client vcsclient.VcsClient) (gitInfo *services.XscGitInfoContext, err error) {
	latestCommit, err := client.GetLatestCommit(context.Background(), rsd.git.RepoOwner, rsd.git.RepoName, scannedBranch)
	if err != nil {
		return nil, fmt.Errorf("failed getting latest commit, repository: %s, branch: %s. error: %s ", rsd.git.RepoName, scannedBranch, err.Error())
	}
	// In some VCS providers, there are no git projects, fallback to the repository owner.
	if gitProject == "" {
		gitProject = rsd.git.RepoOwner
	}
	gitInfo = &services.XscGitInfoContext{
		// Use Clone URLs as Repo Url, on browsers it will redirect to repository URLS.
		GitRepoUrl:    rsd.git.RepositoryCloneUrl,
		GitRepoName:   rsd.git.RepoName,
		GitProvider:   rsd.git.GitProvider.String(),
		GitProject:    gitProject,
		BranchName:    scannedBranch,
		LastCommit:    latestCommit.Url,
		CommitHash:    latestCommit.Hash,
		CommitMessage: latestCommit.Message,
		CommitAuthor:  latestCommit.AuthorName,
	}
	return
}
