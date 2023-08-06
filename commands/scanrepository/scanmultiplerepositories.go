package scanrepository

import (
	"errors"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type ScanMultipleRepositories struct {
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
}

func (saf *ScanMultipleRepositories) Run(repoAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	// Aggregate errors and log at the end rather than failing the entire run if there is an error on one repository.
	var aggregatedErrors error
	for repoNum := range repoAggregator {
		if err := saf.scanAndFixSingleRepository(&repoAggregator[repoNum], client); err != nil {
			aggregatedErrors = errors.Join(err)
		}
	}
	return aggregatedErrors
}

func (saf *ScanMultipleRepositories) scanAndFixSingleRepository(repoConfig *utils.Repository, client vcsclient.VcsClient) error {
	var aggregatedErrors error
	for _, branch := range repoConfig.Branches {
		if err := saf.downloadAndRunScanAndFix(repoConfig, branch, client); err != nil {
			if _, isCustomError := err.(*utils.ErrUnsupportedFix); isCustomError {
				log.Debug(err.Error())
			} else {
				aggregatedErrors = errors.Join(err)
			}
		}
	}
	return aggregatedErrors
}

func (saf *ScanMultipleRepositories) downloadAndRunScanAndFix(repository *utils.Repository, branch string, client vcsclient.VcsClient) (err error) {
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, repository.Git.RepoOwner, repository.Git.RepoName, branch)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, cleanup())
	}()

	restoreDir, err := utils.Chdir(wd)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, restoreDir())
	}()

	cfp := ScanRepositoryCmd{dryRun: saf.dryRun, dryRunRepoPath: wd}
	return cfp.scanAndFixRepository(repository, branch, client)
}
