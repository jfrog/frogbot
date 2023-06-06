package commands

import (
	"errors"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"path/filepath"
)

type ScanAndFixRepositories struct {
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
}

func (saf *ScanAndFixRepositories) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	// Don't fail the whole run if there is an error on one repo, aggregate errors and log at the end.
	var totalErrors error
	for repoNum := range configAggregator {
		if err := saf.scanAndFixSingleRepository(&configAggregator[repoNum], client); err != nil {
			totalErrors = errors.Join(err)
		}
	}
	return totalErrors
}

func (saf *ScanAndFixRepositories) scanAndFixSingleRepository(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) error {
	var totalErrors error
	for _, branch := range repoConfig.Branches {
		if err := saf.downloadAndRunScanAndFix(repoConfig, branch, client); err != nil {
			if _, isCustomError := err.(*utils.ErrUnsupportedFix); isCustomError {
				log.Debug(err.Error())
			} else {
				totalErrors = errors.Join(err)
			}
		}
	}
	return totalErrors
}

func (saf *ScanAndFixRepositories) downloadAndRunScanAndFix(repository *utils.FrogbotRepoConfig, branch string, client vcsclient.VcsClient) (err error) {
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, branch, &repository.Git)
	if err != nil {
		return err
	}
	defer func() {
		e := cleanup()
		if err == nil {
			err = e
		}
	}()

	restoreDir, err := utils.Chdir(wd)
	if err != nil {
		return err
	}
	defer func() {
		e := restoreDir()
		if err == nil {
			err = e
		}
	}()

	cfp := CreateFixPullRequestsCmd{dryRun: saf.dryRun, dryRunRepoPath: filepath.Join(saf.dryRunRepoPath, repository.RepoName)}
	return cfp.scanAndFixRepository(repository, branch, client)
}
