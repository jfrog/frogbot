package commands

import (
	"errors"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os"
)

type ScanAndFixRepositories struct {
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
}

// Run scanning multi repositories by cloning each one from repoAggregator and running CreateFixPullRequestsCmd.
// As this command doesn't have the context of one repository, each repository needs to be cloned.
func (saf *ScanAndFixRepositories) Run(repoAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	if !saf.dryRun {
		// Prepare environment
		// TODO rethink this.
		wd, err := fileutils.CreateTempDir()
		if err != nil {
			return err
		}
		if err = os.Chdir(wd); err != nil {
			return err
		}
		defer func() {
			err = errors.Join(err, fileutils.RemoveTempDir(wd))
		}()
	}
	// Aggregate errors and log at the end rather than failing the entire run if there is an error on one repository.
	var aggregatedErrors error
	for repoNum := range repoAggregator {
		if err := saf.cloneAndRunScanAndFix(&repoAggregator[repoNum], client); err != nil {
			aggregatedErrors = errors.Join(err)
		}
	}
	return aggregatedErrors
}

// Clone each repository, run CreateFixPullRequestsCmd command and return to the parent directory
func (saf *ScanAndFixRepositories) cloneAndRunScanAndFix(repository *utils.Repository, client vcsclient.VcsClient) (err error) {
	parentWd, _ := os.Getwd()
	defer func() {
		err = errors.Join(err, os.Chdir(parentWd))
	}()
	_, err = utils.CloneRepositoryAndChDir(saf.dryRun, &repository.Git)
	if err != nil {
		return
	}
	cfp := CreateFixPullRequestsCmd{dryRun: saf.dryRun, dryRunRepoPath: saf.dryRunRepoPath}
	return cfp.Run(utils.RepoAggregator{*repository}, client)
}
