package scanrepository

import (
	"errors"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
)

type ScanMultipleRepositories struct {
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
}

func (saf *ScanMultipleRepositories) Run(repoAggregator utils.RepoAggregator, client vcsclient.VcsClient) (err error) {
	var dryRunRepoPath string
	if saf.dryRun {
		if dryRunRepoPath, err = fileutils.CreateTempDir(); err != nil {
			return err
		}
		defer func() {
			err = errors.Join(err, fileutils.RemoveTempDir(dryRunRepoPath))
		}()
	}

	scanRepositoryCmd := &ScanRepositoryCmd{dryRun: saf.dryRun, dryRunRepoPath: dryRunRepoPath}
	for repoNum := range repoAggregator {
		if e := scanRepositoryCmd.scanAndFixRepository(&repoAggregator[repoNum], client); e != nil {
			err = errors.Join(err, e)
		}
	}
	return
}
