package scanrepository

import (
	"errors"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/froggit-go/vcsclient"
)

type ScanMultipleRepositories struct {
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
}

func (saf *ScanMultipleRepositories) Run(repoAggregator utils.RepoAggregator, client vcsclient.VcsClient) (err error) {
	scanRepositoryCmd := &ScanRepositoryCmd{dryRun: saf.dryRun, dryRunRepoPath: saf.dryRunRepoPath, baseWd: saf.dryRunRepoPath}
	for repoNum := range repoAggregator {
		if e := scanRepositoryCmd.scanAndFixRepository(&repoAggregator[repoNum], client); e != nil {
			err = errors.Join(err, e)
		}
	}
	return
}
