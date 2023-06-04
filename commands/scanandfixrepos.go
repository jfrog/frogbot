package commands

import (
	"errors"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"path/filepath"
	"strings"
	"time"
)

type ScanAndFixRepositories struct {
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
}

func (saf *ScanAndFixRepositories) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	var errList strings.Builder
	for repoNum := range configAggregator {
		saf.scanAndFixSingleRepository(&configAggregator[repoNum], client, errList)
	}
	if errList.String() != "" {
		return errors.New(errList.String())
	}
	return nil
}

func (saf *ScanAndFixRepositories) scanAndFixSingleRepository(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient, errList strings.Builder) {
	for _, branch := range repoConfig.Branches {
		if err := saf.downloadAndRunScanAndFix(repoConfig, branch, client); err != nil {
			if _, isCustomError := err.(*utils.ErrUnsupportedFix); isCustomError {
				errList.WriteString(err.Error())
			}
		}
	}
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

// Returns true if the latest commit status by Frogbot is not successful
// OR it's older than SkipRepoScanDays.
func shouldScanCommitByStatus(statuses []vcsclient.CommitStatusInfo) bool {
	for _, status := range statuses {
		if status.Creator == utils.FrogbotCreatorName && status.Description == utils.CommitStatusDescription {
			return status.State != vcsclient.Pass || statusTimestampElapsed(status)
		}
	}
	return true
}

// Checks if a commit status is older than SkipRepoScanDays number of days.
func statusTimestampElapsed(latestStatus vcsclient.CommitStatusInfo) bool {
	if latestStatus.CreatedAt.IsZero() && latestStatus.LastUpdatedAt.IsZero() {
		// In case non were initialized, address this as expired date
		return true
	}
	statusLastUpdatedTime := latestStatus.LastUpdatedAt
	if statusLastUpdatedTime.IsZero() {
		// Fallback to creation time
		statusLastUpdatedTime = latestStatus.CreatedAt
	}
	passDueDate := time.Now().UTC().AddDate(0, 0, -utils.SkipRepoScanDays)
	return statusLastUpdatedTime.Before(passDueDate)
}
