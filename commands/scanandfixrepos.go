package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
		err := saf.scanAndFixSingleRepository(&configAggregator[repoNum], client)
		if err != nil {
			errList.WriteString(fmt.Sprintf("repository %s returned the following error: \n%s\n", configAggregator[repoNum].RepoName, err.Error()))
		}
	}

	if errList.String() != "" {
		return errors.New(errList.String())
	}
	return nil
}

func (saf *ScanAndFixRepositories) scanAndFixSingleRepository(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) error {
	for _, branch := range repoConfig.Branches {
		shouldScan, checkedCommit, err := saf.shouldScanLatestCommit(context.Background(), repoConfig, client, branch)
		if err != nil {
			return err
		}
		if !shouldScan {
			log.Info(fmt.Sprintf("Commit %s has already been scanned by FrogBot", checkedCommit))
			continue
		}
		err = saf.downloadAndRunScanAndFix(repoConfig, branch, client)
		if err != nil {
			errorDescription := fmt.Sprintf("FrogBot error %s", err)
			log.Error(errorDescription)
			err = saf.setCommitBuildStatus(client, repoConfig, vcsclient.Fail, checkedCommit, errorDescription)
			return err
		}
		err = saf.setCommitBuildStatus(client, repoConfig, vcsclient.Pass, checkedCommit, "FrogBot scanned")
		if err != nil {
			return err
		}
	}
	return nil
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

func (saf ScanAndFixRepositories) setCommitBuildStatus(client vcsclient.VcsClient, repoConfig *utils.FrogbotRepoConfig, state vcsclient.CommitStatus, commitHash string, description string) error {
	background := context.Background()
	err := client.SetCommitStatus(background, state, repoConfig.RepoOwner, repoConfig.RepoName, commitHash, utils.FrogbotCreatorName, description, utils.CommitStatusDetailsUrl)
	if err != nil {
		log.Error("Failed to mark last commit as checked")
		return err
	}
	log.Info(fmt.Sprintf("Successfully marked commit %s as checked by FrogBot", commitHash))
	return nil
}

// Returns true if the latest commit hasn't been scanned
// or the time passed from the last scan exceed the configured value.
func (saf ScanAndFixRepositories) shouldScanLatestCommit(ctx context.Context, repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient, branch string) (shouldScan bool, commitHash string, err error) {
	owner := repoConfig.RepoOwner
	repo := repoConfig.RepoName
	latestCommit, err := client.GetLatestCommit(ctx, owner, repo, branch)
	if err != nil {
		return false, "", err
	}
	ref := latestCommit.Hash
	statuses, err := client.GetCommitStatuses(ctx, owner, repo, ref)
	if err != nil {
		return false, "", err
	}
	return shouldScanCommitByStatus(statuses), latestCommit.Hash, err
}

// Returns true if the latest commit status by FrogBot is not successful
// OR it's older than SkipRepoScanDays.
func shouldScanCommitByStatus(statuses []vcsclient.CommitStatusInfo) bool {
	for _, status := range statuses {
		if status.Creator == utils.FrogbotCreatorName && status.Description == utils.CommitStatusDescription {
			return status.State != vcsclient.Pass || statusTimestampExpired(status)
		}
	}
	return true
}

// Checks if a commit status is older than SkipRepoScanDays number of days.
func statusTimestampExpired(latestStatus vcsclient.CommitStatusInfo) bool {
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
