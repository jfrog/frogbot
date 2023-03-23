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

func (cmd ScanAndFixRepositories) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	var errList strings.Builder
	for repoNum := range configAggregator {
		err := cmd.scanAndFixSingleRepository(&configAggregator[repoNum], client)
		if err != nil {
			errList.WriteString(fmt.Sprintf("repository %s returned the following error: \n%s\n", configAggregator[repoNum].RepoName, err.Error()))
		}
	}

	if errList.String() != "" {
		return errors.New(errList.String())
	}
	return nil
}

func (cmd ScanAndFixRepositories) scanAndFixSingleRepository(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) error {
	for _, branch := range repoConfig.Branches {
		shouldScan, checkedCommit, err := cmd.shouldScanRepositoryByFrogBotCommitStatus(context.Background(), repoConfig, client, branch)
		if err != nil {
			return err
		}
		if !shouldScan {
			log.Info(fmt.Sprintf("Commit %s has already been scanned by FrogBot", checkedCommit))
			continue
		}
		err = cmd.downloadAndRunScanAndFix(client, branch, repoConfig)
		if err != nil {
			errorDescription := fmt.Sprintf("FrogBot error %s", err)
			log.Error(errorDescription)
			err = cmd.setCommitBuildStatus(client, repoConfig, vcsclient.Fail, checkedCommit, errorDescription)
			return err
		}
		err = cmd.setCommitBuildStatus(client, repoConfig, vcsclient.Pass, checkedCommit, "FrogBot scanned")
		if err != nil {
			return err
		}
	}
	return nil
}

func (cmd ScanAndFixRepositories) downloadAndRunScanAndFix(client vcsclient.VcsClient, branch string, repoConfig *utils.FrogbotRepoConfig) (err error) {
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, branch, &repoConfig.Git)
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

	var cfp = CreateFixPullRequestsCmd{dryRun: cmd.dryRun, dryRunRepoPath: filepath.Join(cmd.dryRunRepoPath, repoConfig.RepoName)}
	return cfp.scanAndFixRepository(repoConfig, client, branch)
}

// Checking last FrogBot commit status that indicates whether FrogBot has already scanned this branch or not
func (cmd ScanAndFixRepositories) shouldScanRepositoryByFrogBotCommitStatus(ctx context.Context, repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient, branch string) (shouldScan bool, commitHash string, err error) {
	owner := repoConfig.RepoOwner
	repo := repoConfig.RepoName
	latestCommit, err := client.GetLatestCommit(ctx, owner, repo, branch)
	if latestCommit.Hash == "" {
		// No commits at all
		return true, "", nil
	}
	if err != nil {
		return false, "", err
	}
	ref := latestCommit.Hash
	statuses, err := client.GetCommitStatuses(ctx, owner, repo, ref)
	if err != nil {
		return false, "", err
	}
	return shouldScanBranchByStatus(statuses), latestCommit.Hash, err
}

func (cmd ScanAndFixRepositories) setCommitBuildStatus(client vcsclient.VcsClient, repoConfig *utils.FrogbotRepoConfig, state vcsclient.CommitStatus, commitHash string, description string) error {
	background := context.Background()
	err := client.SetCommitStatus(background, state, repoConfig.RepoOwner, repoConfig.RepoName, commitHash, utils.ProductId, description, utils.FrogbotReadMeUrl)
	if err != nil {
		log.Error("Failed to mark last commit as checked")
		return err
	}
	log.Info(fmt.Sprintf("Successfully marked commit %s as checked by FrogBot", commitHash))
	return nil
}

// Return true if that last status by FrogBot is not successful
// OR it's older than DefaultAmountOfDaysToRescanRepo.
func shouldScanBranchByStatus(statuses []vcsclient.CommitStatusInfo) bool {
	length := len(statuses)
	if length == 0 {
		return true
	}
	latestStatus := statuses[length-1]
	if !strings.Contains(latestStatus.DetailsUrl, utils.FrogbotReadMeUrl) {
		return shouldScanBranchByStatus(statuses[0 : length-1])
	}
	return isStatusOldAndNeedScan(latestStatus) || latestStatus.State != vcsclient.Pass
}

// isStatusOldAndNeedScan - check if status need rescan because it is older than DefaultAmountOfDaysToRescanRepo
func isStatusOldAndNeedScan(latestStatus vcsclient.CommitStatusInfo) bool {
	statusLastUpdatedTime := time.Time{}
	if !latestStatus.CreatedAt.IsZero() {
		statusLastUpdatedTime = latestStatus.CreatedAt
	}
	if !latestStatus.LastUpdatedAt.IsZero() {
		statusLastUpdatedTime = latestStatus.LastUpdatedAt
	}
	if statusLastUpdatedTime.IsZero() {
		return true
	}
	return statusLastUpdatedTime.Before(time.Now().UTC().AddDate(0, 0, -utils.DefaultAmountOfDaysToRescanRepo))
}
