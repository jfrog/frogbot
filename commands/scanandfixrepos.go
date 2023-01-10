package commands

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"path/filepath"
	"strings"
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
		if configAggregator[repoNum].GitProvider == vcsutils.BitbucketServer {
			// Bitbucket server requires a simple output without emojis + images
			configAggregator[repoNum].SimplifiedOutput = true
		}
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
		err := cmd.downloadAndRunScanAndFix(client, branch, repoConfig)
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
