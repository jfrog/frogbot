package commands

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"strings"
)

type ScanAndFixRepositories struct {
}

func (cmd ScanAndFixRepositories) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
	var errList strings.Builder
	for repoNum := range configAggregator {
		err := scanAndFixSingleRepository(&configAggregator[repoNum], client)
		if err != nil {
			errList.WriteString(fmt.Sprintf("repository %s returned the following error: \n%s\n", configAggregator[repoNum].RepoName, err.Error()))
		}
	}

	if errList.String() != "" {
		return errors.New(errList.String())
	}
	return nil
}

func scanAndFixSingleRepository(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) error {
	for _, branch := range repoConfig.Branches {
		err := downloadAndRunScanAndFix(client, branch, repoConfig)
		if err != nil {
			return err
		}
	}

	return nil
}

func downloadAndRunScanAndFix(client vcsclient.VcsClient, branch string, repoConfig *utils.FrogbotRepoConfig) (err error) {
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, branch, &repoConfig.GitParams)
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

	var cfp CreateFixPullRequestsCmd
	return cfp.scanAndFixRepository(repoConfig, client, branch)
}
