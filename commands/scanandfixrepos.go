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
	for _, repoConfig := range configAggregator {
		err := downloadAndFixRepository(&repoConfig, client)
		if err != nil {
			errList.WriteString(fmt.Sprintf("repository %s returned the following error: \n%s\n", repoConfig.RepoName, err.Error()))
		}
	}

	if errList.String() != "" {
		return errors.New(errList.String())
	}
	return nil
}

func downloadAndFixRepository(repoConfig *utils.FrogbotRepoConfig, client vcsclient.VcsClient) (err error) {
	var cfp CreateFixPullRequestsCmd
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, repoConfig.RepoName, &repoConfig.GitParams)
	if err != nil {
		return err
	}
	defer func() {
		e := cleanup(err)
		if err == nil {
			err = e
		}
	}()
	restoreDir, err := utils.Chdir(wd)
	defer func() {
		e := restoreDir()
		if err == nil {
			err = e
		}
	}()

	return cfp.scanAndFixRepository(repoConfig, client)
}
