package main

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/scanpullrequest"
	"github.com/jfrog/frogbot/scanrepository"
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clitool "github.com/urfave/cli/v2"
	"os"
)

type FrogbotCommand interface {
	// Run the command
	Run(config utils.RepoAggregator, client vcsclient.VcsClient) error
}

func GetCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    utils.ScanPullRequest.ToString(),
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanpullrequest.ScanPullRequestCmd{}, utils.FrogbotCommandName(ctx.Command.Name))
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    utils.ScanRepository.ToString(),
			Aliases: []string{"cfpr", "create-fix-pull-requests"},
			Usage:   "Scan the current branch and create pull requests with fixes if needed",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanrepository.ScanRepositoryCmd{}, utils.FrogbotCommandName(ctx.Command.Name))
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    utils.ScanAllPullRequests.ToString(),
			Aliases: []string{"sprs", "scan-pull-requests"},
			Usage:   "Scans all the open pull requests within a single or multiple repositories with JFrog Xray for security vulnerabilities",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanpullrequest.ScanAllPullRequestsCmd{}, utils.FrogbotCommandName(ctx.Command.Name))
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    utils.ScanMultipleRepositories.ToString(),
			Aliases: []string{"scan-and-fix-repos", "safr"},
			Usage:   "Scan single or multiple repositories and create pull requests with fixes if any security vulnerabilities are found",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanrepository.ScanMultipleRepositories{}, utils.FrogbotCommandName(ctx.Command.Name))
			},
			Flags: []clitool.Flag{},
		},
	}
}

func Exec(command FrogbotCommand, commandName utils.FrogbotCommandName) (err error) {
	// Get frogbotDetails that contains the config, server, and VCS client
	log.Info("Frogbot version:", utils.FrogbotVersion)
	frogbotDetails, err := utils.GetFrogbotDetails(commandName)
	if err != nil {
		return err
	}

	// Build the server configuration file
	originalJfrogHomeDir, tempJFrogHomeDir, err := utils.BuildServerConfigFile(frogbotDetails.ServerDetails)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, os.Setenv(utils.JfrogHomeDirEnv, originalJfrogHomeDir), fileutils.RemoveTempDir(tempJFrogHomeDir))
	}()

	// Set releases remote repository env if needed
	previousReleasesRepoEnv := os.Getenv(coreutils.ReleasesRemoteEnv)
	if frogbotDetails.ReleasesRepo != "" {
		if err = os.Setenv(coreutils.ReleasesRemoteEnv, fmt.Sprintf("frogbot/%s", frogbotDetails.ReleasesRepo)); err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, os.Setenv(coreutils.ReleasesRemoteEnv, previousReleasesRepoEnv))
		}()
	}

	// Send a usage report
	waitForUsageResponse := utils.ReportUsageOnCommand(commandName, frogbotDetails.ServerDetails, frogbotDetails.Repositories)

	// Invoke the command interface
	log.Info(fmt.Sprintf("Running Frogbot %q command", commandName))
	err = command.Run(frogbotDetails.Repositories, frogbotDetails.GitClient)

	// Wait for usage reporting to finish.
	waitForUsageResponse()

	if err == nil {
		log.Info(fmt.Sprintf("Frogbot %q command finished successfully", commandName))
	}
	return err
}
